package app

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func addNetworkProxy(t *testing.T, store *apiKeyStore, name, endpoint string) string {
	t.Helper()
	id, err := store.saveNetworkProxy("", networkProxyInput{Name: name, URL: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A real forwarding proxy fixture: authenticated absolute-form HTTP and CONNECT.
func fakeHTTPProxy(t *testing.T, secure bool, username, password string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if username != "" {
			auth := r.Header.Get("Proxy-Authorization")
			check := &http.Request{Header: make(http.Header)}
			check.Header.Set("Authorization", auth)
			u, p, ok := check.BasicAuth()
			if !ok || u != username || p != password {
				w.WriteHeader(407)
				return
			}
		}
		if r.Method == http.MethodConnect {
			target, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				target.Close()
				return
			}
			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = rw.Flush()
			go func() { defer target.Close(); _, _ = io.Copy(target, rw) }()
			go func() { defer conn.Close(); _, _ = io.Copy(conn, target) }()
			return
		}
		req := r.Clone(r.Context())
		req.RequestURI = ""
		req.Header.Del("Proxy-Authorization")
		resp, err := transport.RoundTrip(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(flushingProxyWriter{w}, resp.Body)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(func() { server.Close(); transport.CloseIdleConnections() })
	return server
}

type flushingProxyWriter struct{ http.ResponseWriter }

func (w flushingProxyWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.ResponseWriter.(http.Flusher).Flush()
	return n, err
}

func fakeSOCKS5(t *testing.T, username, password string, calls *atomic.Int32) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := make([]net.Conn, 0)
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, c)
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 2)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				methods := make([]byte, int(buf[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				method := byte(0)
				if username != "" {
					method = 2
				}
				_, _ = c.Write([]byte{5, method})
				if method == 2 {
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					u := make([]byte, int(buf[1]))
					_, _ = io.ReadFull(c, u)
					n := make([]byte, 1)
					_, _ = io.ReadFull(c, n)
					p := make([]byte, int(n[0]))
					_, _ = io.ReadFull(c, p)
					if string(u) != username || string(p) != password {
						_, _ = c.Write([]byte{1, 1})
						return
					}
					_, _ = c.Write([]byte{1, 0})
				}
				header := make([]byte, 4)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				host := ""
				switch header[3] {
				case 1:
					b := make([]byte, 4)
					_, _ = io.ReadFull(c, b)
					host = net.IP(b).String()
				case 4:
					b := make([]byte, 16)
					_, _ = io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					n := make([]byte, 1)
					_, _ = io.ReadFull(c, n)
					b := make([]byte, int(n[0]))
					_, _ = io.ReadFull(c, b)
					host = string(b)
				default:
					return
				}
				port := make([]byte, 2)
				if _, err := io.ReadFull(c, port); err != nil {
					return
				}
				target, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port))), 2*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer target.Close()
				calls.Add(1)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_ = c.SetDeadline(time.Time{})
				done := make(chan struct{})
				go func() { _, _ = io.Copy(target, c); close(done) }()
				_, _ = io.Copy(c, target)
				c.Close()
				<-done
			}(c)
		}
	}()
	return "socks5://" + listener.Addr().String()
}

func TestNetworkProxyProtocolsAndAuthorization(t *testing.T) {
	for _, scheme := range []string{"http", "https", "socks5"} {
		for _, upstreamTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tls-%v", scheme, upstreamTLS), func(t *testing.T) {
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer sk-network-provider" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
						t.Error("authorization isolation failed")
					}
					if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/models" {
						t.Errorf("wrong path %s", r.URL.Path)
					}
					_, _ = io.WriteString(w, nativeChatResponse)
				})
				var upstream *httptest.Server
				if upstreamTLS {
					upstream = httptest.NewTLSServer(handler)
				} else {
					upstream = httptest.NewServer(handler)
				}
				defer upstream.Close()
				var calls atomic.Int32
				endpoint := ""
				if scheme == "socks5" {
					endpoint = fakeSOCKS5(t, "test-user", "test-password", &calls)
				} else {
					endpoint = fakeHTTPProxy(t, scheme == "https", "test-user", "test-password", &calls).URL
				}
				gateway := multiUpstreamProxy(t, upstream.URL)
				// Only fixtures trust self-signed proxy and target certificates.
				gateway.outbound.base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				u, p := "test-user", "test-password"
				id, err := gateway.keys.saveNetworkProxy("", networkProxyInput{Name: "Route", URL: endpoint, Username: &u, Password: &p})
				if err != nil {
					t.Fatal(err)
				}
				key := addUpstream(t, gateway, "Provider", upstream.URL, protocolChatCompletions, "sk-network-provider", 0)
				rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
				if rec.Code != 200 || rec.Body.String() != nativeChatResponse || calls.Load() < 1 {
					t.Fatalf("proxy failed: %d calls=%d %s", rec.Code, calls.Load(), rec.Body.String())
				}
				selected, err := gateway.keys.byID(key.ID)
				if err != nil || selected.NetworkProxy.ID != id {
					t.Fatal("binding lost")
				}
				status, _ := gateway.probeAPIKey(context.Background(), *selected)
				if status != 200 {
					t.Fatalf("key probe failed: %d", status)
				}
				route, _ := gateway.outboundRoute(selected)
				route.client.CloseIdleConnections()
			})
		}
	}
}

func TestNetworkProxyBalancedStableAssignments(t *testing.T) {
	store := newAPIKeyStore(filepath.Join(t.TempDir(), "keys.json"), "proxy-balance-secret")
	for i := 0; i < 20; i++ {
		if _, err := store.add(fmt.Sprintf("Key %02d", i), fmt.Sprintf("sk-balance-key-%02d", i), true); err != nil {
			t.Fatal(err)
		}
	}
	first := addNetworkProxy(t, store, "First", "http://127.0.0.1:19001")
	before, _ := store.list()
	for _, k := range before {
		if k.ProxyID != first {
			t.Fatal("initial auto binding missing")
		}
	}
	addNetworkProxy(t, store, "Second", "http://127.0.0.1:19002")
	after, _ := store.list()
	moved := 0
	for i, k := range after {
		if k.ProxyID != before[i].ProxyID {
			moved++
		}
	}
	if moved != 10 {
		t.Fatalf("expected minimal 10 moves, got %d", moved)
	}
	addNetworkProxy(t, store, "Third", "socks5://127.0.0.1:19003")
	addNetworkProxy(t, store, "Fourth", "https://127.0.0.1:19004")
	for _, p := range store.listNetworkProxies() {
		if p.AssignedKeys != 5 {
			t.Fatalf("unbalanced %+v", p)
		}
	}
	stable, _ := store.list()
	// Rebalancing an already balanced pool must not move any key.
	store.mu.Lock()
	store.rebalanceProxiesLocked()
	store.mu.Unlock()
	check, _ := store.list()
	for i, k := range check {
		if k.ProxyID != stable[i].ProxyID {
			t.Fatal("assignment churn")
		}
	}
	pinned, err := store.updatePolicy(check[0].ID, apiKeyPolicy{ProxyMode: "fixed", ProxyID: first, Weight: 1})
	if err != nil {
		t.Fatal(err)
	}
	addNetworkProxy(t, store, "Fifth", "http://127.0.0.1:19005")
	final, _ := store.list()
	for _, k := range final {
		if k.ID == pinned.ID && k.ProxyID != first {
			t.Fatal("pinned assignment moved")
		}
	}
	if err := store.deleteNetworkProxy(first); err == nil {
		t.Fatal("deleted pinned proxy")
	}
}

func TestNetworkProxyRebalanceMovesIdleKeysFirst(t *testing.T) {
	store := newAPIKeyStore(filepath.Join(t.TempDir(), "keys.json"), "idle-test-secret")
	for i := 0; i < 4; i++ {
		_, _ = store.add(fmt.Sprint(i), fmt.Sprintf("sk-idle-provider-%d", i), true)
	}
	first := addNetworkProxy(t, store, "First", "http://127.0.0.1:19001")
	store.mu.Lock()
	for i := 0; i < 2; i++ {
		store.keys[i].LastUsed = time.Now().UTC()
	}
	busy := []string{store.keys[0].ID, store.keys[1].ID}
	store.mu.Unlock()
	addNetworkProxy(t, store, "Second", "http://127.0.0.1:19002")
	keys, _ := store.list()
	for _, k := range keys {
		for _, id := range busy {
			if k.ID == id && k.ProxyID != first {
				t.Fatal("busy key moved before idle keys")
			}
		}
	}
}

func TestNetworkProxyEncryptionBackupAndLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "network-secret")
	original, err := store.add("Original", "sk-original-provider", true)
	if err != nil {
		t.Fatal(err)
	}
	username, password := "private-proxy-user", "private-proxy-password"
	id, err := store.saveNetworkProxy("", networkProxyInput{Name: "Private", URL: "socks5://127.0.0.1:1080", Username: &username, Password: &password})
	if err != nil {
		t.Fatal(err)
	}
	backup, err := store.exportBackup()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{username, password, "sk-original-provider"} {
		if strings.Contains(string(backup), secret) {
			t.Fatal("secret in backup")
		}
	}
	views, _ := json.Marshal(store.listNetworkProxies())
	if strings.Contains(string(views), password) || strings.Contains(string(views), username) {
		t.Fatal("admin exposes auth")
	}
	loaded := newAPIKeyStore(path, "network-secret")
	key, err := loaded.byID(original.ID)
	if err != nil || key.NetworkProxy.ID != id || key.NetworkProxy.Password != password {
		t.Fatal("reload lost credentials")
	}
	restored := newAPIKeyStore(filepath.Join(t.TempDir(), "restore.json"), "network-secret")
	if err := restored.importBackup(backup); err != nil {
		t.Fatal(err)
	}
	p, err := restored.networkProxyByID(id)
	if err != nil || p.Username != username || p.Password != password {
		t.Fatal("backup lost proxy auth")
	}
	// Edits without credentials preserve auth; explicitly empty removes it.
	if _, err := restored.saveNetworkProxy(id, networkProxyInput{Name: "Edited", URL: p.URL}); err != nil {
		t.Fatal(err)
	}
	p, _ = restored.networkProxyByID(id)
	if p.Password != password {
		t.Fatal("edit erased password")
	}
	empty := ""
	_, err = restored.saveNetworkProxy(id, networkProxyInput{Name: "Edited", URL: p.URL, Username: &empty, Password: &empty})
	if err != nil {
		t.Fatal(err)
	}
	p, _ = restored.networkProxyByID(id)
	if p.Password != "" || p.Username != "" {
		t.Fatal("auth removal failed")
	}
	legacy := newAPIKeyStore(filepath.Join(t.TempDir(), "legacy.json"), "network-secret")
	_, _ = legacy.add("Legacy", "sk-legacy-provider", true)
	k, err := legacy.selectNext(nil)
	if err != nil || k.NetworkProxy != nil {
		t.Fatal("legacy config broken")
	}
}

func TestNetworkProxyFailureNeverFallsBackOrCoolsAPIKey(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	gateway := multiUpstreamProxy(t, upstream.URL)
	id := addNetworkProxy(t, gateway.keys, "Unavailable", "http://127.0.0.1:1")
	key := addUpstream(t, gateway, "Provider", upstream.URL, protocolChatCompletions, "sk-network-provider", 0)
	gateway.routingMode.Store("pool-first")
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 502 || calls.Load() != 0 {
		t.Fatal("proxy failure bypassed route")
	}
	selected, _ := gateway.keys.byID(key.ID)
	status, _ := gateway.probeAPIKey(context.Background(), *selected)
	if status != 0 {
		t.Fatal("proxy error attributed to key")
	}
	keys, _ := gateway.keys.list()
	if keys[0].Failures != 0 || keys[0].CooldownUntil != nil {
		t.Fatal("API key penalized for proxy failure")
	}
	disabled := false
	_, err := gateway.keys.saveNetworkProxy(id, networkProxyInput{Name: "Unavailable", URL: "http://127.0.0.1:1", Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	rec = requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 503 || calls.Load() != 0 {
		t.Fatal("disabled pool fell back to inbound/default")
	}
	if err := gateway.keys.deleteNetworkProxy(id); err != nil {
		t.Fatal(err)
	}
	rec = requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 503 || calls.Load() != 0 {
		t.Fatal("empty pool silently changed to direct")
	}
	// Direct access requires an explicit operator decision.
	_, err = gateway.keys.updatePolicy(key.ID, apiKeyPolicy{Weight: 1, APIProtocol: protocolChatCompletions, BaseURL: upstream.URL, ProxyMode: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	rec = requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 200 || calls.Load() != 1 {
		t.Fatal("explicit direct broken")
	}
}

func TestNetworkProxyWAFIsolationAndWarmup(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Set-Cookie", "acw_tc=route-cookie")
			return
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	var a, b atomic.Int32
	first := fakeHTTPProxy(t, false, "", "", &a)
	second := fakeHTTPProxy(t, false, "", "", &b)
	gateway := multiUpstreamProxy(t, upstream.URL)
	one := addNetworkProxy(t, gateway.keys, "One", first.URL)
	two := addNetworkProxy(t, gateway.keys, "Two", second.URL)
	p1, _ := gateway.keys.networkProxyByID(one)
	p2, _ := gateway.keys.networkProxyByID(two)
	r1, _ := gateway.outboundRoute(&selectedAPIKey{NetworkProxy: p1})
	r2, _ := gateway.outboundRoute(&selectedAPIKey{NetworkProxy: p2})
	if !r1.cookies.warmupWithClient(context.Background(), gateway.cfg.UpstreamURL, r1.client) {
		t.Fatal("proxied warmup failed")
	}
	if a.Load() != 1 || b.Load() != 0 || r2.cookies.header() != "" || gateway.cookies.header() != "" {
		t.Fatal("WAF routes mixed")
	}
	r1.cookies.capture(http.Header{"Set-Cookie": {"acw_tc=one-only"}})
	if r2.cookies.header() != "" {
		t.Fatal("cookie leaked")
	}
	same, _ := gateway.outboundRoute(&selectedAPIKey{NetworkProxy: p1})
	if same != r1 {
		t.Fatal("route/session not stable")
	}
	r1.client.CloseIdleConnections()
	r2.client.CloseIdleConnections()
}

func TestNetworkProxyWAFRetryUsesAssignedRoute(t *testing.T) {
	var generationCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Set-Cookie", "acw_tc=proxied-cookie")
			return
		}
		if generationCalls.Add(1) == 1 {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, "<script src=\"waf.js\"></script>")
			return
		}
		if r.Header.Get("Cookie") != "acw_tc=proxied-cookie" {
			t.Error("wrong WAF cookie")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	var proxyCalls atomic.Int32
	p := fakeHTTPProxy(t, false, "", "", &proxyCalls)
	gateway := multiUpstreamProxy(t, upstream.URL)
	id := addNetworkProxy(t, gateway.keys, "Route", p.URL)
	key := addUpstream(t, gateway, "Provider", upstream.URL, protocolChatCompletions, "sk-waf-proxy-provider", 0)
	if gateway.warmup(context.Background()) {
		t.Fatal("background warmup bypassed managed pool")
	}
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 200 || proxyCalls.Load() != 3 || generationCalls.Load() != 2 || gateway.cookies.header() != "" {
		t.Fatalf("WAF route incorrect: %d calls=%d", rec.Code, proxyCalls.Load())
	}
	present, _, _, _ := gateway.wafStatus()
	if !present {
		t.Fatal("managed WAF session not visible")
	}
	selected, _ := gateway.keys.byID(key.ID)
	before, _ := gateway.outboundRoute(selected)
	if _, err := gateway.keys.saveNetworkProxy(id, networkProxyInput{Name: "Renamed", URL: p.URL}); err != nil {
		t.Fatal(err)
	}
	gateway.invalidateNetworkProxy(id)
	selected, _ = gateway.keys.byID(key.ID)
	after, _ := gateway.outboundRoute(selected)
	if before != after || after.cookies.header() != "acw_tc=proxied-cookie" {
		t.Fatal("name edit reset stable WAF route")
	}
}

func TestNetworkProxyDirectIgnoresEnvironmentTransport(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	route, err := gateway.outboundRoute(&selectedAPIKey{ProxyMode: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if route.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("explicit direct uses environment proxy")
	}
	legacy, _ := gateway.outboundRoute(&selectedAPIKey{})
	if legacy.client != gateway.client || legacy.cookies == route.cookies {
		t.Fatal("legacy/direct route mixed")
	}
}

func TestNetworkProxyValidationAndRollback(t *testing.T) {
	for _, raw := range []string{"http://host", "http://user:pass@host:80", "socks5://host:1080/path", "https://host:443?x=1", "socks5://host:0", "ftp://host:21"} {
		if _, err := parseNetworkProxyURL(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	store := newAPIKeyStore(filepath.Join(t.TempDir(), "keys.json"), "rollback-secret")
	_, _ = store.add("Key", "sk-rollback-provider", true)
	id := addNetworkProxy(t, store, "First", "http://127.0.0.1:19001")
	before, _ := store.exportBackup()
	store.setSaveHook(func([]byte) error { return fmt.Errorf("storage failed") })
	if _, err := store.saveNetworkProxy("", networkProxyInput{Name: "Second", URL: "http://127.0.0.1:19002"}); err == nil {
		t.Fatal("save error lost")
	}
	after, _ := store.exportBackup()
	if string(after) != string(before) {
		t.Fatal("failed save changed assignments")
	}
	store.setSaveHook(nil)
	// A malformed proxy nonce cannot panic or replace a working pool.
	var file persistedKeyFile
	_ = json.Unmarshal(before, &file)
	file.Proxies[0].Nonce = "AA"
	bad, _ := json.Marshal(file)
	if err := store.importBackup(bad); err == nil {
		t.Fatal("bad nonce accepted")
	}
	if _, err := store.networkProxyByID(id); err != nil {
		t.Fatal("bad backup damaged store")
	}
	// Restore the durable file after an intentional failing external save hook.
	if err := os.WriteFile(store.path, before, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkProxyConcurrentRouteAndRebalance(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	first := addNetworkProxy(t, gateway.keys, "First", "http://127.0.0.1:19001")
	for i := 0; i < 20; i++ {
		addUpstream(t, gateway, fmt.Sprint(i), "", protocolResponses, fmt.Sprintf("sk-concurrent-%02d", i), 0)
	}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				k, err := gateway.keys.selectNext(nil)
				if err != nil {
					t.Error(err)
					return
				}
				if k.NetworkProxy == nil {
					t.Error("missing route")
					return
				}
				if _, err := gateway.outboundRoute(k); err != nil {
					t.Error(err)
				}
				_ = gateway.keys.listNetworkProxies()
			}
		}()
	}
	addNetworkProxy(t, gateway.keys, "Second", "socks5://127.0.0.1:19002")
	wg.Wait()
	views := gateway.keys.listNetworkProxies()
	for _, p := range views {
		if p.AssignedKeys != 10 {
			t.Fatalf("unbalanced after concurrency: %+v (first %s)", p, first)
		}
	}
}

func TestNetworkProxyStreamingSurvivesRebalance(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	payload := "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
		w.(http.Flusher).Flush()
		close(started)
		<-finish
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	var firstCalls, secondCalls atomic.Int32
	first := fakeHTTPProxy(t, false, "", "", &firstCalls)
	second := fakeHTTPProxy(t, false, "", "", &secondCalls)
	gateway := multiUpstreamProxy(t, upstream.URL)
	addNetworkProxy(t, gateway.keys, "First", first.URL)
	addUpstream(t, gateway, "Streaming", upstream.URL, protocolChatCompletions, "sk-stream-network-provider", 0)
	addUpstream(t, gateway, "Other", upstream.URL, protocolChatCompletions, "sk-other-network-provider", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := gateway.doUpstream(ctx, make(http.Header), http.MethodPost, "/v1/chat/completions", []byte(`{"model":"m","messages":[],"stream":true}`), true)
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-started
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != payload {
		close(finish)
		t.Fatal("first SSE frame was buffered")
	}
	addNetworkProxy(t, gateway.keys, "Second", second.URL)
	close(finish)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != "data: [DONE]\n\n" || firstCalls.Load() != 1 || secondCalls.Load() != 0 {
		t.Fatalf("rebalance interrupted/rerouted stream: %v %s", err, rest)
	}
}

func TestNetworkProxyFailoverChangesTransport(t *testing.T) {
	var calls1, calls2 atomic.Int32
	p1 := fakeHTTPProxy(t, false, "", "", &calls1)
	p2 := fakeHTTPProxy(t, false, "", "", &calls2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer sk-first-network-provider" {
			w.WriteHeader(429)
			return
		}
		if r.Header.Get("Authorization") != "Bearer sk-second-network-provider" {
			t.Error("wrong failover credential")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	gateway := multiUpstreamProxy(t, upstream.URL)
	id1 := addNetworkProxy(t, gateway.keys, "One", p1.URL)
	id2 := addNetworkProxy(t, gateway.keys, "Two", p2.URL)
	for i, id := range []string{id1, id2} {
		key := fmt.Sprintf("sk-%s-network-provider", []string{"first", "second"}[i])
		_, err := gateway.keys.addWithPolicy(fmt.Sprint(i), key, true, apiKeyPolicy{Weight: 1, Priority: 10 - i, APIProtocol: protocolChatCompletions, BaseURL: upstream.URL, ProxyMode: "fixed", ProxyID: id})
		if err != nil {
			t.Fatal(err)
		}
	}
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 200 || calls1.Load() != 1 || calls2.Load() != 1 {
		t.Fatalf("failover transport wrong: %d %d/%d", rec.Code, calls1.Load(), calls2.Load())
	}
}

func TestNetworkProxyRejectedAuthDoesNotPenalizeProvider(t *testing.T) {
	var calls atomic.Int32
	p := fakeHTTPProxy(t, false, "expected-user", "expected-password", &calls)
	gateway := multiUpstreamProxy(t, "http://127.0.0.1:1")
	addNetworkProxy(t, gateway.keys, "Wrong auth", p.URL)
	key := addUpstream(t, gateway, "Provider", "", protocolChatCompletions, "sk-proxy-auth-provider", 0)
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 407 || calls.Load() != 1 {
		t.Fatalf("expected proxy auth rejection: %d", rec.Code)
	}
	selected, _ := gateway.keys.byID(key.ID)
	status, _ := gateway.probeAPIKey(context.Background(), *selected)
	if status != 0 {
		t.Fatal("proxy auth probe attributed to provider")
	}
	views, _ := gateway.keys.list()
	if views[0].Failures != 0 || views[0].CooldownUntil != nil {
		t.Fatal("provider penalized for proxy auth")
	}
}

func TestNetworkProxyAdminRBACAndProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("probe sent API credential")
		}
		w.WriteHeader(404)
	}))
	defer upstream.Close()
	var calls atomic.Int32
	p := fakeHTTPProxy(t, false, "", "", &calls)
	gateway := multiUpstreamProxy(t, upstream.URL)
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "admin-test-token"}, {Name: "viewer", Role: "viewer", Token: "viewer-test-token"}}
	input := `{"name":"Proxy","url":"` + p.URL + `","username":"test-secret-user","password":"test-secret-password"}`
	send := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Admin-Token", token)
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := send("POST", "/api/admin/network-proxies", input, "viewer-test-token"); rec.Code != 403 {
		t.Fatal("viewer created proxy")
	}
	rec := send("POST", "/api/admin/network-proxies", input, "admin-test-token")
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec = send("GET", "/api/admin/network-proxies", "", "viewer-test-token")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "test-secret") {
		t.Fatal("list leaks auth")
	}
	rec = send("POST", "/api/admin/network-proxies/"+created.ID+"/test", `{}`, "admin-test-token")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) || calls.Load() != 1 {
		t.Fatalf("probe %d %s", rec.Code, rec.Body.String())
	}
	rec = send("POST", "/api/admin/network-proxies/"+created.ID+"/test", `{}`, "viewer-test-token")
	if rec.Code != 403 {
		t.Fatal("viewer ran probe")
	}
	parsed, _ := url.Parse(p.URL)
	gateway.cfg.AllowedUpstreamOrigins = []string{upstreamOrigin(parsed)}
	rec = send("POST", "/api/admin/network-proxies/"+created.ID+"/test", `{"target_url":"http://169.254.169.254"}`, "admin-test-token")
	if !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatal("probe bypassed target allowlist")
	}
}
