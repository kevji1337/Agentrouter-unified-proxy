package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type outboundRoute struct {
	client  *http.Client
	cookies *cookieStore
}

type outboundRoutes struct {
	mu     sync.Mutex
	routes map[string]*outboundRoute
	base   *http.Transport
}

func newOutboundRoutes(base *http.Transport) *outboundRoutes {
	return &outboundRoutes{routes: make(map[string]*outboundRoute), base: base}
}

// A route cache is keyed by the transport configuration, NOT by API key. A
// credential edit creates a new route/session; old active requests finish.
func (server *proxyServer) outboundRoute(key *selectedAPIKey) (*outboundRoute, error) {
	if key == nil {
		return &outboundRoute{client: server.client, cookies: server.cookies}, nil
	}
	routeKey := "direct"
	var proxyURL *url.URL
	if key.NetworkProxy != nil {
		p := key.NetworkProxy
		parsed, err := parseNetworkProxyURL(p.URL)
		if err != nil {
			return nil, err
		}
		proxyURL = parsed
		if p.Username != "" {
			proxyURL.User = url.UserPassword(p.Username, p.Password)
		}
		digest := sha256.Sum256([]byte(proxyURL.String()))
		routeKey = p.ID + ":" + hex.EncodeToString(digest[:])
	} else if key.ProxyMode != "direct" {
		// Legacy installations without a configured pool retain environment proxy
		// behavior. Explicit direct ALWAYS disables environment proxies.
		return &outboundRoute{client: server.client, cookies: server.cookies}, nil
	}
	cache := server.outbound
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if route := cache.routes[routeKey]; route != nil {
		return route, nil
	}
	transport := cache.base.Clone()
	transport.Proxy = nil
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	route := &outboundRoute{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cookies: newCookieStore()}
	cache.routes[routeKey] = route
	return route, nil
}

func (server *proxyServer) resetOutboundRoutes() {
	server.outbound.mu.Lock()
	defer server.outbound.mu.Unlock()
	for id, route := range server.outbound.routes {
		route.client.CloseIdleConnections()
		delete(server.outbound.routes, id)
	}
}

func (server *proxyServer) wafStatus() (bool, []string, time.Time, time.Time) {
	if !server.keys.networkPoolConfigured() {
		return server.cookies.status()
	}
	server.outbound.mu.Lock()
	defer server.outbound.mu.Unlock()
	present := false
	names := make(map[string]bool)
	var updated, warmup time.Time
	for _, route := range server.outbound.routes {
		ok, ns, u, w := route.cookies.status()
		present = present || ok
		for _, n := range ns {
			names[n] = true
		}
		if u.After(updated) {
			updated = u
		}
		if w.After(warmup) {
			warmup = w
		}
	}
	result := make([]string, 0, len(names))
	for n := range names {
		result = append(result, n)
	}
	sort.Strings(result)
	return present, result, updated, warmup
}

// Drop stale transports after administrative changes, without canceling active
// requests. Current configurations for other proxies retain their WAF sessions.
func (server *proxyServer) invalidateNetworkProxy(id string) {
	// A name/enabled edit must not reset the unchanged route's WAF session.
	keep := ""
	if p, err := server.keys.networkProxyByID(id); err == nil {
		if parsed, err := parseNetworkProxyURL(p.URL); err == nil {
			if p.Username != "" {
				parsed.User = url.UserPassword(p.Username, p.Password)
			}
			digest := sha256.Sum256([]byte(parsed.String()))
			keep = id + ":" + hex.EncodeToString(digest[:])
		}
	}
	server.outbound.mu.Lock()
	defer server.outbound.mu.Unlock()
	for cacheID, route := range server.outbound.routes {
		if cacheID != keep && strings.HasPrefix(cacheID, id+":") {
			route.client.CloseIdleConnections()
			delete(server.outbound.routes, cacheID)
		}
	}
}

func (server *proxyServer) probeNetworkProxy(ctx context.Context, proxy *selectedNetworkProxy, target string) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	base, err := server.validateUpstreamURL(target)
	if err != nil {
		return 0, "invalid or disallowed probe target"
	}
	route, err := server.outboundRoute(&selectedAPIKey{NetworkProxy: proxy})
	if err != nil {
		return 0, "network proxy configuration invalid"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return 0, "network proxy probe failed"
	}
	req.Header.Set("User-Agent", "agentrouter-unified-proxy/network-probe")
	resp, err := route.client.Do(req)
	if err != nil {
		return 0, "network proxy connection failed"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return resp.StatusCode, "network proxy authentication rejected"
	}
	return resp.StatusCode, "HTTP response received through network proxy; upstream API credentials were not sent"
}

func networkProbeOK(status int) bool { return status > 0 && status != http.StatusProxyAuthRequired }

// This check does not change assignments or retry generations. Failures are
// route failures, not proof that any provider API key has become invalid.
func (server *proxyServer) handleAdminNetworkProxies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"data": server.keys.listNetworkProxies()})
	case http.MethodPost:
		var input networkProxyInput
		if decodeAdminJSON(w, r, &input) != nil {
			return
		}
		id, err := server.keys.saveNetworkProxy("", input)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_network_proxy_created", map[string]any{"proxy_id": id})
		writeJSON(w, 201, map[string]any{"id": id})
	default:
		writeError(w, 405, "method_not_allowed", "use GET or POST")
	}
}

func (server *proxyServer) handleAdminNetworkProxy(w http.ResponseWriter, r *http.Request, id string, test bool) {
	if test {
		if r.Method != http.MethodPost {
			writeError(w, 405, "method_not_allowed", "use POST")
			return
		}
		var input struct {
			TargetURL string `json:"target_url"`
		}
		if decodeAdminJSON(w, r, &input) != nil {
			return
		}
		if input.TargetURL == "" {
			input.TargetURL = server.cfg.UpstreamURL.String()
		}
		p, err := server.keys.networkProxyByID(id)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		start := time.Now()
		status, message := server.probeNetworkProxy(r.Context(), p, input.TargetURL)
		server.keys.recordProxyProbe(id, networkProbeOK(status))
		writeJSON(w, 200, map[string]any{"ok": networkProbeOK(status), "status": status, "message": message, "duration_ms": time.Since(start).Milliseconds()})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var input networkProxyInput
		if decodeAdminJSON(w, r, &input) != nil {
			return
		}
		_, err := server.keys.saveNetworkProxy(id, input)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		server.invalidateNetworkProxy(id)
		logEvent("info", "admin_network_proxy_updated", map[string]any{"proxy_id": id})
		writeJSON(w, 200, map[string]any{"id": id})
	case http.MethodDelete:
		if err := server.keys.deleteNetworkProxy(id); err != nil {
			writeAdminStoreError(w, err)
			return
		}
		server.invalidateNetworkProxy(id)
		logEvent("info", "admin_network_proxy_deleted", map[string]any{"proxy_id": id})
		w.WriteHeader(204)
	default:
		writeError(w, 405, "method_not_allowed", "use PATCH or DELETE")
	}
}
