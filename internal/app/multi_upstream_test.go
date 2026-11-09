package app

import (
	"context"
	"encoding/json"
	"io"
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

const nativeChatRequest = `{"model":"m","messages":[{"role":"user","content":"hello"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],"n":2,"custom":{"keep":true}}`
const nativeChatResponse = `{"id":"chatcmpl-native","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`
const responsesReply = `{"id":"resp_test","model":"m","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":3,"output_tokens":2}}`

func multiUpstreamProxy(t *testing.T, base string) *proxyServer {
	t.Helper()
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return newProxyServer(config{UpstreamURL: parsed, Profile: "claude-code", KeySelectionMode: "pool-only", KeyFailover: true, KeyCooldown: time.Minute, KeyStoreSecret: "multi-upstream-test-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"), ForceSequentialTools: true})
}

func addUpstream(t *testing.T, proxy *proxyServer, name, base, protocol, key string, priority int, models ...string) apiKeyView {
	t.Helper()
	view, err := proxy.keys.addWithPolicy(name, key, true, apiKeyPolicy{BaseURL: base, APIProtocol: protocol, Weight: 1, Priority: priority, Models: models})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func requestGateway(proxy *proxyServer, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer inbound-private-secret")
	request.Header.Set("X-Api-Key", "inbound-other-private-secret")
	request.Header.Set("Cookie", "client_session=private")
	request.Header.Set("X-Proxy-Token", "gateway-access-private")
	request.Header.Set("Anthropic-Beta", "client-spoof")
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, request)
	return recorder
}

func TestMultiUpstreamNativeChatAndConvertedResponses(t *testing.T) {
	for _, protocol := range []string{protocolChatCompletions, protocolResponses} {
		t.Run(protocol, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				if r.Header.Get("Authorization") != "Bearer sk-selected-provider" {
					t.Errorf("wrong provider credential")
				}
				for _, header := range []string{"X-Api-Key", "Cookie", "X-Proxy-Token", "Anthropic-Beta", "X-App"} {
					if r.Header.Get(header) != "" {
						t.Errorf("unexpected header %s", header)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if protocol == protocolChatCompletions {
					if r.URL.Path != "/api/v1/chat/completions" || string(raw) != nativeChatRequest {
						t.Errorf("native request changed: %s %s", r.URL.Path, raw)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, nativeChatResponse)
				} else {
					obj, err := decodeObject(raw)
					if err != nil || r.URL.Path != "/api/v1/responses" || obj["input"] == nil || obj["messages"] != nil || obj["parallel_tool_calls"] != false {
						t.Errorf("invalid Responses request: %s %s", r.URL.Path, raw)
					}
					_, _ = io.WriteString(w, responsesReply)
				}
			}))
			defer upstream.Close()
			proxy := multiUpstreamProxy(t, "https://agentrouter.org")
			key := addUpstream(t, proxy, "Custom", upstream.URL+"/api/v1", protocol, "sk-selected-provider", 0)
			proxy.cookies.capture(http.Header{"Set-Cookie": {"acw_tc=agentrouter-private; Path=/"}})
			recorder := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
			if protocol == protocolChatCompletions {
				if recorder.Code != http.StatusCreated || recorder.Body.String() != nativeChatResponse {
					t.Fatalf("native response changed: %d %s", recorder.Code, recorder.Body.String())
				}
			} else if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"content":"ok"`) {
				t.Fatalf("conversion failed: %d %s", recorder.Code, recorder.Body.String())
			}
			views, _ := proxy.keys.list()
			if len(views) != 1 || views[0].ID != key.ID || views[0].InputTokens != 3 || views[0].OutputTokens != 2 {
				t.Fatalf("usage missing: %+v", views)
			}
		})
	}
}

func TestMultiUpstreamFailoverRebuildsProtocolAndAuthorization(t *testing.T) {
	for _, firstProtocol := range []string{protocolResponses, protocolChatCompletions} {
		t.Run(firstProtocol, func(t *testing.T) {
			secondProtocol := protocolResponses
			if firstProtocol == protocolResponses {
				secondProtocol = protocolChatCompletions
			}
			var calls atomic.Int32
			makeUpstream := func(protocol, credential string, failing bool) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					body, _ := io.ReadAll(r.Body)
					obj, _ := decodeObject(body)
					if r.Header.Get("Authorization") != "Bearer "+credential || r.Header.Get("X-Api-Key") != "" {
						t.Errorf("credential isolation failed")
					}
					if protocol == protocolResponses {
						if r.URL.Path != "/v1/responses" || obj["input"] == nil || obj["messages"] != nil {
							t.Errorf("bad Responses attempt: %s %s", r.URL.Path, body)
						}
					} else if r.URL.Path != "/v1/chat/completions" || string(body) != nativeChatRequest {
						t.Errorf("bad Chat attempt: %s %s", r.URL.Path, body)
					}
					w.Header().Set("Content-Type", "application/json")
					if failing {
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = io.WriteString(w, `{"error":"rate limited"}`)
						return
					}
					if protocol == protocolResponses {
						_, _ = io.WriteString(w, responsesReply)
					} else {
						_, _ = io.WriteString(w, nativeChatResponse)
					}
				}))
			}
			first := makeUpstream(firstProtocol, "sk-first-provider", true)
			defer first.Close()
			second := makeUpstream(secondProtocol, "sk-second-provider", false)
			defer second.Close()
			proxy := multiUpstreamProxy(t, first.URL)
			failed := addUpstream(t, proxy, "First", first.URL+"/v1", firstProtocol, "sk-first-provider", 10)
			addUpstream(t, proxy, "Second", second.URL, secondProtocol, "sk-second-provider", 0)
			recorder := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
			if recorder.Code != 200 || calls.Load() != 2 {
				t.Fatalf("failover failed: %d calls=%d %s", recorder.Code, calls.Load(), recorder.Body.String())
			}
			views, _ := proxy.keys.list()
			for _, view := range views {
				if view.ID == failed.ID && (view.CooldownUntil == nil || view.Failures != 1) {
					t.Fatalf("failed key not cooled: %+v", view)
				}
			}
		})
	}
}

func TestMultiUpstreamProtocolAndModelFiltering(t *testing.T) {
	var wrongCalls, rightCalls atomic.Int32
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrongCalls.Add(1); w.WriteHeader(500) }))
	defer wrong.Close()
	right := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rightCalls.Add(1)
		_, _ = io.WriteString(w, responsesReply)
	}))
	defer right.Close()
	proxy := multiUpstreamProxy(t, wrong.URL)
	addUpstream(t, proxy, "Chat-only", wrong.URL, protocolChatCompletions, "sk-chat-provider", 100, "m")
	addUpstream(t, proxy, "Other model", wrong.URL, protocolResponses, "sk-other-model-provider", 100, "different")
	valid := addUpstream(t, proxy, "Compatible", right.URL, protocolResponses, "sk-right-provider", 0, "m")
	recorder := requestGateway(proxy, "/v1/responses", `{"model":"m","input":"hello"}`)
	if recorder.Code != 200 || wrongCalls.Load() != 0 || rightCalls.Load() != 1 {
		t.Fatalf("wrong routing: %d wrong=%d right=%d", recorder.Code, wrongCalls.Load(), rightCalls.Load())
	}
	disabled := false
	_, _ = proxy.keys.update(valid.ID, nil, &disabled)
	recorder = requestGateway(proxy, "/v1/responses", `{"model":"m","input":"hello"}`)
	if recorder.Code != 503 || !strings.Contains(recorder.Body.String(), "no_compatible_upstream") || wrongCalls.Load() != 0 {
		t.Fatalf("missing incompatible error: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = requestGateway(proxy, "/v1/chat/completions", `{"model":"unlisted","messages":[]}`)
	if recorder.Code != 503 || wrongCalls.Load() != 0 {
		t.Fatal("model allowlist was bypassed")
	}
}

func TestMultiUpstreamStreamingModes(t *testing.T) {
	native := "data: {\"id\":\"chatcmpl-s\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":5}}\n\ndata: [DONE]\n\n"
	responses := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":4,\"output_tokens\":5}}}\n\n"
	for _, protocol := range []string{protocolChatCompletions, protocolResponses} {
		t.Run(protocol, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept") != "text/event-stream" {
					t.Errorf("missing SSE accept")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				text := native
				if protocol == protocolResponses {
					text = responses
				}
				for _, frame := range strings.Split(text, "\n\n") {
					if frame != "" {
						_, _ = io.WriteString(w, frame+"\n\n")
						w.(http.Flusher).Flush()
					}
				}
			}))
			defer upstream.Close()
			proxy := multiUpstreamProxy(t, "https://agentrouter.org")
			addUpstream(t, proxy, "Streaming", upstream.URL, protocol, "sk-stream-provider", 0)
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[],"stream":true}`))
			recorder := newFlushRecorder()
			proxy.routes().ServeHTTP(recorder, request)
			if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "data: [DONE]") || recorder.flushes < 2 || recorder.Header().Get("X-Accel-Buffering") != "no" {
				t.Fatalf("SSE broken: %d %s", recorder.Code, recorder.Body.String())
			}
			if protocol == protocolChatCompletions && recorder.Body.String() != native {
				t.Fatal("native SSE changed")
			}
			views, _ := proxy.keys.list()
			if views[0].InputTokens != 4 || views[0].OutputTokens != 5 {
				t.Fatalf("stream usage=%+v", views[0])
			}
		})
	}
}

func TestMultiUpstreamURLValidationAndJoining(t *testing.T) {
	proxy := multiUpstreamProxy(t, "https://agentrouter.org")
	for _, tc := range []struct{ base, want string }{
		{"https://provider.example", "https://provider.example/v1/chat/completions"},
		{"https://provider.example/", "https://provider.example/v1/chat/completions"},
		{"https://provider.example/v1", "https://provider.example/v1/chat/completions"},
		{"https://provider.example/api/v1/", "https://provider.example/api/v1/chat/completions"},
		{"https://provider.example/custom", "https://provider.example/custom/v1/chat/completions"},
		{"https://provider.example/tenant%2Fname/v1", "https://provider.example/tenant%2Fname/v1/chat/completions"},
	} {
		base, err := parseUpstreamURL(tc.base)
		if err != nil {
			t.Fatal(err)
		}
		if got := proxy.upstreamURLFor(base, "/v1/chat/completions"); got != tc.want {
			t.Errorf("URL=%s want=%s", got, tc.want)
		}
	}
	for _, raw := range []string{"provider.example", "ftp://provider.example", "https://user:secret@provider.example", "https://provider.example?token=secret", "https://provider.example?", "https://provider.example#fragment", "https://provider.example#", "http://", "http://provider.example:invalid", "http://provider.example:0", "http://provider.example:70000"} {
		if _, err := proxy.keys.addWithPolicy("Invalid", "sk-invalid-url-provider", true, apiKeyPolicy{BaseURL: raw}); err == nil {
			t.Errorf("accepted invalid URL %s", raw)
		}
	}
}

func TestMultiUpstreamCookieCaptureAndRedirectIsolation(t *testing.T) {
	var foreignCalls atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignCalls.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Anthropic-Version") != "" {
			t.Error("AgentRouter state leaked")
		}
		w.Header().Add("Set-Cookie", "acw_tc=foreign-poison; Path=/")
		w.WriteHeader(200)
	}))
	defer foreign.Close()
	trusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "acw_tc=trusted-cookie" {
			t.Error("trusted cookie missing")
		}
		http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
	}))
	defer trusted.Close()
	proxy := multiUpstreamProxy(t, trusted.URL)
	proxy.cookies.capture(http.Header{"Set-Cookie": {"acw_tc=trusted-cookie"}})
	trustedKey := addUpstream(t, proxy, "Trusted", trusted.URL, protocolResponses, "sk-trusted-provider", 10)
	custom := addUpstream(t, proxy, "Foreign", foreign.URL, protocolChatCompletions, "sk-foreign-provider", 0)
	recorder := requestGateway(proxy, "/v1/responses", `{"model":"m","input":"hi"}`)
	if recorder.Code != 307 || foreignCalls.Load() != 0 {
		t.Fatal("upstream redirect followed")
	}
	disabled := false
	_, _ = proxy.keys.update(trustedKey.ID, nil, &disabled)
	_ = requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
	key, _ := proxy.keys.byID(custom.ID)
	_, _ = proxy.probeAPIKey(context.Background(), *key)
	if foreignCalls.Load() != 2 || proxy.cookies.header() != "acw_tc=trusted-cookie" {
		t.Fatal("foreign cookie poisoned trusted store")
	}
	parsed := *proxy.cfg.UpstreamURL
	parsed.Scheme = "https"
	if proxy.usesWAFCookies(&parsed, "claude-code") {
		t.Fatal("cookies are not scoped to scheme")
	}
}

func TestMultiUpstreamLegacyStoreAndBackup(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keys.json")
			store := newAPIKeyStore(path, "migration-secret")
			old, err := store.add("Legacy", "sk-legacy-provider", true)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := store.exportBackup()
			var file map[string]any
			_ = json.Unmarshal(raw, &file)
			file["version"] = version
			legacy, _ := json.Marshal(file)
			if err := os.WriteFile(path, legacy, 0600); err != nil {
				t.Fatal(err)
			}
			reloaded := newAPIKeyStore(path, "migration-secret")
			key, err := reloaded.byID(old.ID)
			if err != nil || key.Key != "sk-legacy-provider" || key.APIProtocol != protocolResponses {
				t.Fatal("legacy credential lost")
			}
			added, err := reloaded.addWithPolicy("Chat", "sk-chat-restored-provider", true, apiKeyPolicy{BaseURL: "https://provider.example/api/v1", APIProtocol: protocolChatCompletions, SpoofProfile: "generic", Weight: 3, Priority: 4, Models: []string{"m"}})
			if err != nil {
				t.Fatal(err)
			}
			backup, _ := reloaded.exportBackup()
			if strings.Contains(string(backup), "sk-chat-restored-provider") {
				t.Fatal("plaintext credential in backup")
			}
			restored := newAPIKeyStore(filepath.Join(t.TempDir(), "restored.json"), "migration-secret")
			if err := restored.importBackup(backup); err != nil {
				t.Fatal(err)
			}
			selected, err := restored.byID(added.ID)
			if err != nil || selected.APIProtocol != protocolChatCompletions || selected.BaseURL != "https://provider.example/api/v1" || selected.SpoofProfile != "generic" || selected.Key != "sk-chat-restored-provider" {
				t.Fatalf("settings lost: %+v %v", selected, err)
			}
			// Existing admin callers omitting api_protocol must not reset it.
			updated, err := restored.updatePolicy(added.ID, apiKeyPolicy{Weight: 1})
			if err != nil || updated.APIProtocol != protocolChatCompletions {
				t.Fatal("old policy client reset protocol")
			}
		})
	}
}

func TestMultiUpstreamOptionalModelsProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	view := addUpstream(t, proxy, "No models", upstream.URL, protocolChatCompletions, "sk-no-models-provider", 0)
	proxy.keys.recordResult(view.ID, 429, "rate limited", time.Hour)
	proxy.probeAllKeys(context.Background())
	keys, _ := proxy.keys.list()
	if keys[0].Failures != 1 || keys[0].LastError != "rate limited" || keys[0].CooldownUntil == nil {
		t.Fatal("optional models changed health/cooldown")
	}
	recorder := httptest.NewRecorder()
	proxy.handleAdminKeyTest(recorder, httptest.NewRequest(http.MethodPost, "/test", nil), view.ID)
	var result map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &result)
	if result["ok"] != false || result["inconclusive"] != true || result["status"] != float64(404) {
		t.Fatalf("misleading probe result: %s", recorder.Body.String())
	}
}

func TestMultiUpstreamConcurrentRoundRobin(t *testing.T) {
	var first, second atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer sk-round-robin-first":
			first.Add(1)
		case "Bearer sk-round-robin-second":
			second.Add(1)
		default:
			t.Error("wrong credential")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	addUpstream(t, proxy, "First", upstream.URL, protocolChatCompletions, "sk-round-robin-first", 0)
	addUpstream(t, proxy, "Second", upstream.URL, protocolChatCompletions, "sk-round-robin-second", 0)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
			if recorder.Code != 200 {
				t.Errorf("concurrent status=%d", recorder.Code)
			}
			_, _ = proxy.keys.list()
			_ = proxy.keys.status()
		}()
	}
	wg.Wait()
	if first.Load() != 12 || second.Load() != 12 {
		t.Fatalf("round-robin counts=%d/%d", first.Load(), second.Load())
	}
	views, _ := proxy.keys.list()
	for _, view := range views {
		if view.Uses != 12 || view.InputTokens != 36 || view.OutputTokens != 24 {
			t.Fatalf("concurrent usage lost: %+v", view)
		}
	}
}

func TestMultiUpstreamDoesNotRetryAmbiguousPOST(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	proxy.cfg.MaxRetries = 2
	proxy.cfg.RetryDelay = time.Millisecond
	addUpstream(t, proxy, "Ambiguous", upstream.URL, protocolChatCompletions, "sk-ambiguous-provider", 0)
	recorder := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
	if recorder.Code != 502 || calls.Load() != 1 {
		t.Fatalf("ambiguous POST repeated: %d calls=%d", recorder.Code, calls.Load())
	}
	proxy.cfg.RetryUnsafeRequests = true
	recorder = requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
	if recorder.Code != 502 || calls.Load() != 4 {
		t.Fatalf("explicit retry policy broken: %d calls=%d", recorder.Code, calls.Load())
	}
}

func TestMultiUpstreamRoutingModesKeepInboundAtDefault(t *testing.T) {
	for _, mode := range []string{"inbound-first", "pool-first", "pool-only"} {
		t.Run(mode, func(t *testing.T) {
			var defaultCalls, poolCalls atomic.Int32
			defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defaultCalls.Add(1)
				if r.Header.Get("Authorization") != "Bearer inbound-private-secret" {
					t.Error("default received wrong key")
				}
				_, _ = io.WriteString(w, nativeChatResponse)
			}))
			defer defaultUpstream.Close()
			pool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				poolCalls.Add(1)
				if r.Header.Get("Authorization") != "Bearer sk-pool-isolated-provider" || r.Header.Get("X-Api-Key") != "" {
					t.Error("pool received inbound key")
				}
				_, _ = io.WriteString(w, nativeChatResponse)
			}))
			defer pool.Close()
			proxy := multiUpstreamProxy(t, defaultUpstream.URL)
			proxy.cfg.UpstreamProtocol = protocolChatCompletions
			proxy.routingMode.Store(mode)
			view := addUpstream(t, proxy, "Pool", pool.URL, protocolChatCompletions, "sk-pool-isolated-provider", 0)
			recorder := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
			if recorder.Code != 200 {
				t.Fatalf("status=%d", recorder.Code)
			}
			if mode == "inbound-first" {
				if defaultCalls.Load() != 1 || poolCalls.Load() != 0 {
					t.Fatal("inbound priority broken")
				}
			} else if defaultCalls.Load() != 0 || poolCalls.Load() != 1 {
				t.Fatal("pool priority broken")
			}
			disabled := false
			_, _ = proxy.keys.update(view.ID, nil, &disabled)
			recorder = requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
			if mode == "pool-only" {
				if recorder.Code != 503 || defaultCalls.Load() != 0 {
					t.Fatal("pool-only fell back to inbound")
				}
			} else if recorder.Code != 200 {
				t.Fatal("inbound fallback broken")
			}
		})
	}
}

func TestMultiUpstreamGatewayClientCannotBecomeUpstreamKey(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer sk-stored-private-provider" || r.Header.Get("X-Api-Key") != "" {
			t.Error("gateway credential leaked")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	proxy.routingMode.Store("inbound-first")
	view := addUpstream(t, proxy, "Stored", upstream.URL, protocolChatCompletions, "sk-stored-private-provider", 0)
	_, token, err := proxy.keys.createClientKey("Client")
	if err != nil {
		t.Fatal(err)
	}
	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(nativeChatRequest))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Api-Key", token)
		rec := httptest.NewRecorder()
		proxy.routes().ServeHTTP(rec, req)
		return rec
	}
	if rec := send(); rec.Code != 200 {
		t.Fatalf("client request=%d %s", rec.Code, rec.Body.String())
	}
	if err := proxy.keys.delete(view.ID); err != nil {
		t.Fatal(err)
	}
	if rec := send(); rec.Code != 503 || calls.Load() != 1 {
		t.Fatal("client request bypassed empty pool")
	}
}

func TestMultiUpstreamFailoverExhaustionIsBounded(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"rejected"}`)
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	addUpstream(t, proxy, "First", upstream.URL, protocolChatCompletions, "sk-rejected-first-provider", 0)
	addUpstream(t, proxy, "Second", upstream.URL, protocolChatCompletions, "sk-rejected-second-provider", 0)
	rec := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 401 || calls.Load() != 2 || rec.Body.String() != `{"error":"rejected"}` {
		t.Fatalf("failover exhaustion broken: %d calls=%d", rec.Code, calls.Load())
	}
}

func TestMultiUpstreamNativeErrorBodyIsNotTruncated(t *testing.T) {
	payload := strings.Repeat("x", (4<<20)+4096)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, upstream.URL)
	addUpstream(t, proxy, "First", upstream.URL, protocolChatCompletions, "sk-error-first-provider", 0)
	// A second record enables a failover search, but its allowlist excludes m.
	addUpstream(t, proxy, "Excluded", upstream.URL, protocolChatCompletions, "sk-error-excluded-provider", 0, "other")
	rec := requestGateway(proxy, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 401 || rec.Body.String() != payload {
		t.Fatalf("native error truncated: status=%d bytes=%d", rec.Code, rec.Body.Len())
	}
}

func TestMultiUpstreamDirectResponsesSSE(t *testing.T) {
	payload := "event: response.created\ndata: {\"type\":\"response.created\"}\n\ndata: [DONE]\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("wrong endpoint: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()
	proxy := multiUpstreamProxy(t, "https://agentrouter.org")
	addUpstream(t, proxy, "Responses", upstream.URL+"/v1", protocolResponses, "sk-direct-sse-provider", 0)
	rec := requestGateway(proxy, "/v1/responses", `{"model":"m","input":"hi","stream":true}`)
	if rec.Code != 200 || rec.Body.String() != payload {
		t.Fatal("direct Responses SSE changed")
	}
}

func TestMultiUpstreamMalformedBackupCannotPanicOrReplaceKeys(t *testing.T) {
	store := newAPIKeyStore(filepath.Join(t.TempDir(), "keys.json"), "backup-test-secret")
	original, err := store.add("Original", "sk-preserved-provider", true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := store.exportBackup()
	var file persistedKeyFile
	_ = json.Unmarshal(raw, &file)
	file.Keys[0].Nonce = "AA"
	malformed, _ := json.Marshal(file)
	if err := store.importBackup(malformed); err == nil {
		t.Fatal("invalid nonce accepted")
	}
	key, err := store.byID(original.ID)
	if err != nil || key.Key != "sk-preserved-provider" {
		t.Fatal("invalid backup damaged store")
	}
}

func TestMultiUpstreamAdminCreateAndAllowlist(t *testing.T) {
	proxy := multiUpstreamProxy(t, "https://agentrouter.org")
	proxy.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "admin-test-private-token"}}
	proxy.cfg.AllowedUpstreamOrigins = []string{"https://agentrouter.org", "http://127.0.0.1:9999"}
	send := func(base string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"name": "Local", "key": "sk-admin-create-provider", "enabled": false, "policy": apiKeyPolicy{BaseURL: base, APIProtocol: protocolChatCompletions, SpoofProfile: "generic", Weight: 2}})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/keys", strings.NewReader(string(raw)))
		req.Header.Set("X-Admin-Token", "admin-test-private-token")
		rec := httptest.NewRecorder()
		proxy.routes().ServeHTTP(rec, req)
		return rec
	}
	denied := send("http://169.254.169.254/latest")
	if denied.Code != 400 {
		t.Fatal("SSRF origin allowlist bypassed")
	}
	created := send("http://127.0.0.1:9999/api/v1")
	if created.Code != 201 || strings.Contains(created.Body.String(), "sk-admin-create-provider") {
		t.Fatalf("admin create failed: %d %s", created.Code, created.Body.String())
	}
	var view apiKeyView
	_ = json.Unmarshal(created.Body.Bytes(), &view)
	if view.APIProtocol != protocolChatCompletions || view.Enabled || view.BaseURL != "http://127.0.0.1:9999/api/v1" {
		t.Fatalf("create settings lost: %+v", view)
	}
	// Runtime restriction applies even to entries introduced by an encrypted backup.
	key, _ := proxy.keys.byID(view.ID)
	proxy.cfg.AllowedUpstreamOrigins = []string{"https://agentrouter.org"}
	if _, _, _, err := proxy.upstreamSettings(key); err == nil {
		t.Fatal("loaded key bypassed runtime allowlist")
	}
}
