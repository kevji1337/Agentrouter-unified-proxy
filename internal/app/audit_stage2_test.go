package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheAuthIsolationAndPoolAvailability(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk-valid-user-a" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid api key"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-iso","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"secret-answer"}}]}`)
	}))
	defer upstream.Close()

	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{
		UpstreamURL:      parsed,
		UpstreamProtocol: protocolChatCompletions,
		Profile:          "generic",
		KeySelectionMode: "inbound-first",
		ResponseCache:    true,
		KeyStoreSecret:   "cache-iso-secret",
		KeyStorePath:     filepath.Join(t.TempDir(), "keys.json"),
	})

	body := `{"model":"gpt-4o","temperature":0,"messages":[{"role":"user","content":"secret prompt"}]}`

	// 1. User A populates cache with valid inbound Bearer key.
	reqA := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	reqA.Header.Set("Authorization", "Bearer sk-valid-user-a")
	recA := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK || recA.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("User A first call failed: %d %s", recA.Code, recA.Body.String())
	}

	// 2. User A second call hits cache.
	reqA2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	reqA2.Header.Set("Authorization", "Bearer sk-valid-user-a")
	recA2 := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recA2, reqA2)
	if recA2.Code != http.StatusOK || recA2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("User A expected HIT, got %d X-Cache=%s", recA2.Code, recA2.Header().Get("X-Cache"))
	}

	// 3. User B with wrong inbound key MUST NOT receive User A's cached answer.
	reqB := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	reqB.Header.Set("Authorization", "Bearer sk-invalid-user-b")
	recB := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recB, reqB)
	if recB.Code != http.StatusUnauthorized || strings.Contains(recB.Body.String(), "secret-answer") {
		t.Fatalf("cross-tenant cache leak! status=%d body=%s", recB.Code, recB.Body.String())
	}

	// 4. Pool-only mode: disabling all keys in pool must reject cached responses with 503.
	poolProxy := multiUpstreamProxy(t, upstream.URL)
	view := addUpstream(t, poolProxy, "PoolA", upstream.URL, protocolChatCompletions, "sk-valid-user-a", 10, "gpt-4o")
	recPool1 := requestGateway(poolProxy, "/v1/chat/completions", body)
	if recPool1.Code != http.StatusOK {
		t.Fatalf("pool first call=%d", recPool1.Code)
	}
	disabled := false
	if _, err := poolProxy.keys.update(view.ID, nil, &disabled); err != nil {
		t.Fatal(err)
	}
	recPool2 := requestGateway(poolProxy, "/v1/chat/completions", body)
	if recPool2.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled pool served stale cache: status=%d body=%s", recPool2.Code, recPool2.Body.String())
	}
}

func TestCacheKeyIncludesSemanticParametersAndCapsTTL(t *testing.T) {
	base := map[string]any{
		"model":       "gpt-4o",
		"temperature": 0.0,
		"messages":    []any{map[string]any{"role": "user", "content": "solve"}},
	}
	withHighReasoning := map[string]any{
		"model":            "gpt-4o",
		"temperature":      0.0,
		"reasoning_effort": "high",
		"messages":         []any{map[string]any{"role": "user", "content": "solve"}},
	}
	withStop := map[string]any{
		"model":       "gpt-4o",
		"temperature": 0.0,
		"stop":        []any{"END"},
		"messages":    []any{map[string]any{"role": "user", "content": "solve"}},
	}
	kBase, _ := computeCacheKey(base)
	kHigh, _ := computeCacheKey(withHighReasoning)
	kStop, _ := computeCacheKey(withStop)
	if kBase == kHigh || kBase == kStop || kHigh == kStop {
		t.Fatalf("semantic cache collision: base=%s high=%s stop=%s", kBase, kHigh, kStop)
	}

	cache := newResponseCache(true, time.Hour, 100, false)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Cache-TTL", "87600h")
	_, ttl, ok := cache.isCacheable(req, nil, base)
	if !ok || ttl != maxCustomCacheTTL {
		t.Fatalf("expected TTL capped at %v, got ok=%v ttl=%v", maxCustomCacheTTL, ok, ttl)
	}

	// Verify config{ResponseCache: false} is respected even when RESPONSE_CACHE env is unset.
	parsed, _ := url.Parse("https://agentrouter.org")
	disabledServer := newProxyServer(config{UpstreamURL: parsed, ResponseCache: false})
	if disabledServer.cache.enabled {
		t.Fatal("ResponseCache: false was overridden to true")
	}
}

func TestNegativeAndOverflowUsageNeverCorruptsBudget(t *testing.T) {
	in, out := parseUsage([]byte(`{"usage":{"prompt_tokens":-1,"completion_tokens":-500}}`))
	if in != 0 || out != 0 {
		t.Fatalf("negative usage overflowed to %d / %d", in, out)
	}
	if v := uint64Value(json.Number("-42")); v != 0 {
		t.Fatalf("expected 0 for negative json.Number, got %d", v)
	}
}

func TestGenAITransportFailureAndClientBadRequestDoNotPenalizeKeyOrLeakProxyURL(t *testing.T) {
	proxy := multiUpstreamProxy(t, "http://127.0.0.1:1")
	proxyUser, proxyPass := "secret-proxy-user", "secret-proxy-pass"
	proxyID, err := proxy.keys.saveNetworkProxy("", networkProxyInput{
		Name: "DeadProxy", URL: "http://127.0.0.1:1", Username: &proxyUser, Password: &proxyPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := addUpstream(t, proxy, "GeminiKey", "http://127.0.0.1:1", protocolGenAI, "sk-gemini-secret", 10, "gemini-2.5-flash")

	// 1. Invalid client request body (messages[0] not an object) -> 400 invalid_request, 0 key failures.
	badBody := `{"model":"gemini-2.5-flash","messages":["not-an-object"]}`
	recBad := requestGateway(proxy, "/v1/chat/completions", badBody)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed client messages, got %d: %s", recBad.Code, recBad.Body.String())
	}
	views, _ := proxy.keys.list()
	if views[0].Failures != 0 {
		t.Fatalf("client validation failure penalized API key: %+v", views[0])
	}

	// 2. Dead proxy transport failure -> 502 without leaking proxy credentials/URL, 0 key failures, proxy marked failed.
	validBody := `{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]}`
	recNet := requestGateway(proxy, "/v1/chat/completions", validBody)
	if recNet.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on dead proxy, got %d: %s", recNet.Code, recNet.Body.String())
	}
	for _, secret := range []string{proxyUser, proxyPass, "127.0.0.1:1", "sk-gemini-secret"} {
		if strings.Contains(recNet.Body.String(), secret) {
			t.Fatalf("GenAI transport error leaked %q in body: %s", secret, recNet.Body.String())
		}
	}
	views, _ = proxy.keys.list()
	if views[0].ID != key.ID || views[0].Failures != 0 {
		t.Fatalf("dead proxy penalized GenAI API key: %+v", views[0])
	}
	proxies := proxy.keys.listNetworkProxies()
	if len(proxies) != 1 || proxies[0].ID != proxyID || proxies[0].LastError == "" {
		t.Fatalf("dead proxy failure was not recorded on network proxy: %+v", proxies)
	}
}

func TestGenAIStreamEarlyCloseCancelsProducerAndTracksHiddenUsage(t *testing.T) {
	// Part 1: Verify include_usage=false still records tokens in key store.
	usageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":17,"candidatesTokenCount":9,"totalTokenCount":26}}`+"\n\n")
		w.(http.Flusher).Flush()
	}))
	defer usageServer.Close()

	gateway := multiUpstreamProxy(t, usageServer.URL)
	view := addUpstream(t, gateway, "GenAIUsage", usageServer.URL, protocolGenAI, "sk-genai-usage-key", 10, "gemini-2.5-flash")
	rec := requestGateway(gateway, "/v1/chat/completions", `{"model":"gemini-2.5-flash","stream":true,"stream_options":{"include_usage":false},"messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"usage"`) {
		t.Fatalf("include_usage=false leaked usage chunk to client:\n%s", rec.Body.String())
	}
	keys, _ := gateway.keys.list()
	if len(keys) != 1 || keys[0].ID != view.ID || keys[0].InputTokens != 17 || keys[0].OutputTokens != 9 {
		t.Fatalf("hidden GenAI stream usage was lost: %+v", keys)
	}

	// Part 2: Early downstream close stops upstream stream promptly.
	upstreamDone := make(chan struct{})
	slowStream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 50; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			_, writeErr := fmt.Fprintf(w, "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"chunk-%d \"}]}}]}\n\n", i)
			if writeErr != nil {
				return
			}
			flusher.Flush()
			time.Sleep(15 * time.Millisecond)
		}
	}))
	defer slowStream.Close()

	gateway2 := multiUpstreamProxy(t, slowStream.URL)
	addUpstream(t, gateway2, "GenAISlow", slowStream.URL, protocolGenAI, "sk-genai-slow-key", 10, "gemini-2.5-flash")
	resp, err := gateway2.doUpstream(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).Context(), make(http.Header), http.MethodPost, "/v1/chat/completions", []byte(`{"model":"gemini-2.5-flash","stream":true,"messages":[{"role":"user","content":"hi"}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = resp.Body.Read(buf)
	_ = resp.Body.Close()

	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("GenAI upstream stream goroutine leaked after downstream body close")
	}
}

func TestPassthroughSkipsGenAIKeysInMixedPool(t *testing.T) {
	var openAICalls atomic.Int32
	openAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openAICalls.Add(1)
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2]}]}`)
	}))
	defer openAI.Close()

	gateway := multiUpstreamProxy(t, openAI.URL)
	// GenAI key has HIGHER priority (100), OpenAI key has lower priority (10).
	genaiView := addUpstream(t, gateway, "GeminiHighPrio", "https://generativelanguage.googleapis.com", protocolGenAI, "sk-gemini-prio", 100)
	addUpstream(t, gateway, "OpenAILowPrio", openAI.URL, protocolChatCompletions, "sk-openai-prio", 10)

	rec := requestGateway(gateway, "/v1/embeddings", `{"model":"text-embedding-3-small","input":"hello"}`)
	if rec.Code != http.StatusOK || openAICalls.Load() != 1 {
		t.Fatalf("passthrough failed in mixed pool: status=%d calls=%d body=%s", rec.Code, openAICalls.Load(), rec.Body.String())
	}
	views, _ := gateway.keys.list()
	for _, v := range views {
		if v.ID == genaiView.ID && v.Uses != 0 {
			t.Fatalf("incompatible GenAI key had Uses incremented on /v1/embeddings: %+v", v)
		}
	}
}
