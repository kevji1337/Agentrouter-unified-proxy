package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCacheKeyDeterminism(t *testing.T) {
	req1 := map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "user", "content": "What is 2+2?"},
		},
		"temperature": float64(0),
	}
	req2 := map[string]any{
		"temperature": float64(0),
		"messages": []any{
			map[string]any{"role": "user", "content": "What is 2+2?"},
		},
		"model": "gpt-4o",
	}
	req3 := map[string]any{
		"model": "gpt-4o-mini",
		"messages": []any{
			map[string]any{"role": "user", "content": "What is 2+2?"},
		},
		"temperature": float64(0),
	}

	key1, err1 := computeCacheKey(req1)
	key2, err2 := computeCacheKey(req2)
	key3, err3 := computeCacheKey(req3)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("computeCacheKey failed: %v %v %v", err1, err2, err3)
	}
	if key1 != key2 {
		t.Errorf("expected key1 == key2 for identical semantic content, got %s vs %s", key1, key2)
	}
	if key1 == key3 {
		t.Errorf("expected different keys for different models, got same: %s", key1)
	}
}

func TestResponseCacheMemoryStore(t *testing.T) {
	cache := newResponseCache(true, 50*time.Millisecond, 100, false)
	ctx := context.Background()

	// Initial get must miss
	if _, hit := cache.get(ctx, "k1"); hit {
		t.Fatal("expected cache miss")
	}

	// Set and get
	cache.set(ctx, "k1", []byte("hello-cache"), 50*time.Millisecond)
	val, hit := cache.get(ctx, "k1")
	if !hit || string(val) != "hello-cache" {
		t.Fatalf("expected cache hit with 'hello-cache', got hit=%v val=%s", hit, string(val))
	}

	// Wait for expiration
	time.Sleep(70 * time.Millisecond)
	if _, hit := cache.get(ctx, "k1"); hit {
		t.Fatal("expected cache miss after TTL expiration")
	}

	// Clear
	cache.set(ctx, "k2", []byte("val2"), time.Hour)
	cache.clear(ctx)
	if _, hit := cache.get(ctx, "k2"); hit {
		t.Fatal("expected cache miss after clear")
	}
}

func TestResponseCacheIsCacheable(t *testing.T) {
	cache := newResponseCache(true, time.Hour, 100, false)

	// 1. Omitted temperature -> not cacheable
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	_, _, ok := cache.isCacheable(r, nil, map[string]any{"model": "m", "messages": []any{}})
	if ok {
		t.Fatal("expected omitted temperature to NOT be cacheable")
	}

	// 2. Temperature > 0.05 -> not cacheable
	_, _, ok = cache.isCacheable(r, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.7})
	if ok {
		t.Fatal("expected temperature 0.7 to NOT be cacheable")
	}

	// 3. Temperature 0 -> cacheable!
	key, ttl, ok := cache.isCacheable(r, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.0})
	if !ok || key == "" || ttl != time.Hour {
		t.Fatalf("expected temperature 0 to be cacheable with 1h TTL, got ok=%v key=%s ttl=%v", ok, key, ttl)
	}

	// 4. Force cache with X-Cache: true header even if temperature is 0.7
	rForce := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	rForce.Header.Set("X-Cache", "true")
	_, _, ok = cache.isCacheable(rForce, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.7})
	if !ok {
		t.Fatal("expected X-Cache: true to force caching")
	}

	// 5. Custom TTL header X-Cache-TTL: 5m
	rTTL := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	rTTL.Header.Set("X-Cache-TTL", "5m")
	_, customTTL, ok := cache.isCacheable(rTTL, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.0})
	if !ok || customTTL != 5*time.Minute {
		t.Fatalf("expected custom TTL 5m, got ok=%v ttl=%v", ok, customTTL)
	}

	// 6. Cache-Control: no-cache skips cache
	rSkip := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	rSkip.Header.Set("Cache-Control", "no-cache")
	_, _, ok = cache.isCacheable(rSkip, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.0})
	if ok {
		t.Fatal("expected Cache-Control: no-cache to skip caching")
	}

	// 7. stream: true is not cached
	_, _, ok = cache.isCacheable(r, nil, map[string]any{"model": "m", "messages": []any{}, "temperature": 0.0, "stream": true})
	if ok {
		t.Fatal("expected stream: true to NOT be cacheable")
	}
}

func TestResponseCacheEndToEnd(t *testing.T) {
	callCount := 0
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "chatcmpl-cache-test",
			"object": "chat.completion",
			"choices": []any{
				map[string]any{
					"index":   0,
					"message": map[string]any{"role": "assistant", "content": "The answer is 42."},
				},
			},
		})
	}))
	defer mockUpstream.Close()

	proxy := multiUpstreamProxy(t, mockUpstream.URL)
	addUpstream(t, proxy, "cache-test-key", mockUpstream.URL, protocolChatCompletions, "sk-cache-key-test", 100, "gemini-2.5-flash")

	reqBody := `{"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "What is the answer?"}], "temperature": 0}`

	// First call: Cache MISS
	rec1 := requestGateway(proxy, "/v1/chat/completions", reqBody)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec1.Code, rec1.Body.String())
	}
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS on first call, got %s", rec1.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Fatalf("expected 1 upstream call, got %d", callCount)
	}

	// Second call with same deterministic payload: Cache HIT!
	rec2 := requestGateway(proxy, "/v1/chat/completions", reqBody)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on cached call, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT on second call, got %s", rec2.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("upstream should not be called on cache hit, callCount is %d", callCount)
	}
	if !strings.Contains(rec2.Body.String(), "The answer is 42.") {
		t.Errorf("expected cached response body to match, got %s", rec2.Body.String())
	}

	// Third call with Cache-Control: no-cache: Bypasses cache and calls upstream!
	req3 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer sk-cache-key-test")
	req3.Header.Set("Cache-Control", "no-cache")
	rec3 := httptest.NewRecorder()
	proxy.routes().ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on bypass call, got %d", rec3.Code)
	}
	if callCount != 2 {
		t.Errorf("expected upstream to be called again when bypassing cache, got callCount=%d", callCount)
	}
}

func TestAdminCacheEndpoints(t *testing.T) {
	proxy := multiUpstreamProxy(t, "https://agentrouter.org")
	proxy.cfg.AdminToken = "multi-upstream-test-secret"
	proxy.cfg.AdminAccounts = []adminAccount{{Name: "owner", Token: "multi-upstream-test-secret", Role: "admin"}}

	// Pre-fill cache
	proxy.cache.set(context.Background(), "test-key-1", []byte("resp1"), time.Hour)

	// GET /api/admin/cache
	getReq := httptest.NewRequest(http.MethodGet, "/api/admin/cache", nil)
	getReq.Header.Set("X-Admin-Token", "multi-upstream-test-secret")
	getRec := httptest.NewRecorder()
	proxy.routes().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/admin/cache, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var stats map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", stats["enabled"])
	}
	if stats["items"] != float64(1) {
		t.Errorf("expected 1 item in cache, got %v", stats["items"])
	}

	// DELETE /api/admin/cache
	delReq := httptest.NewRequest(http.MethodDelete, "/api/admin/cache", nil)
	delReq.Header.Set("X-Admin-Token", "multi-upstream-test-secret")
	delRec := httptest.NewRecorder()
	proxy.routes().ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for DELETE /api/admin/cache, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// Verify items is now 0
	getRec2 := httptest.NewRecorder()
	proxy.routes().ServeHTTP(getRec2, getReq)
	var statsAfter map[string]any
	_ = json.Unmarshal(getRec2.Body.Bytes(), &statsAfter)
	if statsAfter["items"] != float64(0) {
		t.Errorf("expected 0 items in cache after clear, got %v", statsAfter["items"])
	}
}
