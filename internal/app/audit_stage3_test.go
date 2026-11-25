package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInfrastructureInvalidTelegramTokenDoesNotPanicAndClosesCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Control characters in token make http.NewRequestWithContext fail; must not panic.
	infra, err := newInfrastructure(ctx, config{
		TelegramBotToken: "bad\x7f\n-token",
		TelegramChatID:   "12345",
		AlertCooldown:    0,
	})
	if err != nil {
		t.Fatalf("newInfrastructure failed: %v", err)
	}
	logEvent("error", "no_available_api_keys", map[string]any{"model": "gpt-4o"})
	// Close waits for eventWorker to drain queued events without panicking.
	infra.Close()
	// Idempotent second Close.
	infra.Close()
}

func TestMetricsWafCookieReflectsManagedProxyPoolAndHealthSanitizesErrors(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	id := addNetworkProxy(t, gateway.keys, "Route1", "http://127.0.0.1:19999")
	p, err := gateway.keys.networkProxyByID(id)
	if err != nil {
		t.Fatal(err)
	}
	route, err := gateway.outboundRoute(&selectedAPIKey{NetworkProxy: p})
	if err != nil {
		t.Fatal(err)
	}
	route.cookies.capture(http.Header{"Set-Cookie": {"acw_tc=proxy-route-cookie; Path=/"}})

	recMetrics := httptest.NewRecorder()
	gateway.routes().ServeHTTP(recMetrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recMetrics.Code != http.StatusOK || !strings.Contains(recMetrics.Body.String(), "agentrouter_proxy_waf_cookie_present 1") {
		t.Fatalf("expected waf_cookie_present 1 in /metrics, got:\n%s", recMetrics.Body.String())
	}

	// Corrupt key store file and verify public /health does not leak filesystem path.
	corruptDir := t.TempDir()
	corruptPath := filepath.Join(corruptDir, "secret_internal_dir_keys.json")
	if err := os.WriteFile(corruptPath, []byte("not-valid-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	brokenGateway := newProxyServer(config{
		UpstreamURL:    gateway.cfg.UpstreamURL,
		Profile:        "generic",
		KeyStorePath:   corruptPath,
		KeyStoreSecret: "secret-1234567890",
	})
	recHealth := httptest.NewRecorder()
	brokenGateway.routes().ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("health status=%d", recHealth.Code)
	}
	if strings.Contains(recHealth.Body.String(), "secret_internal_dir_keys.json") || strings.Contains(recHealth.Body.String(), "decode key store") {
		t.Fatalf("public /health leaked internal load error details: %s", recHealth.Body.String())
	}

	// Verify security headers on /docs and /openapi.json.
	recDocs := httptest.NewRecorder()
	gateway.routes().ServeHTTP(recDocs, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if recDocs.Header().Get("X-Frame-Options") != "DENY" || recDocs.Header().Get("X-Content-Type-Options") != "nosniff" || recDocs.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("missing security headers on /docs: %v", recDocs.Header())
	}
	var spec map[string]any
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("embedded openapi.json is invalid JSON: %v", err)
	}
}

func TestParallelKeyProbeBatchBoundsConcurrency(t *testing.T) {
	var inFlight, maxObserved atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			prev := maxObserved.Load()
			if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		inFlight.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer upstream.Close()

	gateway := multiUpstreamProxy(t, upstream.URL)
	for i := 0; i < 10; i++ {
		addUpstream(t, gateway, "Key-"+string(rune('A'+i)), upstream.URL, protocolChatCompletions, "sk-batch-probe-key", 0)
	}
	checked, accepted, failed, inconclusive := gateway.probeAllKeysWithStats(context.Background())
	if checked != 10 || accepted != 10 || failed != 0 || inconclusive != 0 {
		t.Fatalf("unexpected probe stats: checked=%d accepted=%d failed=%d inconclusive=%d", checked, accepted, failed, inconclusive)
	}
	if peak := maxObserved.Load(); peak < 2 || peak > maxConcurrentKeyProbes {
		t.Fatalf("expected bounded concurrency in [2..%d], observed peak=%d", maxConcurrentKeyProbes, peak)
	}

	// Verify mid-batch context cancellation while semaphore is saturated returns promptly without deadlocking.
	cancelCtx, cancel := context.WithCancel(context.Background())
	slowStarted := make(chan struct{})
	var startedOnce atomic.Bool
	slowUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if startedOnce.CompareAndSwap(false, true) {
			close(slowStarted)
		}
		<-r.Context().Done()
	}))
	defer slowUpstream.Close()

	gateway2 := multiUpstreamProxy(t, slowUpstream.URL)
	for i := 0; i < 8; i++ {
		addUpstream(t, gateway2, "CancelKey-"+string(rune('A'+i)), slowUpstream.URL, protocolChatCompletions, "sk-cancel-probe-key", 0)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		gateway2.probeAllKeysWithStats(cancelCtx)
	}()
	<-slowStarted
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("probeKeyBatch deadlocked on context cancellation")
	}
}

func TestBuiltInContainerHealthcheckCLI(t *testing.T) {
	if _, handled := maybeRunHealthcheck(nil); handled {
		t.Fatal("empty args must not trigger healthcheck")
	}
	if _, handled := maybeRunHealthcheck([]string{"-unknown"}); handled {
		t.Fatal("unrelated flag must not trigger healthcheck")
	}

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer healthy.Close()

	if code := probeHealthEndpoint(healthy.URL+"/health", time.Second); code != 0 {
		t.Fatalf("expected exit code 0 on 200 OK, got %d", code)
	}
	if code := probeHealthEndpoint(healthy.URL+"/missing", time.Second); code != 1 {
		t.Fatalf("expected exit code 1 on 404, got %d", code)
	}
	if code := probeHealthEndpoint("http://127.0.0.1:1/health", 200*time.Millisecond); code != 1 {
		t.Fatalf("expected exit code 1 on unreachable port, got %d", code)
	}

	t.Setenv("PORT", "invalid-port")
	if code, handled := maybeRunHealthcheck([]string{"-healthcheck"}); !handled || code != 1 {
		t.Fatalf("expected handled=true code=1 for invalid PORT, got handled=%v code=%d", handled, code)
	}
}
