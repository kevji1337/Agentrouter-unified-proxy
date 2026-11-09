package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func logForRequest(t *testing.T, id, event string) map[string]any {
	t.Helper()
	entries := adminLogRing.recent(0, 200)
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry["request_id"] == id && entry["message"] == event {
			return entry
		}
	}
	t.Fatalf("missing %s for request %s", event, id)
	return nil
}

func TestRequestLogSelectedRouteWithoutSecrets(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, nativeChatResponse) }))
	defer upstream.Close()
	gateway := multiUpstreamProxy(t, upstream.URL)
	p := createProvider(t, gateway.keys, "Readable provider", upstream.URL, protocolChatCompletions, "m")
	key := addProviderKey(t, gateway, "Primary", "sk-secret-private-provider", p.ID, 0)
	id := "readable-route-test"
	req := httptest.NewRequest("POST", "/v1/chat/completions?credential=private-query", strings.NewReader(nativeChatRequest))
	req.Header.Set("X-Request-ID", id)
	req.Header.Set("X-Api-Key", "private-client-credential")
	rec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	entry := logForRequest(t, id, "request_completed")
	for name, want := range map[string]any{"provider": "Readable provider", "key_name": "Primary", "key_mask": key.Mask, "key_id": key.ID, "model": "m", "upstream_protocol": protocolChatCompletions, "attempts": 1, "level": "info", "input_tokens": uint64(3)} {
		if entry[name] != want {
			t.Errorf("%s=%v want %v", name, entry[name], want)
		}
	}
	if !strings.Contains(fmt.Sprint(entry["summary"]), "HTTP 200") || entry["category"] != "requests" {
		t.Fatal("missing readable summary")
	}
	raw, _ := json.Marshal(entry)
	for _, secret := range []string{"sk-secret-private-provider", "private-client-credential", "private-query", "messages", "hello"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("log leaked %s", secret)
		}
	}
}

func TestRequestLogFailoverShowsBothKeysAndFinalProvider(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, responsesReply) }))
	defer second.Close()
	gateway := multiUpstreamProxy(t, first.URL)
	a := createProvider(t, gateway.keys, "API A", first.URL, protocolChatCompletions, "m")
	b := createProvider(t, gateway.keys, "API B", second.URL, protocolResponses, "m")
	addProviderKey(t, gateway, "A key", "sk-failover-private-a", a.ID, 10)
	addProviderKey(t, gateway, "B key", "sk-failover-private-b", b.ID, 0)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(nativeChatRequest))
	req.Header.Set("X-Request-ID", "readable-failover-test")
	rec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(rec, req)
	change := logForRequest(t, "readable-failover-test", "api_key_failover")
	if change["failed_provider"] != "API A" || change["next_provider"] != "API B" || !strings.Contains(fmt.Sprint(change["summary"]), "A key") {
		t.Fatalf("failover details=%v", change)
	}
	final := logForRequest(t, "readable-failover-test", "request_completed")
	if final["provider"] != "API B" || final["key_name"] != "B key" || final["attempts"] != 2 {
		t.Fatalf("wrong final context %v", final)
	}
}

func TestRequestLogErrorsAndBackground(t *testing.T) {
	gateway := multiUpstreamProxy(t, "http://127.0.0.1:1")
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(nativeChatRequest))
	req.Header.Set("X-Request-ID", "readable-empty-pool")
	gateway.routes().ServeHTTP(httptest.NewRecorder(), req)
	entry := logForRequest(t, "readable-empty-pool", "request_completed")
	if entry["level"] != "error" || entry["error_code"] != "no_enabled_api_keys" {
		t.Fatal(entry)
	}
	addUpstream(t, gateway, "Unavailable", "", protocolChatCompletions, "sk-transport-private-key", 0)
	req = httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(nativeChatRequest))
	req.Header.Set("X-Request-ID", "readable-connection-failed")
	gateway.routes().ServeHTTP(httptest.NewRecorder(), req)
	entry = logForRequest(t, "readable-connection-failed", "request_completed")
	if entry["error_code"] != "connection_error" {
		t.Fatalf("generic error erased diagnosis: %v", entry)
	}
	if !logIsBackground("tool_call_emitted", map[string]any{"level": "info"}) || !logIsBackground("request_completed", map[string]any{"method": "GET", "path": "/api/admin/status", "level": "info"}) {
		t.Fatal("background classification")
	}
	if logIsBackground("request_completed", map[string]any{"path": "/v1/models", "level": "error"}) || logIsBackground("parallel_tools_suppressed", map[string]any{"level": "warn"}) {
		t.Fatal("important warning hidden")
	}
}

type brokenLogBody struct{}

func (brokenLogBody) Read([]byte) (int, error) { return 0, errUpstreamIdleTimeout }
func (brokenLogBody) Close() error             { return nil }
func TestRequestLogInterruptedResponse(t *testing.T) {
	record := &requestLog{fields: map[string]any{}}
	ctx := context.WithValue(context.Background(), requestLogContextKey{}, record)
	ctx = context.WithValue(ctx, requestIDContextKey{}, "readable-interrupted-test")
	body := &loggedResponseBody{ReadCloser: brokenLogBody{}, ctx: ctx}
	_, _ = body.Read(make([]byte, 8))
	_, _ = body.Read(make([]byte, 8))
	fields := record.snapshot()
	if fields["error_code"] != "upstream_idle_timeout" || fields["response_interrupted"] != true || requestLogLevel(200, fields) != "warn" {
		t.Fatal(fields)
	}
	record.responseError("upstream_error")
	if record.snapshot()["error_code"] != "upstream_idle_timeout" {
		t.Fatal("diagnosis lost")
	}
}

func TestRequestFailureCodeNeverIncludesTransportURL(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "http://user:private-password@host/?token=secret", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private error")}}
	if code := requestFailureCode(err); code != "connection_error" {
		t.Fatal(code)
	}
	if requestFailureCode(context.Canceled) != "request_canceled" || requestFailureCode(context.DeadlineExceeded) != "upstream_timeout" {
		t.Fatal("context diagnosis")
	}
}

func TestLogPageLatestCursorAndProcessRestart(t *testing.T) {
	ring := &logRing{}
	for i := 0; i < 250; i++ {
		ring.add(map[string]any{"message": "test"})
	}
	page := ring.page(0, 100)
	if len(page.Data) != 100 || page.Data[0]["seq"] != uint64(151) || page.NextAfter != 250 || page.Instance == "" {
		t.Fatalf("latest page %+v", page)
	}
	page = ring.page(10, 100)
	if len(page.Data) != 100 || !page.HasMore || page.NextAfter != 110 {
		t.Fatalf("incremental page %+v", page)
	}
	page = ring.page(999, 100)
	if !page.Reset || page.NextAfter != 250 {
		t.Fatal("restart cursor stuck")
	}
	ring2 := &logRing{}
	if ring2.page(0, 100).Instance == page.Instance {
		t.Fatal("process generations not distinct")
	}
	page.Data[0]["message"] = "mutated"
	if ring.page(0, 100).Data[0]["message"] == "mutated" {
		t.Fatal("caller mutates log ring")
	}
}

func TestRequestLogConcurrentUpdates(t *testing.T) {
	record := &requestLog{fields: map[string]any{}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 50; n++ {
				record.attempt(map[string]any{"model": "m"})
				_ = record.snapshot()
			}
		}()
	}
	wg.Wait()
	if record.snapshot()["attempts"] != 400 {
		t.Fatal("lost attempts")
	}
}

func TestCredentialEditPreservesBindingsAndEncryptsReplacement(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "Provider", "https://api.example", protocolResponses, "m")
	key := addProviderKey(t, gateway, "Original", "sk-original-private-key", p.ID, 8)
	gateway.keys.recordUsage(key.ID, 10, 5)
	gateway.keys.recordResult(key.ID, 401, "Unauthorized", time.Hour)
	name, enabled, replacement := "Renamed", false, "sk-replaced-private-key"
	view, err := gateway.keys.updateCredential(key.ID, &name, &enabled, &replacement)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := gateway.keys.byID(key.ID)
	if err != nil || selected.Key != replacement || view.ProviderID != p.ID || view.Priority != 8 || view.InputTokens != 10 || view.Enabled || view.CooldownUntil != nil {
		t.Fatal("edit lost settings")
	}
	backup, _ := gateway.keys.exportBackup()
	if strings.Contains(string(backup), replacement) {
		t.Fatal("replacement stored plaintext")
	}
	empty := ""
	_, err = gateway.keys.updateCredential(key.ID, nil, nil, &empty)
	if err != nil {
		t.Fatal(err)
	}
	selected, _ = gateway.keys.byID(key.ID)
	if selected.Key != replacement {
		t.Fatal("empty edit erased credential")
	}
	bad := "tiny"
	name = "Should not apply"
	if _, err := gateway.keys.updateCredential(key.ID, &name, nil, &bad); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	selected, _ = gateway.keys.byID(key.ID)
	if selected.Name != "Renamed" || selected.Key != replacement {
		t.Fatal("failed validation partially edited key")
	}
}

func TestCredentialEditAdminRBACAndSecretSafeResponse(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	view := addUpstream(t, gateway, "Original", "", protocolResponses, "sk-old-admin-private", 0)
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "admin", Role: "admin", Token: "editing-admin-token"}, {Name: "viewer", Role: "viewer", Token: "editing-viewer-token"}}
	send := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PATCH", "/api/admin/keys/"+view.ID, strings.NewReader(`{"name":"Changed","key":"sk-new-admin-private"}`))
		req.Header.Set("X-Admin-Token", token)
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, req)
		return rec
	}
	if send("editing-viewer-token").Code != 403 {
		t.Fatal("viewer replaced credential")
	}
	rec := send("editing-admin-token")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "sk-new-admin-private") {
		t.Fatal("secret in response")
	}
	records, _ := json.Marshal(adminLogRing.recent(0, 200))
	if strings.Contains(string(records), "sk-new-admin-private") {
		t.Fatal("secret in logs")
	}
	selected, _ := gateway.keys.byID(view.ID)
	if selected.Key != "sk-new-admin-private" {
		t.Fatal("replacement not saved")
	}
}
