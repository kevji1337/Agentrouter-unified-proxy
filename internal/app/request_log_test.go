package app

import (
	"bufio"
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

func waitForRequestLog(t *testing.T, id, event string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries := adminLogRing.recent(0, 200)
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i]["request_id"] == id && entries[i]["message"] == event {
				return entries[i]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s for request %s", event, id)
	return nil
}

func hasLogForRequest(id, event string) bool {
	entries := adminLogRing.recent(0, 200)
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i]["request_id"] == id && entries[i]["message"] == event {
			return true
		}
	}
	return false
}

func TestSSEClientClosesAfterDoneNotLoggedAsInterrupted(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":8}}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
		// Keep the upstream connection open after [DONE], matching OneAPI/NewAPI keep-alive tails.
		select {
		case <-r.Context().Done():
		case <-upstreamDone:
		}
	}))
	defer func() {
		close(upstreamDone)
		upstream.Close()
	}()

	gateway := multiUpstreamProxy(t, upstream.URL)
	p := createProvider(t, gateway.keys, "SSE Provider", upstream.URL, protocolChatCompletions, "m")
	key := addProviderKey(t, gateway, "SSE Key", "sk-sse-done-private-key", p.ID, 0)

	proxyHTTP := httptest.NewServer(gateway.routes())
	defer proxyHTTP.Close()

	reqID := "sse-close-after-done-test"
	req, err := http.NewRequest(http.MethodPost, proxyHTTP.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", reqID)

	resp, err := proxyHTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	// Read until "data: [DONE]" like OpenAI SDKs do, then immediately close the socket.
	scanner := bufio.NewScanner(resp.Body)
	sawDone := false
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "data: [DONE]" {
			sawDone = true
			break
		}
	}
	_ = resp.Body.Close()
	if !sawDone {
		t.Fatal("client did not receive data: [DONE]")
	}

	completed := waitForRequestLog(t, reqID, "request_completed", 3*time.Second)
	if hasLogForRequest(reqID, "upstream_response_interrupted") {
		t.Fatalf("false positive upstream_response_interrupted logged after [DONE]")
	}
	if completed["level"] != "info" {
		t.Fatalf("expected level=info, got %v (fields=%v)", completed["level"], completed)
	}
	if completed["response_interrupted"] != nil {
		t.Fatalf("expected response_interrupted unset, got %v", completed["response_interrupted"])
	}
	if completed["error_code"] != nil && completed["error_code"] != "" {
		t.Fatalf("expected error_code unset, got %v", completed["error_code"])
	}
	if completed["input_tokens"] != uint64(12) || completed["output_tokens"] != uint64(8) {
		t.Fatalf("expected usage finalized (12/8), got in=%v out=%v", completed["input_tokens"], completed["output_tokens"])
	}
	views, err := gateway.keys.list()
	if err != nil || len(views) != 1 || views[0].ID != key.ID || views[0].InputTokens != 12 || views[0].OutputTokens != 8 {
		t.Fatalf("expected key usage persisted (12/8), got %+v err=%v", views, err)
	}
}

func TestSSEClientCancelsBeforeDoneStillLoggedAsInterrupted(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-mid\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n")
		flusher.Flush()
		select {
		case <-r.Context().Done():
		case <-upstreamDone:
		}
	}))
	defer func() {
		close(upstreamDone)
		upstream.Close()
	}()

	gateway := multiUpstreamProxy(t, upstream.URL)
	p := createProvider(t, gateway.keys, "SSE Provider", upstream.URL, protocolChatCompletions, "m")
	addProviderKey(t, gateway, "SSE Key", "sk-sse-mid-cancel-key", p.ID, 0)

	proxyHTTP := httptest.NewServer(gateway.routes())
	defer proxyHTTP.Close()

	reqID := "sse-cancel-before-done-test"
	req, err := http.NewRequest(http.MethodPost, proxyHTTP.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", reqID)

	resp, err := proxyHTTP.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "partial") {
		_ = resp.Body.Close()
		t.Fatal("did not receive partial SSE chunk")
	}
	// Disconnect mid-stream before any terminal marker arrives.
	_ = resp.Body.Close()

	completed := waitForRequestLog(t, reqID, "request_completed", 3*time.Second)
	if completed["level"] != "warn" {
		t.Fatalf("expected level=warn for mid-stream cancel, got %v (fields=%v)", completed["level"], completed)
	}
	if completed["response_interrupted"] != true {
		t.Fatalf("expected response_interrupted=true, got %v", completed["response_interrupted"])
	}
	if completed["error_code"] != "request_canceled" && completed["error_code"] != "client_write_failed" {
		t.Fatalf("expected request_canceled/client_write_failed, got %v", completed["error_code"])
	}
	if completed["error_code"] == "request_canceled" && !hasLogForRequest(reqID, "upstream_response_interrupted") {
		t.Fatal("expected upstream_response_interrupted event for mid-stream cancel")
	}
}

type failingAfterFirstWriteWriter struct {
	header http.Header
	writes int
}

func (w *failingAfterFirstWriteWriter) Header() http.Header { return w.header }
func (w *failingAfterFirstWriteWriter) WriteHeader(int)     {}
func (w *failingAfterFirstWriteWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(p), nil
	}
	return 0, errors.New("broken pipe")
}

func TestSSETerminalTrackerAndStatusWriterPostDoneWriteFailure(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
		want   bool
	}{
		{name: "chat_done_split", chunks: []string{"data: {\"ok\":true}\n\ndata: [DO", "NE]\n\n"}, want: true},
		{name: "chat_done_no_space_crlf", chunks: []string{"data:[DONE]\r\n\r\n"}, want: true},
		{name: "anthropic_event", chunks: []string{"event: message_stop\n"}, want: true},
		{name: "anthropic_json_split", chunks: []string{"data: {\"type\":\"messa", "ge_stop\"}\n\n"}, want: true},
		{name: "responses_event", chunks: []string{"event: response.completed\n"}, want: true},
		{name: "responses_long_json", chunks: []string{"data: {\"pad\":\"" + strings.Repeat("a", 2048) + "\",\"type\": \"response.completed\"}\n\n"}, want: true},
		{name: "model_text_mentioning_done", chunks: []string{"data: {\"choices\":[{\"delta\":{\"content\":\"send data: [DONE]\\n\\n\"}}]}\n\n"}, want: false},
		{name: "responses_failed", chunks: []string{"event: response.failed\ndata: {\"type\":\"response.failed\"}\n\n"}, want: false},
		{name: "responses_incomplete", chunks: []string{"event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n"}, want: false},
	}
	for _, tc := range cases {
		var tr sseTerminalTracker
		for _, ch := range tc.chunks {
			tr.observe([]byte(ch))
		}
		if tr.completed != tc.want {
			t.Errorf("%s: completed=%v want %v", tc.name, tr.completed, tc.want)
		}
	}

	// StatusWriter: write failure AFTER delivering data: [DONE] must not mark response_interrupted.
	recPostDone := &requestLog{fields: map[string]any{}}
	fw1 := &failingAfterFirstWriteWriter{header: http.Header{"Content-Type": []string{"text/event-stream"}}}
	sw1 := &statusWriter{ResponseWriter: fw1, log: recPostDone}
	if _, err := sw1.Write([]byte("data: [DONE]\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := sw1.Write([]byte("\n")); err == nil {
		t.Fatal("expected second write error")
	}
	if snap := recPostDone.snapshot(); snap["response_interrupted"] != nil || snap["error_code"] != nil {
		t.Fatalf("post-DONE write error wrongly marked interrupted: %v", snap)
	}

	// StatusWriter: write failure BEFORE [DONE] must still mark client_write_failed + response_interrupted.
	recMid := &requestLog{fields: map[string]any{}}
	fw2 := &failingAfterFirstWriteWriter{header: http.Header{"Content-Type": []string{"text/event-stream"}}}
	sw2 := &statusWriter{ResponseWriter: fw2, log: recMid}
	if _, err := sw2.Write([]byte("data: {\"delta\":\"hi\"}\n\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := sw2.Write([]byte("data: {\"delta\":\"more\"}\n\n")); err == nil {
		t.Fatal("expected second write error")
	}
	if snap := recMid.snapshot(); snap["response_interrupted"] != true || snap["error_code"] != "client_write_failed" {
		t.Fatalf("mid-stream write error not logged as interrupted: %v", snap)
	}
}
