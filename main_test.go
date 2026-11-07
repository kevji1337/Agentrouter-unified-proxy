package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (r *flushRecorder) Flush() {
	r.flushes++
	r.ResponseRecorder.Flush()
}

func TestCookieWarmupAndSpoofedChatProxy(t *testing.T) {
	type seenRequest struct {
		Authorization string
		Cookie        string
		UserAgent     string
		Anthropic     string
		Path          string
		Body          map[string]any
	}
	seen := make(chan seenRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Add("Set-Cookie", "acw_tc=test-cookie; Path=/; HttpOnly")
			w.WriteHeader(http.StatusOK)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen <- seenRequest{
			Authorization: r.Header.Get("Authorization"), Cookie: r.Header.Get("Cookie"),
			UserAgent: r.Header.Get("User-Agent"), Anthropic: r.Header.Get("Anthropic-Version"),
			Path: r.URL.Path, Body: body,
		}
		w.Header().Add("Set-Cookie", "cdn_sec_tc=rotated; Path=/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_x","created_at":1,"status":"completed","model":"m","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{UpstreamURL: parsed, Port: 8080, Profile: "claude-code"})
	if !proxy.cookies.warmup(context.Background(), parsed) {
		t.Fatal("warmup did not capture cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(
		`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Authorization", "Bearer exact-key")
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	request := <-seen
	if request.Authorization != "Bearer exact-key" {
		t.Fatalf("authorization = %q", request.Authorization)
	}
	if !strings.Contains(request.Cookie, "acw_tc=test-cookie") {
		t.Fatalf("cookie = %q", request.Cookie)
	}
	if !strings.HasPrefix(request.UserAgent, "claude-cli/") || request.Anthropic != "2023-06-01" {
		t.Fatalf("spoof headers missing: UA=%q anthropic=%q", request.UserAgent, request.Anthropic)
	}
	if request.Path != "/v1/responses" || request.Body["input"] == nil {
		t.Fatalf("bad upstream request: path=%s body=%#v", request.Path, request.Body)
	}
	if !strings.Contains(recorder.Body.String(), `"object":"chat.completion"`) ||
		!strings.Contains(recorder.Body.String(), `"content":"ok"`) {
		t.Fatalf("bad converted response: %s", recorder.Body.String())
	}
	if !strings.Contains(proxy.cookies.header(), "cdn_sec_tc=rotated") {
		t.Fatalf("rotated cookie not captured: %q", proxy.cookies.header())
	}
}

func TestResponsesRoutePassesBodyThrough(t *testing.T) {
	requestBody := `{"model":"m","input":"hello","stream":false,"custom":{"keep":true}}`
	seenBody := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/responses" {
			var buffer bytes.Buffer
			_, _ = buffer.ReadFrom(r.Body)
			seenBody <- buffer.String()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_direct","object":"response"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{UpstreamURL: parsed, Port: 8080, Profile: "codex"})

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(requestBody))
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := <-seenBody; got != requestBody {
		t.Fatalf("body changed:\ngot  %s\nwant %s", got, requestBody)
	}
	if recorder.Body.String() != `{"id":"resp_direct","object":"response"}` {
		t.Fatalf("response changed: %s", recorder.Body.String())
	}
}

func TestWafBlockRefreshesCookieAndRetriesOnce(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Add("Set-Cookie", "acw_tc=refreshed; Path=/")
			w.WriteHeader(http.StatusOK)
			return
		}
		attempt := calls.Add(1)
		if attempt == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<html><script src="waf.js"></script></html>`))
			return
		}
		if !strings.Contains(r.Header.Get("Cookie"), "acw_tc=refreshed") {
			t.Errorf("retry cookie = %q", r.Header.Get("Cookie"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_retry","created_at":1,"status":"completed","model":"m","output":[]}`))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{UpstreamURL: parsed, Port: 8080, Profile: "claude-code"})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(
		`{"model":"m","messages":[{"role":"user","content":"hello"}]}`))
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2", calls.Load())
	}
}
