package agentrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRequestModesAndErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer arp_test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/models":
			if r.Method != http.MethodGet || r.Header.Get("Content-Type") != "" {
				t.Errorf("unexpected GET method/headers: %s %v", r.Method, r.Header)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"object": "list"})
		case "/v1/chat/completions":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("missing JSON Content-Type on POST")
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["model"] != "gpt-4o" {
				t.Errorf("invalid POST payload: %v %v", err, payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "chatcmpl-1"})
		case "/v1/noop":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer server.Close()

	client := New(server.URL+"/", "arp_test_token")
	var models map[string]any
	if err := client.Request(context.Background(), http.MethodGet, "/v1/models", nil, &models); err != nil || models["object"] != "list" {
		t.Fatalf("GET /v1/models failed: %v %v", err, models)
	}
	var chat map[string]any
	if err := client.Request(context.Background(), http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-4o"}, &chat); err != nil || chat["id"] != "chatcmpl-1" {
		t.Fatalf("POST /v1/chat/completions failed: %v %v", err, chat)
	}
	if err := client.Request(context.Background(), http.MethodPost, "/v1/noop", nil, nil); err != nil {
		t.Fatalf("nil output failed: %v", err)
	}
	if err := client.Request(context.Background(), http.MethodGet, "/v1/fail", nil, &models); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("expected HTTP 502 error, got %v", err)
	}
}
