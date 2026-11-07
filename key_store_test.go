package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAPIKeyStoreEncryptsAndManagesKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "test-encryption-secret")
	first, err := store.add("Primary", "sk-primary-secret-value", true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.add("Backup", "sk-backup-secret-value", true)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sk-primary-secret-value")) || bytes.Contains(raw, []byte("sk-backup-secret-value")) {
		t.Fatal("key store contains plaintext API key")
	}
	if first.Mask == "sk-primary-secret-value" || !strings.Contains(first.Mask, "••") {
		t.Fatalf("key was not masked: %q", first.Mask)
	}

	selected1, err := store.selectNext(nil)
	if err != nil || selected1.ID != first.ID || selected1.Key != "sk-primary-secret-value" {
		t.Fatalf("first selection = %#v err=%v", selected1, err)
	}
	selected2, err := store.selectNext(nil)
	if err != nil || selected2.ID != second.ID {
		t.Fatalf("second selection = %#v err=%v", selected2, err)
	}
	disabled := false
	if _, err := store.update(first.ID, nil, &disabled); err != nil {
		t.Fatal(err)
	}
	selected3, err := store.selectNext(nil)
	if err != nil || selected3.ID != second.ID {
		t.Fatalf("disabled key was selected: %#v err=%v", selected3, err)
	}
	if err := store.delete(second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.selectNext(nil); !errors.Is(err, errNoEnabledAPIKeys) {
		t.Fatalf("selection after delete error = %v", err)
	}

	reloaded := newAPIKeyStore(path, "test-encryption-secret")
	views, err := reloaded.list()
	if err != nil || len(views) != 1 || views[0].ID != first.ID || views[0].Enabled {
		t.Fatalf("reloaded views = %#v err=%v", views, err)
	}
	wrongSecret := newAPIKeyStore(path, "wrong-secret")
	if wrongSecret.loadErr == nil {
		t.Fatal("wrong encryption secret should fail to load")
	}
}

func TestAdminKeyAPI(t *testing.T) {
	parsed, _ := url.Parse("http://127.0.0.1:1")
	proxy := newProxyServer(config{
		UpstreamURL: parsed, Profile: "claude-code", AdminToken: "admin-secret",
		KeyStoreSecret: "store-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"),
	})
	body := `{"name":"Primary","key":"sk-super-secret-value","enabled":true}`
	request := httptest.NewRequest(http.MethodPost, "/api/admin/keys", strings.NewReader(body))
	request.Header.Set("X-Admin-Token", "admin-secret")
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "sk-super-secret-value") {
		t.Fatal("admin response exposed full API key")
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/admin/keys", nil)
	listRequest.Header.Set("X-Admin-Token", "admin-secret")
	listRecorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK || strings.Contains(listRecorder.Body.String(), "sk-super-secret-value") {
		t.Fatalf("list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var list struct {
		Data []apiKeyView `json:"data"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &list); err != nil || len(list.Data) != 1 {
		t.Fatalf("list decode=%v data=%#v", err, list.Data)
	}

	unauthorized := httptest.NewRecorder()
	proxy.routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/admin/keys", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
}

func TestPoolOnlyRoutingAndKeyFailover(t *testing.T) {
	var calls atomic.Int32
	seen := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seen <- auth
		calls.Add(1)
		if auth == "Bearer sk-failing-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid key"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{
		UpstreamURL: parsed, Profile: "claude-code", KeySelectionMode: "pool-only", KeyFailover: true,
		KeyStoreSecret: "store-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"),
	})
	if _, err := proxy.keys.add("Failing", "sk-failing-key", true); err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.keys.add("Working", "sk-working-key", true); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if recorder.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, calls.Load(), recorder.Body.String())
	}
	if first, second := <-seen, <-seen; first != "Bearer sk-failing-key" || second != "Bearer sk-working-key" {
		t.Fatalf("authorization sequence = %q, %q", first, second)
	}
}
