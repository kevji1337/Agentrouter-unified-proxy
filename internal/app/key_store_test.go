package app

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
	"time"
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
	store.recordResult(first.ID, http.StatusTooManyRequests, "rate limited", time.Hour)
	selectedAfterCooldown, err := store.selectNext(nil)
	if err != nil || selectedAfterCooldown.ID != second.ID {
		t.Fatalf("cooling key was selected: %#v err=%v", selectedAfterCooldown, err)
	}
	viewsAfterCooldown, _ := store.list()
	if viewsAfterCooldown[0].CooldownUntil == nil {
		t.Fatal("cooldown was not exposed in key view")
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
	if err := store.saveSelectionMode("pool-only"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.selectNext(nil); !errors.Is(err, errNoEnabledAPIKeys) {
		t.Fatalf("selection after delete error = %v", err)
	}

	reloaded := newAPIKeyStore(path, "test-encryption-secret")
	views, err := reloaded.list()
	if err != nil || len(views) != 1 || views[0].ID != first.ID || views[0].Enabled || reloaded.savedSelectionMode() != "pool-only" {
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

func TestAdminCanChangeRoutingModeAtRuntime(t *testing.T) {
	parsed, _ := url.Parse("http://127.0.0.1:1")
	proxy := newProxyServer(config{
		UpstreamURL: parsed, Profile: "claude-code", AdminToken: "admin-secret",
		KeyStoreSecret: "store-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"),
		KeySelectionMode: "inbound-first",
	})
	request := httptest.NewRequest(http.MethodPatch, "/api/admin/settings", strings.NewReader(`{"selection_mode":"pool-only"}`))
	request.Header.Set("X-Admin-Token", "admin-secret")
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || proxy.currentKeySelectionMode() != "pool-only" {
		t.Fatalf("status=%d mode=%s body=%s", recorder.Code, proxy.currentKeySelectionMode(), recorder.Body.String())
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

func TestKeyPolicyPriorityModelLimitsAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "policy-secret")
	low, err := store.addWithPolicy("Low", "sk-low-policy-key", true, apiKeyPolicy{Priority: 1, Weight: 1, Models: []string{"model-a"}})
	if err != nil {
		t.Fatal(err)
	}
	high, err := store.addWithPolicy("High", "sk-high-policy-key", true, apiKeyPolicy{Priority: 10, Weight: 2, Models: []string{"model-b"}, DailyRequestLimit: 1, MonthlyBudgetUSD: 1, InputCostPerMillion: 2, OutputCostPerMillion: 4})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := store.selectNextForModel(nil, "model-b")
	if err != nil || selected.ID != high.ID {
		t.Fatalf("high-priority model key = %#v err=%v", selected, err)
	}
	// Daily limit removes the high-priority key; model-a can still use Low.
	selected, err = store.selectNextForModel(nil, "model-a")
	if err != nil || selected.ID != low.ID {
		t.Fatalf("model allowlist selection = %#v err=%v", selected, err)
	}
	if _, err := store.selectNextForModel(nil, "model-b"); !errors.Is(err, errNoEnabledAPIKeys) {
		t.Fatalf("daily request limit was not enforced: %v", err)
	}
	store.recordUsage(high.ID, 1000, 500)
	views, _ := store.list()
	var highView apiKeyView
	for _, view := range views {
		if view.ID == high.ID {
			highView = view
		}
	}
	if highView.InputTokens != 1000 || highView.OutputTokens != 500 || highView.MonthlySpendUSD <= 0 {
		t.Fatalf("usage/cost accounting failed: %#v", highView)
	}

	backup, err := store.exportBackup()
	if err != nil {
		t.Fatal(err)
	}
	restored := newAPIKeyStore(filepath.Join(t.TempDir(), "restored.json"), "policy-secret")
	if err := restored.importBackup(backup); err != nil {
		t.Fatal(err)
	}
	restoredViews, _ := restored.list()
	if len(restoredViews) != 2 {
		t.Fatalf("restored key count = %d", len(restoredViews))
	}
	wrongSecret := newAPIKeyStore(filepath.Join(t.TempDir(), "wrong.json"), "wrong-secret")
	if err := wrongSecret.importBackup(backup); err == nil {
		t.Fatal("backup imported with the wrong encryption secret")
	}
}

func TestTOTPAndViewerRole(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if !validTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("valid RFC TOTP code was rejected")
	}
	accounts, err := parseAdminAccounts(`[{"name":"auditor","token":"viewer-token-123456","role":"viewer","totp_secret":"`+secret+`"}]`, "")
	if err != nil || len(accounts) != 1 || accounts[0].Role != "viewer" {
		t.Fatalf("accounts=%#v err=%v", accounts, err)
	}
}

func TestAdminSessionEnforcesViewerRole(t *testing.T) {
	parsed, _ := url.Parse("http://127.0.0.1:1")
	proxy := newProxyServer(config{
		UpstreamURL: parsed, Profile: "claude-code",
		AdminAccounts:  []adminAccount{{Name: "auditor", Token: "viewer-token-123456", Role: "viewer"}},
		KeyStoreSecret: "store-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"),
	})
	login := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"token":"viewer-token-123456","totp":""}`))
	loginRecorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(loginRecorder, login)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRecorder.Code, loginRecorder.Body.String())
	}
	var loginResponse struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &loginResponse); err != nil || loginResponse.Session == "" {
		t.Fatalf("login response=%s err=%v", loginRecorder.Body.String(), err)
	}
	mutation := httptest.NewRequest(http.MethodPatch, "/api/admin/settings", strings.NewReader(`{"selection_mode":"pool-only"}`))
	mutation.Header.Set("X-Admin-Session", loginResponse.Session)
	mutationRecorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(mutationRecorder, mutation)
	if mutationRecorder.Code != http.StatusForbidden {
		t.Fatalf("viewer mutation status=%d body=%s", mutationRecorder.Code, mutationRecorder.Body.String())
	}
}

func TestClientAPIKeysAreEncryptedAndAuthenticate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "client-key-secret")
	view, plain, err := store.createClientKey("Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "arp_") || view.Mask == plain {
		t.Fatalf("generated client key is invalid: view=%#v", view)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte(plain)) {
		t.Fatal("client key was stored in plaintext")
	}
	if id, ok := store.authenticateClientKey(plain); !ok || id != view.ID {
		t.Fatalf("client key authentication failed: id=%s ok=%v", id, ok)
	}
	revealed, err := store.revealClientKey(view.ID)
	if err != nil || revealed != plain {
		t.Fatalf("reveal=%q err=%v", revealed, err)
	}
	disabled := false
	if _, err := store.updateClientKey(view.ID, &disabled, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.authenticateClientKey(plain); ok {
		t.Fatal("disabled client key authenticated")
	}
}

func TestClientBearerKeyUsesStoredUpstreamKey(t *testing.T) {
	seenAuth := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer upstream.Close()
	parsed, _ := url.Parse(upstream.URL)
	proxy := newProxyServer(config{
		UpstreamURL: parsed, Profile: "claude-code", KeySelectionMode: "pool-first",
		KeyStoreSecret: "client-routing-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json"),
	})
	if _, err := proxy.keys.add("Upstream", "sk-upstream-secret", true); err != nil {
		t.Fatal(err)
	}
	_, clientToken, err := proxy.keys.createClientKey("IDE")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer "+clientToken)
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if auth := <-seenAuth; auth != "Bearer sk-upstream-secret" {
		t.Fatalf("upstream received %q", auth)
	}

	invalid := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	invalid.Header.Set("Authorization", "Bearer arp_invalid")
	invalidRecorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(invalidRecorder, invalid)
	if invalidRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid client key status=%d", invalidRecorder.Code)
	}
}

func TestPerKeyUpstreamEndpoint(t *testing.T) {
	defaultCalls := atomic.Int32{}
	defaultUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defaultCalls.Add(1); w.WriteHeader(500) }))
	defer defaultUpstream.Close()
	customCalls := atomic.Int32{}
	customUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer sk-custom-upstream" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer customUpstream.Close()
	parsed, _ := url.Parse(defaultUpstream.URL)
	proxy := newProxyServer(config{UpstreamURL: parsed, Profile: "claude-code", KeySelectionMode: "pool-only", KeyStoreSecret: "custom-endpoint-secret", KeyStorePath: filepath.Join(t.TempDir(), "keys.json")})
	if _, err := proxy.keys.addWithPolicy("Custom", "sk-custom-upstream", true, apiKeyPolicy{Weight: 1, BaseURL: customUpstream.URL, SpoofProfile: "generic"}); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	proxy.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if recorder.Code != http.StatusOK || customCalls.Load() != 1 || defaultCalls.Load() != 0 {
		t.Fatalf("status=%d custom=%d default=%d", recorder.Code, customCalls.Load(), defaultCalls.Load())
	}
}
