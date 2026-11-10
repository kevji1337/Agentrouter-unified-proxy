package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func adminBrowserRequest(gateway *proxyServer, method, path, body string, cookie *http.Cookie, csrf bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://gateway.example"+path, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf {
		req.Header.Set("X-Admin-CSRF", "1")
		req.Header.Set("Origin", "https://gateway.example")
	}
	rec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(rec, req)
	return rec
}

func browserLogin(t *testing.T, gateway *proxyServer, input string) *http.Cookie {
	t.Helper()
	rec := adminBrowserRequest(gateway, "POST", "/api/admin/login", input, nil, true)
	if rec.Code != 200 {
		t.Fatalf("browser login=%d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	if strings.Contains(rec.Body.String(), cookies[0].Value) || strings.Contains(rec.Body.String(), `"session"`) {
		t.Fatal("browser session leaked to JS")
	}
	return cookies[0]
}

func TestRememberedAdminLoginSurvivesRestartAndLogsOut(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	gateway.cfg.AdminToken = "remembered-admin-fixture-token"
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: gateway.cfg.AdminToken}}
	cookie := browserLogin(t, gateway, `{"token":"remembered-admin-fixture-token","new_password":"fixture-password-at-least-12","browser":true,"remember":true}`)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/admin" || cookie.MaxAge < 29*24*3600 {
		t.Fatalf("unsafe cookie %+v", cookie)
	}
	raw, err := os.ReadFile(gateway.cfg.KeyStorePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cookie.Value, "fixture-password-at-least-12", gateway.cfg.AdminToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("plaintext auth secret in store")
		}
	}
	reloaded := newProxyServer(gateway.cfg)
	rec := adminBrowserRequest(reloaded, "GET", "/api/admin/status", "", cookie, false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"password_set":true`) {
		t.Fatalf("lost browser session after reload %d %s", rec.Code, rec.Body.String())
	}
	login := browserLogin(t, reloaded, `{"name":"owner","password":"fixture-password-at-least-12","browser":true}`)
	if login.MaxAge != 0 || !login.Expires.IsZero() {
		t.Fatal("non-remembered login made persistent browser cookie")
	}
	rec = adminBrowserRequest(reloaded, "POST", "/api/admin/logout", "", cookie, true)
	if rec.Code != 204 || rec.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout failed")
	}
	if rec = adminBrowserRequest(newProxyServer(gateway.cfg), "GET", "/api/admin/status", "", cookie, false); rec.Code != 401 {
		t.Fatal("revoked cookie survived restart")
	}
}

func TestCookieAdminCSRFAndGatewayAuthIsolation(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "csrf-admin-fixture-token"}}
	gateway.cfg.ProxyAuthToken = "gateway-api-token"
	cookie := browserLogin(t, gateway, `{"token":"csrf-admin-fixture-token","browser":true}`)
	rec := adminBrowserRequest(gateway, "PATCH", "/api/admin/settings", `{"selection_mode":"pool-only"}`, cookie, false)
	if rec.Code != 403 {
		t.Fatal("cookie mutation without CSRF accepted")
	}
	req := httptest.NewRequest("PATCH", "https://gateway.example/api/admin/settings", strings.NewReader(`{"selection_mode":"pool-only"}`))
	req.AddCookie(cookie)
	req.Header.Set("X-Admin-CSRF", "1")
	req.Header.Set("Origin", "https://foreign.example")
	rec = httptest.NewRecorder()
	gateway.routes().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	rec = adminBrowserRequest(gateway, "PATCH", "/api/admin/settings", `{"selection_mode":"pool-only"}`, cookie, true)
	if rec.Code != 200 {
		t.Fatal("same-origin admin mutation rejected")
	}
	rec = adminBrowserRequest(gateway, "GET", "/v1/models", "", cookie, false)
	if rec.Code != 401 {
		t.Fatal("admin cookie authenticated LLM gateway")
	}
	rec = adminBrowserRequest(gateway, "POST", "/api/admin/login", `{"token":"csrf-admin-fixture-token","browser":true}`, nil, false)
	if rec.Code != 403 {
		t.Fatal("browser login allowed cross-site form")
	}
	rec = adminBrowserRequest(gateway, "POST", "/api/admin/login", `{"token":"csrf-admin-fixture-token","new_password":"csrf-test-password-long"}`, nil, false)
	if rec.Code != 403 {
		t.Fatal("password setup bypassed CSRF")
	}
}

func TestPasswordChangeReauthenticationRevokesOtherSessions(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "change-admin-fixture-token"}}
	a := browserLogin(t, gateway, `{"token":"change-admin-fixture-token","new_password":"fixture-old-password-long","browser":true}`)
	b := browserLogin(t, gateway, `{"name":"owner","password":"fixture-old-password-long","browser":true}`)
	rec := adminBrowserRequest(gateway, "POST", "/api/admin/password", `{"password":"fixture-new-password-long","current_password":"wrong-password"}`, a, true)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "admin_reauth_required") {
		t.Fatal("password change didn't require fresh auth")
	}
	if adminBrowserRequest(gateway, "GET", "/api/admin/status", "", a, false).Code != 200 {
		t.Fatal("bad reauth revoked current session")
	}
	rec = adminBrowserRequest(gateway, "POST", "/api/admin/password", `{"password":"fixture-new-password-long","current_password":"fixture-old-password-long"}`, a, true)
	if rec.Code != 200 {
		t.Fatalf("change %d %s", rec.Code, rec.Body.String())
	}
	replacement := rec.Result().Cookies()[0]
	for _, old := range []*http.Cookie{a, b} {
		if adminBrowserRequest(gateway, "GET", "/api/admin/status", "", old, false).Code != 401 {
			t.Fatal("old session not revoked")
		}
	}
	if adminBrowserRequest(gateway, "GET", "/api/admin/status", "", replacement, false).Code != 200 {
		t.Fatal("new session invalid")
	}
	if _, err := gateway.authenticateAdminCredentials("owner", "fixture-old-password-long", "", ""); err == nil {
		t.Fatal("old password still works")
	}
	if _, err := gateway.authenticateAdminCredentials("owner", "fixture-new-password-long", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestAdminPasswordAndSessionsRespectRBACAndAccountChanges(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "auditor", Role: "viewer", Token: "viewer-access-fixture-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	cookie := browserLogin(t, gateway, `{"token":"viewer-access-fixture-token","new_password":"viewer-fixture-password-long","browser":true}`)
	if adminBrowserRequest(gateway, "POST", "/api/admin/keys", `{}`, cookie, true).Code != 403 {
		t.Fatal("viewer escalated")
	}
	if adminBrowserRequest(gateway, "POST", "/api/admin/logout", "", cookie, true).Code != 204 {
		t.Fatal("viewer cannot log out")
	}
	cookie = browserLogin(t, gateway, `{"name":"auditor","password":"viewer-fixture-password-long","browser":true}`)
	gateway.cfg.AdminAccounts[0].Role = "admin"
	if adminBrowserRequest(gateway, "GET", "/api/admin/status", "", cookie, false).Code != 401 {
		t.Fatal("changed account retained stale session")
	}
	if _, err := gateway.authenticateAdminCredentials("auditor", "viewer-fixture-password-long", "", ""); err == nil {
		t.Fatal("changed account retained old password")
	}
}

func TestAdminPasswordTOTPAndLoginRateLimit(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "totp-access-fixture-token", TOTPSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	if err := gateway.keys.setAdminPassword(&account, "totp-fixture-password-long"); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.authenticateAdminCredentials("owner", "totp-fixture-password-long", "", ""); err == nil {
		t.Fatal("password bypassed TOTP")
	}
	// Verify the real KDF record and existing TOTP implementation independently.
	record, ok := gateway.keys.adminPassword(&account)
	if !ok || !passwordMatches("totp-fixture-password-long", record) {
		t.Fatal("password hashing invalid")
	}
	for i := 0; i < 10; i++ {
		rec := adminBrowserRequest(gateway, "POST", "/api/admin/login", `{"token":"wrong","browser":true}`, nil, true)
		if rec.Code != 401 {
			t.Fatalf("attempt %d = %d", i, rec.Code)
		}
	}
	rec := adminBrowserRequest(gateway, "POST", "/api/admin/login", `{"token":"wrong","browser":true}`, nil, true)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "60" {
		t.Fatal("login not throttled")
	}
}

func TestAdminAccessBackupExcludesSessionBearers(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "backup-access-fixture-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	cookie := browserLogin(t, gateway, `{"token":"backup-access-fixture-token","new_password":"backup-fixture-password-long","browser":true}`)
	raw, err := gateway.keys.exportBackup()
	if err != nil {
		t.Fatal(err)
	}
	var file persistedKeyFile
	if json.Unmarshal(raw, &file) != nil {
		t.Fatal("bad backup")
	}
	if len(file.AdminPasswords) != 1 || len(file.AdminSessions) != 0 || strings.Contains(string(raw), cookie.Value) {
		t.Fatal("backup contains live session")
	}
	restore := multiUpstreamProxy(t, "https://agentrouter.org")
	if err := restore.keys.importBackup(raw); err != nil {
		t.Fatal(err)
	}
	record, ok := restore.keys.adminPassword(&account)
	if !ok || !passwordMatches("backup-fixture-password-long", record) {
		t.Fatal("password backup lost")
	}
	if restore.keys.browserSessionAccount(cookie.Value, []adminAccount{account}) != nil {
		t.Fatal("backup restored live bearer")
	}
}

func TestBrowserCookieSecureDefaultsAndSessionExpiry(t *testing.T) {
	req := httptest.NewRequest("GET", "http://gateway.example/api/admin/status", nil)
	if !browserCookie(req, "id", time.Now().Add(time.Hour), true).Secure {
		t.Fatal("TLS-terminated cookie not secure")
	}
	req = httptest.NewRequest("GET", "http://localhost:8080/api/admin/status", nil)
	if browserCookie(req, "id", time.Now().Add(time.Hour), true).Secure {
		t.Fatal("localhost dev cookie unexpectedly secure")
	}
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "expiry-access-fixture-token"}
	id, _, err := gateway.keys.saveBrowserSession(&account, true)
	if err != nil {
		t.Fatal(err)
	}
	gateway.keys.mu.Lock()
	gateway.keys.savedAdminSessions[0].Expires = time.Now().Add(-time.Second)
	gateway.keys.mu.Unlock()
	if gateway.keys.browserSessionAccount(id, []adminAccount{account}) != nil {
		t.Fatal("expired session accepted")
	}
}

func TestStartupStateRestoresSessionsButBackupImportRevokes(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "startup-access-fixture-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	cookie := browserLogin(t, gateway, `{"token":"startup-access-fixture-token","browser":true}`)
	raw, err := os.ReadFile(gateway.cfg.KeyStorePath)
	if err != nil {
		t.Fatal(err)
	}
	restored := multiUpstreamProxy(t, "https://agentrouter.org")
	if err := restored.keys.importState(raw, true); err != nil {
		t.Fatal(err)
	}
	if restored.keys.browserSessionAccount(cookie.Value, []adminAccount{account}) == nil {
		t.Fatal("startup import dropped session")
	}
	if err := restored.keys.importBackup(raw); err != nil {
		t.Fatal(err)
	}
	if restored.keys.browserSessionAccount(cookie.Value, []adminAccount{account}) != nil {
		t.Fatal("backup import preserved session")
	}
}

func TestPasswordSetupRevokesLegacyHeaderSessions(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "legacy-access-fixture-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	id, _ := gateway.createAdminSession(&account)
	req := httptest.NewRequest("GET", "/api/admin/status", nil)
	req.Header.Set("X-Admin-Session", id)
	if _, err := gateway.authenticateAdmin(req); err != nil {
		t.Fatal(err)
	}
	if err := gateway.keys.setAdminPassword(&account, "legacy-fixture-password-long"); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.authenticateAdmin(req); err == nil {
		t.Fatal("header session survived password reset")
	}
}

func TestBrowserSessionRejectsChangedPasswordVersion(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "password-version-fixture-token"}
	if err := gateway.keys.setAdminPassword(&account, "version-fixture-password-long"); err != nil {
		t.Fatal(err)
	}
	id, _, err := gateway.keys.saveBrowserSession(&account, true)
	if err != nil {
		t.Fatal(err)
	}
	if gateway.keys.browserSessionAccount(id, []adminAccount{account}) == nil {
		t.Fatal("new session invalid")
	}
	gateway.keys.mu.Lock()
	gateway.keys.savedAdminSessions[0].PasswordVersion = "stale-version"
	gateway.keys.mu.Unlock()
	if gateway.keys.browserSessionAccount(id, []adminAccount{account}) != nil {
		t.Fatal("stale password-version session accepted")
	}
}
