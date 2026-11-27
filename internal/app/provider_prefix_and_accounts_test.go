package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProviderModelPrefixesDisambiguateIdenticalModelsAndStripPrefixUpstream(t *testing.T) {
	var vyceCalls, novitaCalls atomic.Int32
	var vyceModelSeen, novitaModelSeen atomic.Value

	vyceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vyceCalls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if m, ok := body["model"].(string); ok {
			vyceModelSeen.Store(m)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"resp_vyce","object":"response","model":"glm-5.3-flash","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"from vyceai"}]}],"usage":{"input_tokens":11,"output_tokens":7}}`)
	}))
	defer vyceServer.Close()

	novitaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		novitaCalls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if m, ok := body["model"].(string); ok {
			novitaModelSeen.Store(m)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-novita","object":"chat.completion","model":"zai-org/glm-5.3-flash","choices":[{"index":0,"message":{"role":"assistant","content":"from novita"},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":9}}`)
	}))
	defer novitaServer.Close()

	gateway := multiUpstreamProxy(t, vyceServer.URL)
	pVyce := createProvider(t, gateway.keys, "Vyceai", vyceServer.URL+"/v1", protocolResponses, "glm-5.3-flash", "vyceai/shared-model")
	pNovita := createProvider(t, gateway.keys, "Novita", novitaServer.URL+"/v3/openai", protocolChatCompletions, "glm-5.3-flash", "zai-org/glm-5.3-flash", "shared-model")
	addProviderKey(t, gateway, "Vyce key", "sk-vyce-secret-key", pVyce.ID, 1)
	addProviderKey(t, gateway, "Novita key", "sk-novita-secret-key", pNovita.ID, 10) // higher priority, yet prefix must override!

	if pVyce.EffectivePrefix != "vyceai" || pNovita.EffectivePrefix != "novita" {
		t.Fatalf("unexpected prefixes: %q / %q", pVyce.EffectivePrefix, pNovita.EffectivePrefix)
	}
	// Redundant own prefix ("vyceai/shared-model") must be normalized to raw "shared-model" without double prefixing.
	for _, m := range pVyce.Models {
		if strings.HasPrefix(m, "vyceai/") {
			t.Fatalf("expected own prefix to be stripped from stored raw models, got %q", m)
		}
	}

	// 1. Route identical model explicitly to Vyceai despite Novita having higher priority (10 > 1).
	rec := requestGateway(gateway, "/v1/chat/completions", `{"model":"vyceai/glm-5.3-flash","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != 200 || vyceCalls.Load() != 1 || novitaCalls.Load() != 0 {
		t.Fatalf("vyceai prefix routing failed: code=%d vyce=%d novita=%d body=%s", rec.Code, vyceCalls.Load(), novitaCalls.Load(), rec.Body.String())
	}
	if got, _ := vyceModelSeen.Load().(string); got != "glm-5.3-flash" {
		t.Fatalf("expected upstream model 'glm-5.3-flash' (prefix stripped), got %q", got)
	}

	// 2. Route slash-containing upstream model ("novita/zai-org/glm-5.3-flash") via Anthropic /v1/messages endpoint!
	anthReq := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"novita/zai-org/glm-5.3-flash","max_tokens":128,"messages":[{"role":"user","content":"hi"}]}`))
	anthReq.Header.Set("Content-Type", "application/json")
	anthRec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(anthRec, anthReq)
	if anthRec.Code != 200 || novitaCalls.Load() != 1 {
		t.Fatalf("novita slash model via /v1/messages failed: code=%d body=%s", anthRec.Code, anthRec.Body.String())
	}
	if got, _ := novitaModelSeen.Load().(string); got != "zai-org/glm-5.3-flash" {
		t.Fatalf("expected upstream model 'zai-org/glm-5.3-flash', got %q", got)
	}

	// 3. Requesting a model under a provider prefix that does NOT own that model must fail closed (never leak to Novita).
	missRec := requestGateway(gateway, "/v1/chat/completions", `{"model":"vyceai/zai-org/glm-5.3-flash","messages":[{"role":"user","content":"hi"}]}`)
	if missRec.Code != 503 || novitaCalls.Load() != 1 {
		t.Fatalf("expected 503 fail-closed when vyceai lacks model, got %d (novitaCalls=%d)", missRec.Code, novitaCalls.Load())
	}

	// 4. GET /v1/models returns aggregated prefixed catalog.
	modelsReq := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	modelsRec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(modelsRec, modelsReq)
	if modelsRec.Code != 200 {
		t.Fatalf("/v1/models status=%d body=%s", modelsRec.Code, modelsRec.Body.String())
	}
	bodyStr := modelsRec.Body.String()
	for _, want := range []string{`"vyceai/glm-5.3-flash"`, `"novita/glm-5.3-flash"`, `"novita/zai-org/glm-5.3-flash"`} {
		if !strings.Contains(bodyStr, want) {
			t.Fatalf("expected %s in /v1/models response: %s", want, bodyStr)
		}
	}
}

func TestFriendClientKeyUsageLimitsAndUIAccountsRBAC(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-1","object":"chat.completion","model":"glm-5.3-flash","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":25,"completion_tokens":15}}`)
	}))
	defer upstream.Close()

	parsedUpstream, err := parseUpstreamURL(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(t.TempDir(), "keys.json")
	gateway := newProxyServer(config{
		UpstreamURL:      parsedUpstream,
		UpstreamProtocol: protocolChatCompletions,
		Profile:          "generic",
		AdminToken:       "owner-super-secret-token",
		AdminAccounts:    []adminAccount{{Name: "owner", Token: "owner-super-secret-token", Role: "admin"}},
		KeyStorePath:     storePath,
		KeyStoreSecret:   "test-encryption-secret",
		KeySelectionMode: "pool-only",
		KeyFailover:      true,
	})
	prov := createProvider(t, gateway.keys, "Vyceai", upstream.URL, protocolChatCompletions, "glm-5.3-flash")
	addProviderKey(t, gateway, "Main key", "sk-upstream-friend-test", prov.ID, 1)

	adminReq := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", token)
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, req)
		return rec
	}

	// 1. Create a Client API key for friend with daily_request_limit = 2.
	ckRec := adminReq(http.MethodPost, "/api/admin/client-keys", `{"name":"Kent","daily_request_limit":2}`, "owner-super-secret-token")
	if ckRec.Code != http.StatusCreated {
		t.Fatalf("create client key failed: %d %s", ckRec.Code, ckRec.Body.String())
	}
	var ckCreated struct {
		Key   clientKeyView `json:"key"`
		Token string        `json:"token"`
	}
	_ = json.Unmarshal(ckRec.Body.Bytes(), &ckCreated)
	if !strings.HasPrefix(ckCreated.Token, "arp_") || ckCreated.Key.DailyRequestLimit != 2 {
		t.Fatalf("unexpected client key: %+v token=%q", ckCreated.Key, ckCreated.Token)
	}

	callAsFriend := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"vyceai/glm-5.3-flash","messages":[{"role":"user","content":"yo"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+ckCreated.Token)
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, req)
		return rec
	}

	if r1 := callAsFriend(); r1.Code != 200 {
		t.Fatalf("first friend call failed: %d %s", r1.Code, r1.Body.String())
	}
	if r2 := callAsFriend(); r2.Code != 200 {
		t.Fatalf("second friend call failed: %d %s", r2.Code, r2.Body.String())
	}
	// Third call exceeds daily_request_limit=2 -> 429 Too Many Requests!
	if r3 := callAsFriend(); r3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd call over daily limit, got %d %s", r3.Code, r3.Body.String())
	}

	// Verify per-client token telemetry (2 calls * (25 in + 15 out) = 50 in, 30 out).
	listKeys, err := gateway.keys.listClientKeys()
	if err != nil || len(listKeys) != 1 {
		t.Fatalf("listClientKeys err=%v len=%d", err, len(listKeys))
	}
	if listKeys[0].Uses != 2 || listKeys[0].InputTokens != 50 || listKeys[0].OutputTokens != 30 {
		t.Fatalf("unexpected client telemetry: %+v", listKeys[0])
	}

	// 2. Owner creates a UI-managed 'viewer' account for friend right via /api/admin/accounts!
	accRec := adminReq(http.MethodPost, "/api/admin/accounts", `{"name":"kent","password":"kent-secure-password-123","role":"viewer"}`, "owner-super-secret-token")
	if accRec.Code != http.StatusCreated {
		t.Fatalf("create UI account failed: %d %s", accRec.Code, accRec.Body.String())
	}

	// Friend logs in via browser cookie flow (/api/admin/login).
	friendCookie := browserLogin(t, gateway, `{"name":"kent","password":"kent-secure-password-123","browser":true,"remember":true}`)

	// Friend (viewer) CAN view status and providers (including prefixed models), CANNOT view accounts, backup, or mutate keys.
	if st := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/status", "", friendCookie, false); st.Code != 200 {
		t.Fatalf("viewer status failed: %d", st.Code)
	}
	provViewRec := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/providers", "", friendCookie, false)
	if provViewRec.Code != 200 || !strings.Contains(provViewRec.Body.String(), `"vyceai/glm-5.3-flash"`) {
		t.Fatalf("viewer providers failed: %d %s", provViewRec.Code, provViewRec.Body.String())
	}
	if bkp := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/backup", "", friendCookie, false); bkp.Code != http.StatusForbidden {
		t.Fatalf("viewer should not access backup, got %d", bkp.Code)
	}
	if accList := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/accounts", "", friendCookie, false); accList.Code != http.StatusForbidden {
		t.Fatalf("viewer should not list accounts, got %d", accList.Code)
	}
	if mut := adminBrowserRequest(gateway, http.MethodPost, "/api/admin/client-keys", `{"name":"hack"}`, friendCookie, true); mut.Code != http.StatusForbidden {
		t.Fatalf("viewer should not create client keys, got %d", mut.Code)
	}

	// Friend CAN change his own password via /api/admin/password!
	pwChange := adminBrowserRequest(gateway, http.MethodPost, "/api/admin/password", `{"current_password":"kent-secure-password-123","password":"kent-updated-password-456"}`, friendCookie, true)
	if pwChange.Code != 200 {
		t.Fatalf("UI viewer own password change failed: %d %s", pwChange.Code, pwChange.Body.String())
	}
	// Old cookie is immediately invalidated by PasswordVersion change!
	if oldSess := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/status", "", friendCookie, false); oldSess.Code != http.StatusUnauthorized {
		t.Fatalf("expected old session cookie to be revoked after password change, got %d", oldSess.Code)
	}

	// Log in with new password, then owner disables account -> session revoked immediately!
	friendCookie2 := browserLogin(t, gateway, `{"name":"kent","password":"kent-updated-password-456","browser":true}`)
	disableRec := adminReq(http.MethodPatch, "/api/admin/accounts/kent", `{"enabled":false}`, "owner-super-secret-token")
	if disableRec.Code != 200 {
		t.Fatalf("disable UI account failed: %d %s", disableRec.Code, disableRec.Body.String())
	}
	if afterDisable := adminBrowserRequest(gateway, http.MethodGet, "/api/admin/status", "", friendCookie2, false); afterDisable.Code != http.StatusUnauthorized {
		t.Fatalf("expected disabled UI account session to be rejected, got %d", afterDisable.Code)
	}

	// Env account 'owner' cannot be deleted via UI endpoint.
	if delOwner := adminReq(http.MethodDelete, "/api/admin/accounts/owner", "", "owner-super-secret-token"); delOwner.Code != http.StatusBadRequest {
		t.Fatalf("expected env account deletion to fail with 400, got %d", delOwner.Code)
	}

	// Reload from disk preserves UI accounts and client key token usage.
	reloaded := newAPIKeyStore(storePath, "test-encryption-secret")
	if len(reloaded.listAdminUsers()) != 1 || reloaded.listAdminUsers()[0].Name != "kent" {
		t.Fatalf("UI admin users not persisted across reload")
	}
}

func TestNoAvailableAPIKeysAlertSuppressedWhenKeysDisabledButSentOnCooldown(t *testing.T) {
	var sentTexts []string
	tgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		if txt, ok := body["text"].(string); ok {
			sentTexts = append(sentTexts, txt)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tgServer.Close()

	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "Google", "https://generativelanguage.googleapis.com", protocolGenAI, "gemini-4-hydrogen")
	keyView := addProviderKey(t, gateway, "Google Disabled", "sk-google-disabled-key", p.ID, 1)
	disabled := false
	if _, err := gateway.keys.update(keyView.ID, nil, &disabled); err != nil {
		t.Fatal(err)
	}

	// Capture events emitted by doUpstreamWithMeta directly into maybeAlert.
	infra := &infrastructure{
		telegramToken:  "test-token",
		telegramChatID: "12345",
		alertCooldown:  0,
		lastAlerts:     make(map[string]time.Time),
		httpClient:     tgServer.Client(),
	}
	var captured []map[string]any
	setPersistentLogSink(func(record map[string]any) {
		captured = append(captured, record)
	})
	defer setPersistentLogSink(nil)

	// 1. Key is manually disabled -> must mark suppress_alert=true and NOT alert.
	rec := requestGateway(gateway, "/v1/chat/completions", `{"model":"google/gemini-4-hydrogen","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for disabled key, got %d", rec.Code)
	}
	foundDisabled := false
	for _, ev := range captured {
		if ev["message"] == "no_available_api_keys" {
			foundDisabled = true
			if sup, _ := ev["suppress_alert"].(bool); !sup {
				t.Fatalf("expected suppress_alert=true for disabled key, got %+v", ev)
			}
			// Must not send Telegram alert when suppressed.
			infra.maybeAlert(context.Background(), ev)
		}
	}
	if !foundDisabled {
		t.Fatal("expected no_available_api_keys log event")
	}
	if len(sentTexts) != 0 {
		t.Fatalf("expected 0 Telegram alerts for disabled keys, got %d: %v", len(sentTexts), sentTexts)
	}

	// 2. Enable key, then put it into cooldown -> real runtime outage -> suppress_alert must NOT be set!
	captured = nil
	enabled := true
	if _, err := gateway.keys.update(keyView.ID, nil, &enabled); err != nil {
		t.Fatal(err)
	}
	gateway.keys.recordResult(keyView.ID, http.StatusTooManyRequests, "Too Many Requests", 5*time.Minute)
	if !gateway.keys.hasEnabledMatchingKey("google/gemini-4-hydrogen", "/v1/chat/completions") {
		t.Fatal("expected hasEnabledMatchingKey=true for enabled key in cooldown")
	}
	rec = requestGateway(gateway, "/v1/chat/completions", `{"model":"google/gemini-4-hydrogen","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for cooling key, got %d", rec.Code)
	}
	foundCooling := false
	for _, ev := range captured {
		if ev["message"] == "no_available_api_keys" {
			foundCooling = true
			if sup, _ := ev["suppress_alert"].(bool); sup {
				t.Fatalf("expected alert NOT suppressed for enabled key in cooldown, got %+v", ev)
			}
		}
	}
	if !foundCooling {
		t.Fatal("expected no_available_api_keys event for enabled key in cooldown")
	}
}
