package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCoolingKeysProbeAndRecovery(t *testing.T) {
	// Mock server that accepts requests (returns 200 OK for /v1/models)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []any{
				map[string]any{"id": "gemini-2.5-flash"},
			},
		})
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	view := addUpstream(t, proxy, "cooling-key", mockServer.URL, protocolChatCompletions, "sk-test-cooling-key", 100, "gemini-2.5-flash")

	// 1. Manually trigger cooldown (simulate 429 rate limit)
	proxy.keys.recordResult(view.ID, http.StatusTooManyRequests, "rate limited by upstream", time.Hour)

	// Verify key is in cooldown
	cooling, err := proxy.keys.coolingKeysForProbe()
	if err != nil {
		t.Fatalf("coolingKeysForProbe failed: %v", err)
	}
	if len(cooling) != 1 || cooling[0].ID != view.ID {
		t.Fatalf("expected 1 cooling key with ID %s, got %d keys", view.ID, len(cooling))
	}

	// 2. Run probeCoolingKeys: mockServer returns 200 OK, key should recover!
	checked, recovered := proxy.probeCoolingKeys(context.Background())
	if checked != 1 {
		t.Errorf("expected 1 key checked, got %d", checked)
	}
	if recovered != 1 {
		t.Errorf("expected 1 key recovered, got %d", recovered)
	}

	// 3. Verify key is no longer in cooldown
	coolingAfter, err := proxy.keys.coolingKeysForProbe()
	if err != nil {
		t.Fatalf("coolingKeysForProbe failed: %v", err)
	}
	if len(coolingAfter) != 0 {
		t.Errorf("expected 0 cooling keys after recovery, got %d", len(coolingAfter))
	}

	// Verify key view has CooldownUntil cleared
	keys, _ := proxy.keys.list()
	if len(keys) > 0 && keys[0].CooldownUntil != nil {
		t.Errorf("expected CooldownUntil to be nil after recovery, got %v", keys[0].CooldownUntil)
	}
}

func TestAdminKeysProbeEndpoint(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	proxy.cfg.AdminToken = "multi-upstream-test-secret"
	proxy.cfg.AdminAccounts = []adminAccount{{Name: "owner", Token: "multi-upstream-test-secret", Role: "admin"}}
	addUpstream(t, proxy, "probe-key-1", mockServer.URL, protocolChatCompletions, "sk-probe-key-1", 100)

	// POST /api/admin/keys/probe
	req := httptest.NewRequest(http.MethodPost, "/api/admin/keys/probe", nil)
	req.Header.Set("X-Admin-Token", "multi-upstream-test-secret")
	rec := httptest.NewRecorder()
	proxy.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}
	if resp["checked"] != float64(1) {
		t.Errorf("expected checked=1, got %v", resp["checked"])
	}
	if resp["accepted"] != float64(1) {
		t.Errorf("expected accepted=1, got %v", resp["accepted"])
	}

	// GET /api/admin/keys/probe should return 405 Method Not Allowed
	getReq := httptest.NewRequest(http.MethodGet, "/api/admin/keys/probe", nil)
	getReq.Header.Set("X-Admin-Token", "multi-upstream-test-secret")
	getRec := httptest.NewRecorder()
	proxy.routes().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed on GET, got %d", getRec.Code)
	}
}
