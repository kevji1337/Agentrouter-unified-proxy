package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func createProvider(t *testing.T, store *apiKeyStore, name, base, protocol string, models ...string) providerView {
	t.Helper()
	p, err := store.saveProvider("", providerInput{Name: name, BaseURL: base, APIProtocol: protocol, Models: models, SpoofProfile: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addProviderKey(t *testing.T, gateway *proxyServer, name, key, provider string, priority int) apiKeyView {
	t.Helper()
	view, err := gateway.keys.addWithPolicy(name, key, true, apiKeyPolicy{ProviderID: &provider, Weight: 1, Priority: priority})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func TestProviderModelsChooseCorrectAPIAndCredential(t *testing.T) {
	var aCalls, bCalls, legacyCalls atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer sk-provider-a" || r.URL.Path != "/v1/chat/completions" {
			t.Error("wrong A request")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer sk-provider-b" || r.URL.Path != "/api/v1/responses" {
			t.Error("wrong B request")
		}
		_, _ = io.WriteString(w, responsesReply)
	}))
	defer b.Close()
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { legacyCalls.Add(1); w.WriteHeader(500) }))
	defer legacy.Close()
	gateway := multiUpstreamProxy(t, legacy.URL)
	pa := createProvider(t, gateway.keys, "A", a.URL+"/v1", protocolChatCompletions, "model-a")
	pb := createProvider(t, gateway.keys, "B", b.URL+"/api/v1", protocolResponses, "model-b")
	addProviderKey(t, gateway, "A key", "sk-provider-a", pa.ID, 1)
	addProviderKey(t, gateway, "B key", "sk-provider-b", pb.ID, 1)
	addUpstream(t, gateway, "Legacy fallback", legacy.URL, protocolResponses, "sk-legacy-catchall", 100)
	for _, model := range []string{"model-a", "model-b"} {
		rec := requestGateway(gateway, "/v1/chat/completions", `{"model":"`+model+`","messages":[]}`)
		if rec.Code != 200 {
			t.Fatalf("routing %s: %d %s", model, rec.Code, rec.Body.String())
		}
	}
	if aCalls.Load() != 1 || bCalls.Load() != 1 || legacyCalls.Load() != 0 {
		t.Fatal("provider model routing ignored")
	}
	gateway.routingMode.Store("inbound-first")
	rec := requestGateway(gateway, "/v1/chat/completions", `{"model":"model-a","messages":[]}`)
	if rec.Code != 200 || legacyCalls.Load() != 0 {
		t.Fatal("inbound key bypassed explicit provider model rule")
	}
	rec = requestGateway(gateway, "/v1/responses", `{"model":"model-a","input":"hello"}`)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "no_compatible_upstream") || legacyCalls.Load() != 0 {
		t.Fatal("Responses routed to incompatible provider")
	}
}

func TestProviderFailoverNeverLeavesModelProviders(t *testing.T) {
	var first, second, wrong atomic.Int32
	makeServer := func(calls *atomic.Int32, status int, reply string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, reply)
		}))
	}
	a := makeServer(&first, 429, `{"error":"rate limit"}`)
	defer a.Close()
	b := makeServer(&second, 200, responsesReply)
	defer b.Close()
	c := makeServer(&wrong, 500, "")
	defer c.Close()
	gateway := multiUpstreamProxy(t, c.URL)
	p1 := createProvider(t, gateway.keys, "First", a.URL, protocolChatCompletions, "m")
	p2 := createProvider(t, gateway.keys, "Second", b.URL, protocolResponses, "m")
	p3 := createProvider(t, gateway.keys, "Unrelated", c.URL, protocolResponses, "other")
	addProviderKey(t, gateway, "First key", "sk-first-provider-model", p1.ID, 10)
	addProviderKey(t, gateway, "Second key", "sk-second-provider-model", p2.ID, 0)
	addProviderKey(t, gateway, "Wrong key", "sk-unrelated-provider-model", p3.ID, 100)
	addUpstream(t, gateway, "Legacy", c.URL, protocolResponses, "sk-legacy-high-priority", 100)
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 200 || first.Load() != 1 || second.Load() != 1 || wrong.Load() != 0 {
		t.Fatalf("provider failover %d calls=%d/%d/%d", rec.Code, first.Load(), second.Load(), wrong.Load())
	}
}

func TestProviderEmptyDisabledAndMissingModelsAreFailClosed(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	gateway := multiUpstreamProxy(t, upstream.URL)
	p := createProvider(t, gateway.keys, "Provider", upstream.URL, protocolChatCompletions, "m")
	addProviderKey(t, gateway, "Key", "sk-provider-model-key", p.ID, 1)
	addUpstream(t, gateway, "Legacy", upstream.URL, protocolChatCompletions, "sk-legacy-provider-key", 100)
	disabled := false
	_, err := gateway.keys.saveProvider(p.ID, providerInput{Name: p.Name, BaseURL: p.BaseURL, APIProtocol: p.APIProtocol, Models: p.Models, Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 503 || calls.Load() != 0 {
		t.Fatal("disabled model owner fell back to legacy")
	}
	enabled := true
	_, err = gateway.keys.saveProvider(p.ID, providerInput{Name: p.Name, BaseURL: p.BaseURL, APIProtocol: p.APIProtocol, Enabled: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	// Empty catalog doesn't authorize every model on this provider.
	key, err := gateway.keys.selectNextForModel(map[string]bool{gateway.keys.allKeyIDs()[1]: true}, "m")
	if err == nil || key != nil {
		t.Fatal("empty provider catalog allowed generation")
	}
}

func TestProviderChangesPropagateWithoutDuplicatingSettings(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "Provider", "https://first.example/v1", protocolChatCompletions, "a")
	key := addProviderKey(t, gateway, "Key", "sk-provider-shared-settings", p.ID, 0)
	before, err := gateway.keys.byID(key.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.keys.saveProvider(p.ID, providerInput{Name: "Renamed", BaseURL: "https://second.example/api/v1", APIProtocol: protocolResponses, Models: []string{"b"}, SpoofProfile: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := gateway.keys.byID(key.ID)
	if err != nil || after.BaseURL != "https://second.example/api/v1" || after.APIProtocol != protocolResponses {
		t.Fatal("provider changes not inherited")
	}
	if before.BaseURL != "https://first.example/v1" || before.APIProtocol != protocolChatCompletions {
		t.Fatal("in-flight snapshot changed")
	}
	if _, err := gateway.keys.selectNextForModel(nil, "a"); err == nil {
		t.Fatal("removed model still routed")
	}
	if _, err := gateway.keys.selectNextForModel(nil, "b"); err != nil {
		t.Fatal(err)
	}
	backup, _ := gateway.keys.exportBackup()
	var file persistedKeyFile
	_ = json.Unmarshal(backup, &file)
	if file.Keys[0].BaseURL != "" || file.Keys[0].APIProtocol != "" || len(file.Keys[0].Models) != 0 {
		t.Fatal("duplicated provider source of truth")
	}
	views, _ := gateway.keys.list()
	if views[0].ProviderName != "Renamed" || views[0].Models[0] != "b" {
		t.Fatal("key view doesn't show effective provider")
	}
}

func TestProviderBackupValidationAndLegacyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "provider-backup-secret")
	p := createProvider(t, store, "Provider", "https://provider.example/v1", protocolChatCompletions, "m")
	key, err := store.addWithPolicy("Managed", "sk-managed-provider-backup", true, apiKeyPolicy{ProviderID: &p.ID, Weight: 1})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := store.add("Legacy", "sk-legacy-provider-backup", true)
	if err != nil {
		t.Fatal(err)
	}
	backup, _ := store.exportBackup()
	loaded := newAPIKeyStore(path, "provider-backup-secret")
	selected, err := loaded.byID(key.ID)
	if err != nil || selected.BaseURL != p.BaseURL {
		t.Fatal("provider store reload failed")
	}
	restored := newAPIKeyStore(filepath.Join(t.TempDir(), "restored.json"), "provider-backup-secret")
	if err := restored.importBackup(backup); err != nil {
		t.Fatal(err)
	}
	if len(restored.listProviders()) != 1 {
		t.Fatal("providers lost in backup")
	}
	old, err := restored.byID(legacy.ID)
	if err != nil || old.APIProtocol != protocolResponses || old.Key != "sk-legacy-provider-backup" {
		t.Fatal("legacy key changed")
	}
	var file persistedKeyFile
	_ = json.Unmarshal(backup, &file)
	file.Keys[0].ProviderID = "missing"
	invalid, _ := json.Marshal(file)
	if err := restored.importBackup(invalid); err == nil {
		t.Fatal("dangling provider reference accepted")
	}
	if _, err := restored.byID(key.ID); err != nil {
		t.Fatal("bad import damaged credentials")
	}
	if err := restored.deleteProvider(p.ID); err == nil {
		t.Fatal("deleted provider with keys")
	}
	// Older policy clients don't accidentally unlink a key.
	view, err := restored.updatePolicy(key.ID, apiKeyPolicy{Weight: 1})
	if err != nil || view.ProviderID != p.ID {
		t.Fatal("old policy client unlinked provider")
	}
	empty := ""
	view, err = restored.updatePolicy(key.ID, apiKeyPolicy{ProviderID: &empty, Weight: 1, BaseURL: "https://standalone.example", APIProtocol: protocolResponses})
	if err != nil || view.ProviderID != "" {
		t.Fatal("explicit unlink failed")
	}
	if err := restored.deleteProvider(p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestProviderAdminCRUDAndModelValidation(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "provider-admin-token"}, {Name: "viewer", Role: "viewer", Token: "provider-viewer-token"}}
	send := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Admin-Token", token)
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, req)
		return rec
	}
	input := `{"name":"API A","base_url":"https://provider.example/v1","api_protocol":"chat-completions","models":["model-a","model-b"]}`
	if rec := send("POST", "/api/admin/providers", input, "provider-viewer-token"); rec.Code != 403 {
		t.Fatal("viewer created provider")
	}
	rec := send("POST", "/api/admin/providers", input, "provider-admin-token")
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var provider providerView
	_ = json.Unmarshal(rec.Body.Bytes(), &provider)
	keyInput := fmt.Sprintf(`{"name":"Key","key":"sk-provider-admin-key","policy":{"provider_id":%q}}`, provider.ID)
	rec = send("POST", "/api/admin/keys", keyInput, "provider-admin-token")
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), "model-a") || strings.Contains(rec.Body.String(), "sk-provider-admin-key") {
		t.Fatalf("key selection %d %s", rec.Code, rec.Body.String())
	}
	rec = send("GET", "/api/admin/providers", "", "provider-viewer-token")
	if rec.Code != 200 {
		t.Fatal("viewer cannot view")
	}
	rec = send("DELETE", "/api/admin/providers/"+provider.ID, "", "provider-admin-token")
	if rec.Code != 400 {
		t.Fatal("provider with keys deleted")
	}
	for _, model := range []string{"*", "bad model", "prefix*"} {
		if _, err := gateway.keys.saveProvider("", providerInput{Name: "Bad", BaseURL: "https://provider.example", Models: []string{model}}); err == nil {
			t.Errorf("accepted invalid model %q", model)
		}
	}
	gateway.cfg.AllowedUpstreamOrigins = []string{"https://agentrouter.org"}
	rec = send("POST", "/api/admin/providers", input, "provider-admin-token")
	if rec.Code != 400 {
		t.Fatal("provider URL bypassed origin allowlist")
	}
}

func TestProviderModelRoutingAndNetworkProxyCompose(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-provider-via-proxy" {
			t.Error("wrong credential")
		}
		_, _ = io.WriteString(w, nativeChatResponse)
	}))
	defer upstream.Close()
	proxy := fakeHTTPProxy(t, false, "", "", &calls)
	gateway := multiUpstreamProxy(t, upstream.URL)
	addNetworkProxy(t, gateway.keys, "Route", proxy.URL)
	p := createProvider(t, gateway.keys, "API", upstream.URL, protocolChatCompletions, "m")
	addProviderKey(t, gateway, "Key", "sk-provider-via-proxy", p.ID, 1)
	rec := requestGateway(gateway, "/v1/chat/completions", nativeChatRequest)
	if rec.Code != 200 || calls.Load() != 1 {
		t.Fatal("provider/proxy composition failed")
	}
}

func TestProviderEmptyCatalogSafeViewAndModelListIsolation(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "Empty", "https://provider.example", protocolResponses)
	raw, err := json.Marshal(gateway.keys.listProviders())
	if err != nil || !strings.Contains(string(raw), `"models":[]`) {
		t.Fatalf("empty catalog should be array: %s", raw)
	}
	p, err = gateway.keys.saveProvider(p.ID, providerInput{Name: p.Name, BaseURL: p.BaseURL, Models: []string{"m"}})
	if err != nil {
		t.Fatal(err)
	}
	p.Models[0] = "mutated-client-view"
	if gateway.keys.listProviders()[0].Models[0] != "m" {
		t.Fatal("provider returned mutable catalog backing array")
	}
}

func TestProviderSaveFailureRollsBackModelRules(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "API", "https://provider.example", protocolResponses, "m")
	addProviderKey(t, gateway, "Key", "sk-provider-rollback", p.ID, 0)
	gateway.keys.setSaveHook(func([]byte) error { return fmt.Errorf("persistence failed") })
	_, err := gateway.keys.saveProvider(p.ID, providerInput{Name: p.Name, BaseURL: p.BaseURL, Models: []string{"other"}})
	if err == nil {
		t.Fatal("persistence failure ignored")
	}
	gateway.keys.setSaveHook(nil)
	if !gateway.keys.modelManaged("m") || gateway.keys.modelManaged("other") {
		t.Fatal("failed update changed model ownership")
	}
}

func TestProviderConcurrentEditsAndSelections(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	p := createProvider(t, gateway.keys, "API", "https://provider.example", protocolResponses, "m")
	addProviderKey(t, gateway, "Key", "sk-concurrent-provider", p.ID, 1)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				key, err := gateway.keys.selectNextForModel(nil, "m")
				if err != nil || key.BaseURL != "https://provider.example" {
					t.Errorf("selection: %v", err)
					return
				}
				_ = gateway.keys.listProviders()
			}
		}()
	}
	for n := 0; n < 10; n++ {
		if _, err := gateway.keys.saveProvider(p.ID, providerInput{Name: p.Name, BaseURL: p.BaseURL, APIProtocol: protocolResponses, Models: []string{"m"}}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	_, _ = gateway.keys.enabledForProbe()
}
