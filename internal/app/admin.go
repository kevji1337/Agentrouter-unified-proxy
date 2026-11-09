package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func (server *proxyServer) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, adminDashboardHTML)
}

func (server *proxyServer) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openAPISpec)
}

func (server *proxyServer) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'")
	_, _ = io.WriteString(w, apiDocsHTML)
}

func (server *proxyServer) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(server.cfg.AdminAccounts) == 0 {
		writeError(w, http.StatusServiceUnavailable, "admin_disabled", "set ADMIN_TOKEN to enable the admin API")
		return
	}
	if r.URL.Path == "/api/admin/login" {
		server.handleAdminLogin(w, r)
		return
	}
	account, err := server.authenticateAdmin(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "admin_auth_required", err.Error())
		return
	}
	if r.Method != http.MethodGet && account.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin_role_required", "administrator role required")
		return
	}
	r = r.WithContext(withAdminAccount(r.Context(), account))

	switch {
	case r.URL.Path == "/api/admin/status":
		server.handleAdminStatus(w, r)
	case r.URL.Path == "/api/admin/settings":
		server.handleAdminSettings(w, r)
	case r.URL.Path == "/api/admin/backup":
		server.handleAdminBackup(w, r)
	case r.URL.Path == "/api/admin/logs":
		server.handleAdminLogs(w, r)
	case r.URL.Path == "/api/admin/providers":
		server.handleAdminProviders(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/providers/"):
		server.handleAdminProvider(w, r, strings.TrimPrefix(r.URL.Path, "/api/admin/providers/"))
	case r.URL.Path == "/api/admin/network-proxies":
		server.handleAdminNetworkProxies(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/network-proxies/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/admin/network-proxies/"), "/")
		if len(parts) == 1 && parts[0] != "" {
			server.handleAdminNetworkProxy(w, r, parts[0], false)
		} else if len(parts) == 2 && parts[1] == "test" {
			server.handleAdminNetworkProxy(w, r, parts[0], true)
		} else {
			writeError(w, 404, "not_found", "network proxy endpoint not found")
		}
	case r.URL.Path == "/api/admin/keys":
		server.handleAdminKeys(w, r)
	case r.URL.Path == "/api/admin/client-keys":
		server.handleAdminClientKeys(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/client-keys/"):
		server.handleAdminClientKey(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/keys/"):
		server.handleAdminKey(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "admin endpoint not found")
	}
}

func (server *proxyServer) handleAdminClientKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := server.keys.listClientKeys()
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": keys})
	case http.MethodPost:
		var input struct {
			Name string `json:"name"`
		}
		if err := decodeAdminJSON(w, r, &input); err != nil {
			return
		}
		view, plain, err := server.keys.createClientKey(input.Name)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_client_key_created", map[string]any{"client_key_id": view.ID, "name": view.Name})
		writeJSON(w, http.StatusCreated, map[string]any{"key": view, "token": plain})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
	}
}

func (server *proxyServer) handleAdminClientKey(w http.ResponseWriter, r *http.Request) {
	remainder := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/client-keys/"), "/")
	parts := strings.Split(remainder, "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
		writeError(w, http.StatusNotFound, "not_found", "client key not found")
		return
	}
	id := parts[0]
	if len(parts) == 2 {
		if parts[1] != "reveal" || r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST on /reveal")
			return
		}
		plain, err := server.keys.revealClientKey(id)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_client_key_revealed", map[string]any{"client_key_id": id})
		writeJSON(w, http.StatusOK, map[string]any{"token": plain})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var input struct {
			Name    *string `json:"name"`
			Enabled *bool   `json:"enabled"`
		}
		if err := decodeAdminJSON(w, r, &input); err != nil {
			return
		}
		view, err := server.keys.updateClientKey(id, input.Enabled, input.Name)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_client_key_updated", map[string]any{"client_key_id": id, "enabled": view.Enabled})
		writeJSON(w, http.StatusOK, view)
	case http.MethodDelete:
		if err := server.keys.deleteClientKey(id); err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_client_key_deleted", map[string]any{"client_key_id": id})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PATCH or DELETE")
	}
}

func (server *proxyServer) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	var input struct {
		Token string `json:"token"`
		TOTP  string `json:"totp"`
	}
	if err := decodeAdminJSON(w, r, &input); err != nil {
		return
	}
	probe := r.Clone(r.Context())
	probe.Header = r.Header.Clone()
	probe.Header.Set("X-Admin-Token", input.Token)
	probe.Header.Set("X-Admin-TOTP", input.TOTP)
	account, err := server.authenticateAdmin(probe)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "admin_auth_required", err.Error())
		return
	}
	session, expires := server.createAdminSession(account)
	logEvent("info", "admin_login", map[string]any{"admin": account.Name, "role": account.Role})
	writeJSON(w, http.StatusOK, map[string]any{
		"session": session, "expires_at": expires, "admin": map[string]any{"name": account.Name, "role": account.Role},
	})
}

func (server *proxyServer) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	present, _, updated, _ := server.wafStatus()
	lastKeyHealth, _ := server.lastKeyHealth.Load().(time.Time)
	account := adminAccountFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "upstream": server.cfg.UpstreamURL.String(), "profile": server.cfg.Profile,
		"upstream_api_protocol": effectiveProtocol(server.cfg.UpstreamProtocol),
		"network_proxy_pool":    server.keys.networkPoolConfigured(),
		"waf_cookie":            present, "waf_cookie_updated_at": optionalTime(updated),
		"selection_mode": server.currentKeySelectionMode(), "key_failover": server.cfg.KeyFailover,
		"key_cooldown":        server.cfg.KeyCooldown.String(),
		"key_health_interval": server.cfg.KeyHealthInterval.String(), "last_key_health_at": optionalTime(lastKeyHealth),
		"store": server.keys.status(), "force_sequential_tools": server.cfg.ForceSequentialTools,
		"stateless_responses": server.cfg.StatelessResponses,
		"infrastructure":      server.infra.health(),
		"admin":               map[string]any{"name": account.Name, "role": account.Role},
	})
}

func (server *proxyServer) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PATCH")
		return
	}
	var input struct {
		SelectionMode string `json:"selection_mode"`
	}
	if err := decodeAdminJSON(w, r, &input); err != nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(input.SelectionMode))
	if !validKeySelectionMode(mode) {
		writeError(w, http.StatusBadRequest, "invalid_selection_mode", "use inbound-first, pool-first, or pool-only")
		return
	}
	if err := server.keys.saveSelectionMode(mode); err != nil {
		writeError(w, http.StatusInternalServerError, "settings_persist_failed", err.Error())
		return
	}
	server.routingMode.Store(mode)
	logEvent("info", "admin_routing_mode_changed", map[string]any{"selection_mode": mode})
	writeJSON(w, http.StatusOK, map[string]any{"selection_mode": mode})
}

func (server *proxyServer) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := server.keys.list()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "key_store_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": keys})
	case http.MethodPost:
		var input struct {
			Name    string       `json:"name"`
			Key     string       `json:"key"`
			Enabled *bool        `json:"enabled"`
			Policy  apiKeyPolicy `json:"policy"`
		}
		if err := decodeAdminJSON(w, r, &input); err != nil {
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		if err := server.validateAdminPolicy(input.Policy); err != nil {
			writeAdminStoreError(w, err)
			return
		}
		view, err := server.keys.addWithPolicy(input.Name, input.Key, enabled, input.Policy)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
			return
		}
		logEvent("info", "admin_key_added", map[string]any{"key_id": view.ID, "name": view.Name})
		writeJSON(w, http.StatusCreated, view)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
	}
}

func (server *proxyServer) handleAdminKey(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/api/admin/keys/")
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
		writeError(w, http.StatusNotFound, "not_found", "key not found")
		return
	}
	id := parts[0]
	if len(parts) == 2 {
		switch parts[1] {
		case "test":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST on /test")
				return
			}
			server.handleAdminKeyTest(w, r, id)
		case "policy":
			if r.Method != http.MethodPatch {
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PATCH on /policy")
				return
			}
			var policy apiKeyPolicy
			if err := decodeAdminJSON(w, r, &policy); err != nil {
				return
			}
			if err := server.validateAdminPolicy(policy); err != nil {
				writeAdminStoreError(w, err)
				return
			}
			view, err := server.keys.updatePolicy(id, policy)
			if err != nil {
				writeAdminStoreError(w, err)
				return
			}
			logEvent("info", "admin_key_policy_updated", map[string]any{"key_id": id})
			writeJSON(w, http.StatusOK, view)
		default:
			writeError(w, http.StatusNotFound, "not_found", "key action not found")
		}
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var input struct {
			Name    *string `json:"name"`
			Enabled *bool   `json:"enabled"`
			Key     *string `json:"key"`
		}
		if err := decodeAdminJSON(w, r, &input); err != nil {
			return
		}
		view, err := server.keys.updateCredential(id, input.Name, input.Enabled, input.Key)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_key_updated", map[string]any{"key_id": view.ID, "name": view.Name, "enabled": view.Enabled, "credential_replaced": input.Key != nil && strings.TrimSpace(*input.Key) != ""})
		writeJSON(w, http.StatusOK, view)
	case http.MethodDelete:
		if err := server.keys.delete(id); err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_key_deleted", map[string]any{"key_id": id})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PATCH or DELETE")
	}
}

func (server *proxyServer) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, err := server.keys.exportBackup()
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="agentrouter-keys-backup.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	case http.MethodPost:
		defer r.Body.Close()
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_backup", err.Error())
			return
		}
		if err := server.keys.importBackup(raw); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_backup", err.Error())
			return
		}
		server.resetOutboundRoutes()
		logEvent("info", "admin_backup_imported", nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
	}
}

func (server *proxyServer) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, http.StatusOK, adminLogRing.page(after, limit))
}

func (server *proxyServer) handleAdminKeyTest(w http.ResponseWriter, r *http.Request, id string) {
	key, err := server.keys.byID(id)
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	started := time.Now()
	status, message := server.probeAPIKey(r.Context(), *key)
	if !probeInconclusive(status) {
		server.keys.recordResult(id, status, message, server.cfg.KeyCooldown)
	}
	result := map[string]any{
		"ok": status >= 200 && status < 300, "status": status, "inconclusive": probeInconclusive(status),
		"duration_ms": time.Since(started).Milliseconds(), "message": message,
	}
	writeJSON(w, http.StatusOK, result)
}

func (server *proxyServer) validateAdminPolicy(policy apiKeyPolicy) error {
	raw := policy.BaseURL
	if policy.ProviderID != nil && *policy.ProviderID != "" {
		for _, p := range server.keys.listProviders() {
			if p.ID == *policy.ProviderID {
				_, err := server.validateUpstreamURL(p.BaseURL)
				return err
			}
		}
		return errors.New("provider not found")
	}
	if strings.TrimSpace(raw) == "" {
		raw = server.cfg.UpstreamURL.String()
	}
	_, err := server.validateUpstreamURL(raw)
	return err
}

// Models is optional. Do not send a billed generation as a health probe.
func probeInconclusive(status int) bool {
	return status == 0 || status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented
}

func (server *proxyServer) probeAPIKey(ctx context.Context, key selectedAPIKey) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	baseURL, profile, _, err := server.upstreamSettings(&key)
	if err != nil {
		return http.StatusBadGateway, "invalid or disallowed upstream URL"
	}
	wafEnabled := server.usesWAFCookies(baseURL, profile)
	route, err := server.outboundRoute(&key)
	if err != nil {
		return 0, "assigned network route unavailable"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.upstreamURLFor(baseURL, "/v1/models"), nil)
	if err != nil {
		return http.StatusBadGateway, "upstream request failed"
	}
	req.Header = spoofHeaders(profile)
	req.Header.Set("Authorization", "Bearer "+key.Key)
	if cookie := route.cookies.header(); cookie != "" && wafEnabled {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := route.client.Do(req)
	if err != nil {
		if key.NetworkProxy != nil {
			server.keys.recordProxyProbe(key.NetworkProxy.ID, false)
			return 0, "network proxy connection failed"
		}
		return http.StatusBadGateway, "upstream connection failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 407 && key.NetworkProxy != nil {
		server.keys.recordProxyProbe(key.NetworkProxy.ID, false)
		return 0, "network proxy authentication failed"
	}
	if wafEnabled {
		route.cookies.capture(resp.Header)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, "Key accepted by models endpoint; configured API protocol is unverified"
	}
	if probeInconclusive(resp.StatusCode) {
		return resp.StatusCode, "Models endpoint unavailable; credential and configured API protocol are unverified"
	}
	return resp.StatusCode, http.StatusText(resp.StatusCode)
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return err
	}
	return nil
}

func writeAdminStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "key_not_found", "API key not found")
		return
	}
	writeError(w, http.StatusBadRequest, "key_store_error", err.Error())
}

func optionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.Format(time.RFC3339)
}
