package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
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

func (server *proxyServer) handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if server.cfg.AdminToken == "" {
		writeError(w, http.StatusServiceUnavailable, "admin_disabled", "set ADMIN_TOKEN to enable the admin API")
		return
	}
	provided := r.Header.Get("X-Admin-Token")
	if len(provided) != len(server.cfg.AdminToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(server.cfg.AdminToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "admin_auth_required", "missing or invalid X-Admin-Token")
		return
	}

	switch {
	case r.URL.Path == "/api/admin/status":
		server.handleAdminStatus(w, r)
	case r.URL.Path == "/api/admin/keys":
		server.handleAdminKeys(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/admin/keys/"):
		server.handleAdminKey(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "admin endpoint not found")
	}
}

func (server *proxyServer) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	present, _, updated, _ := server.cookies.status()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "upstream": server.cfg.UpstreamURL.String(), "profile": server.cfg.Profile,
		"waf_cookie": present, "waf_cookie_updated_at": optionalTime(updated),
		"selection_mode": server.cfg.KeySelectionMode, "key_failover": server.cfg.KeyFailover,
		"key_cooldown": server.cfg.KeyCooldown.String(),
		"store":        server.keys.status(), "force_sequential_tools": server.cfg.ForceSequentialTools,
		"stateless_responses": server.cfg.StatelessResponses,
	})
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
			Name    string `json:"name"`
			Key     string `json:"key"`
			Enabled *bool  `json:"enabled"`
		}
		if err := decodeAdminJSON(w, r, &input); err != nil {
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		view, err := server.keys.add(input.Name, input.Key, enabled)
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
		if parts[1] != "test" || r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST on /test")
			return
		}
		server.handleAdminKeyTest(w, r, id)
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
		view, err := server.keys.update(id, input.Name, input.Enabled)
		if err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_key_updated", map[string]any{"key_id": view.ID, "name": view.Name, "enabled": view.Enabled})
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

func (server *proxyServer) handleAdminKeyTest(w http.ResponseWriter, r *http.Request, id string) {
	key, err := server.keys.byID(id)
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	started := time.Now()
	status, message := server.probeAPIKey(r.Context(), key.Key)
	server.keys.recordResult(id, status, message, server.cfg.KeyCooldown)
	result := map[string]any{
		"ok": status >= 200 && status < 300, "status": status,
		"duration_ms": time.Since(started).Milliseconds(), "message": message,
	}
	writeJSON(w, http.StatusOK, result)
}

func (server *proxyServer) probeAPIKey(ctx context.Context, key string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.upstreamURL("/v1/models"), nil)
	if err != nil {
		return 0, err.Error()
	}
	req.Header = spoofHeaders(server.cfg.Profile)
	req.Header.Set("Authorization", "Bearer "+key)
	if cookie := server.cookies.header(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := server.client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	server.cookies.capture(resp.Header)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, "Key accepted"
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
