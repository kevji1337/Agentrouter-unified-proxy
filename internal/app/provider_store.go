package app

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

// Provider owns shared API routing settings, not credentials or network routes.
// Keys keep only a reference; old unlinked records keep their original policy.
type apiProvider struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	BaseURL      string    `json:"base_url"`
	APIProtocol  string    `json:"api_protocol"`
	SpoofProfile string    `json:"spoof_profile"`
	Models       []string  `json:"models"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type providerView struct {
	apiProvider
	Keys int `json:"keys"`
}

type providerInput struct {
	Name         string   `json:"name"`
	BaseURL      string   `json:"base_url"`
	APIProtocol  string   `json:"api_protocol"`
	SpoofProfile string   `json:"spoof_profile"`
	Models       []string `json:"models"`
	Enabled      *bool    `json:"enabled"`
}

func validateProvider(p apiProvider) error {
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 80 {
		return errors.New("provider name must contain 1 to 80 characters")
	}
	if p.BaseURL == "" {
		return errors.New("provider base_url is required")
	}
	if err := validateKeyPolicy(persistedAPIKey{BaseURL: p.BaseURL, APIProtocol: p.APIProtocol, SpoofProfile: p.SpoofProfile}); err != nil {
		return err
	}
	if len(p.Models) > 500 {
		return errors.New("provider supports at most 500 explicit model IDs")
	}
	for _, model := range p.Models {
		if model == "" || len(model) > 200 || strings.ContainsAny(model, "*\r\n\t ") {
			return errors.New("provider models must be explicit IDs, at most 200 bytes, without whitespace or wildcards")
		}
	}
	return nil
}

func (store *apiKeyStore) providerIndexLocked(id string) int {
	for i := range store.providers {
		if store.providers[i].ID == id {
			return i
		}
	}
	return -1
}

func (store *apiKeyStore) listProviders() []providerView {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]providerView, 0, len(store.providers))
	for _, p := range store.providers {
		p.Models = append([]string{}, p.Models...)
		count := 0
		for _, k := range store.keys {
			if k.ProviderID == p.ID {
				count++
			}
		}
		result = append(result, providerView{apiProvider: p, Keys: count})
	}
	return result
}

func (store *apiKeyStore) saveProvider(id string, input providerInput) (providerView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return providerView{}, err
	}
	i := store.providerIndexLocked(id)
	if id != "" && i < 0 {
		return providerView{}, os.ErrNotExist
	}
	now := time.Now().UTC()
	record := apiProvider{ID: "provider_" + randomKeyID()[4:], Enabled: true, CreatedAt: now}
	if i >= 0 {
		record = store.providers[i]
	}
	record.Name = strings.TrimSpace(input.Name)
	record.BaseURL = strings.TrimRight(strings.TrimSpace(input.BaseURL), "/")
	record.APIProtocol = effectiveProtocol(input.APIProtocol)
	record.SpoofProfile = strings.ToLower(strings.TrimSpace(input.SpoofProfile))
	record.Models = normalizeModels(input.Models)
	record.UpdatedAt = now
	if input.Enabled != nil {
		record.Enabled = *input.Enabled
	}
	if err := validateProvider(record); err != nil {
		return providerView{}, err
	}
	for _, p := range store.providers {
		if p.ID != id && strings.EqualFold(p.Name, record.Name) {
			return providerView{}, errors.New("provider name already exists")
		}
	}
	old := append([]apiProvider(nil), store.providers...)
	if i < 0 {
		store.providers = append(store.providers, record)
	} else {
		store.providers[i] = record
	}
	if err := store.saveLocked(); err != nil {
		store.providers = old
		return providerView{}, err
	}
	count := 0
	for _, k := range store.keys {
		if k.ProviderID == record.ID {
			count++
		}
	}
	record.Models = append([]string{}, record.Models...)
	return providerView{apiProvider: record, Keys: count}, nil
}

func (store *apiKeyStore) deleteProvider(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	i := store.providerIndexLocked(id)
	if i < 0 {
		return os.ErrNotExist
	}
	for _, k := range store.keys {
		if k.ProviderID == id {
			return errors.New("provider has API keys; reassign or delete them first")
		}
	}
	old := append([]apiProvider(nil), store.providers...)
	store.providers = append(store.providers[:i], store.providers[i+1:]...)
	if err := store.saveLocked(); err != nil {
		store.providers = old
		return err
	}
	return nil
}

func (store *apiKeyStore) validateProviderFile(file persistedKeyFile) error {
	ids := make(map[string]bool)
	names := make(map[string]bool)
	for _, p := range file.Providers {
		if p.ID == "" || ids[p.ID] || names[strings.ToLower(p.Name)] {
			return errors.New("invalid or duplicate provider")
		}
		if err := validateProvider(p); err != nil {
			return err
		}
		ids[p.ID] = true
		names[strings.ToLower(p.Name)] = true
	}
	for _, k := range file.Keys {
		if k.ProviderID != "" && !ids[k.ProviderID] {
			return errors.New("API key references missing provider")
		}
	}
	return nil
}

func clearProviderOverrides(record *persistedAPIKey) {
	if record.ProviderID != "" {
		record.BaseURL = ""
		record.APIProtocol = ""
		record.SpoofProfile = ""
		record.Models = nil
	}
}

func (store *apiKeyStore) providerForKeyLocked(key persistedAPIKey) (persistedAPIKey, bool) {
	if key.ProviderID == "" {
		return key, true
	}
	i := store.providerIndexLocked(key.ProviderID)
	if i < 0 {
		return key, false
	}
	p := store.providers[i]
	key.BaseURL, key.APIProtocol, key.SpoofProfile = p.BaseURL, effectiveProtocol(p.APIProtocol), p.SpoofProfile
	key.Models = p.Models
	// An empty provider catalog means no generation models, NOT allow-all.
	return key, p.Enabled
}

func (store *apiKeyStore) modelManagedLocked(model string) bool {
	if model == "" {
		return false
	}
	for _, p := range store.providers {
		for _, m := range p.Models {
			if strings.EqualFold(m, model) {
				return true
			}
		}
	}
	return false
}

func (store *apiKeyStore) modelManaged(model string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.modelManagedLocked(model)
}

func (store *apiKeyStore) keyEligibleLocked(key persistedAPIKey, excluded map[string]bool, model, protocol string, now time.Time) bool {
	effective, enabled := store.providerForKeyLocked(key)
	if !enabled {
		return false
	}
	if model != "" {
		if store.modelManagedLocked(model) && key.ProviderID == "" {
			return false
		}
		if key.ProviderID != "" && len(effective.Models) == 0 {
			return false
		}
	}
	return keyAvailable(effective, excluded, model, now) && (protocol == "" || effectiveProtocol(effective.APIProtocol) == protocol)
}

func (server *proxyServer) handleAdminProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"data": server.keys.listProviders()})
	case http.MethodPost:
		server.saveAdminProvider(w, r, "")
	default:
		writeError(w, 405, "method_not_allowed", "use GET or POST")
	}
}

func (server *proxyServer) saveAdminProvider(w http.ResponseWriter, r *http.Request, id string) {
	var input providerInput
	if decodeAdminJSON(w, r, &input) != nil {
		return
	}
	if _, err := server.validateUpstreamURL(input.BaseURL); err != nil {
		writeAdminStoreError(w, err)
		return
	}
	view, err := server.keys.saveProvider(id, input)
	if err != nil {
		writeAdminStoreError(w, err)
		return
	}
	status := http.StatusOK
	if id == "" {
		status = http.StatusCreated
	}
	logEvent("info", "admin_provider_saved", map[string]any{"provider_id": view.ID})
	writeJSON(w, status, view)
}

func (server *proxyServer) handleAdminProvider(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" || strings.Contains(id, "/") {
		writeError(w, 404, "not_found", "provider endpoint not found")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		server.saveAdminProvider(w, r, id)
	case http.MethodDelete:
		if err := server.keys.deleteProvider(id); err != nil {
			writeAdminStoreError(w, err)
			return
		}
		logEvent("info", "admin_provider_deleted", map[string]any{"provider_id": id})
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, 405, "method_not_allowed", "use PATCH or DELETE")
	}
}
