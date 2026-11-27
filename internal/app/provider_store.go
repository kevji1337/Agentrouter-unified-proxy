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
	ModelPrefix  string    `json:"model_prefix,omitempty"`
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
	EffectivePrefix string   `json:"effective_prefix"`
	PrefixedModels  []string `json:"prefixed_models"`
	Keys            int      `json:"keys"`
}

type providerInput struct {
	Name         string   `json:"name"`
	ModelPrefix  *string  `json:"model_prefix,omitempty"`
	BaseURL      string   `json:"base_url"`
	APIProtocol  string   `json:"api_protocol"`
	SpoofProfile string   `json:"spoof_profile"`
	Models       []string `json:"models"`
	Enabled      *bool    `json:"enabled"`
}

var cyrillicTranslit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "i", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch",
	'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

func normalizeProviderPrefix(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", nil
	}
	if len(p) > 40 {
		return "", errors.New("provider model_prefix must contain 1 to 40 characters")
	}
	for i := 0; i < len(p); i++ {
		ch := p[i]
		valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.'
		if !valid {
			return "", errors.New("provider model_prefix may contain only lowercase letters, digits, '.', '_', or '-' (no '/')")
		}
	}
	if strings.Trim(p, "-._") == "" {
		return "", errors.New("provider model_prefix must contain at least one letter or digit")
	}
	return p, nil
}

func defaultProviderPrefix(name, id string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if repl, ok := cyrillicTranslit[r]; ok {
			if repl != "" {
				b.WriteString(repl)
				lastDash = false
			}
			continue
		}
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-._")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-._")
	}
	if slug != "" {
		return slug
	}
	shortID := strings.TrimPrefix(strings.ToLower(id), "provider_")
	if len(shortID) > 6 {
		shortID = shortID[:6]
	}
	if shortID != "" {
		return "p-" + shortID
	}
	return "provider"
}

func effectiveProviderPrefixesSlice(providers []apiProvider) []string {
	result := make([]string, len(providers))
	used := make(map[string]bool, len(providers))
	for i, p := range providers {
		if p.ModelPrefix != "" {
			clean := strings.ToLower(strings.TrimSpace(p.ModelPrefix))
			result[i] = clean
			used[clean] = true
		}
	}
	for i, p := range providers {
		if result[i] != "" {
			continue
		}
		base := defaultProviderPrefix(p.Name, p.ID)
		candidate := base
		for suffix := 2; used[candidate]; suffix++ {
			suffixStr := "-" + itoaPositive(suffix)
			maxBase := 40 - len(suffixStr)
			trimmedBase := base
			if len(trimmedBase) > maxBase {
				trimmedBase = strings.Trim(trimmedBase[:maxBase], "-._")
			}
			candidate = trimmedBase + suffixStr
		}
		result[i] = candidate
		used[candidate] = true
	}
	return result
}

func itoaPositive(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	pos := len(digits)
	for n > 0 {
		pos--
		digits[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[pos:])
}

func prefixedModelsFor(prefix string, models []string) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		if prefix != "" {
			out = append(out, prefix+"/"+m)
		} else {
			out = append(out, m)
		}
	}
	return out
}

func stripOwnProviderPrefix(models []string, ownPrefix string) []string {
	if ownPrefix == "" || len(models) == 0 {
		return models
	}
	cleaned := make([]string, 0, len(models))
	lead := strings.ToLower(ownPrefix) + "/"
	for _, m := range models {
		trimmed := strings.TrimSpace(m)
		if len(trimmed) > len(lead) && strings.EqualFold(trimmed[:len(lead)], lead) {
			trimmed = trimmed[len(lead):]
		}
		cleaned = append(cleaned, trimmed)
	}
	return cleaned
}

func validateProvider(p apiProvider) error {
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 80 {
		return errors.New("provider name must contain 1 to 80 characters")
	}
	if p.ModelPrefix != "" {
		if _, err := normalizeProviderPrefix(p.ModelPrefix); err != nil {
			return err
		}
	}
	if p.BaseURL == "" {
		p.BaseURL = defaultBaseURLForProtocol(p.APIProtocol)
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

func (store *apiKeyStore) effectiveProviderPrefixesLocked() []string {
	return effectiveProviderPrefixesSlice(store.providers)
}

func (store *apiKeyStore) listProviders() []providerView {
	store.mu.Lock()
	defer store.mu.Unlock()
	prefixes := store.effectiveProviderPrefixesLocked()
	result := make([]providerView, 0, len(store.providers))
	for idx, p := range store.providers {
		p.Models = append([]string{}, p.Models...)
		count := 0
		for _, k := range store.keys {
			if k.ProviderID == p.ID {
				count++
			}
		}
		effPrefix := prefixes[idx]
		result = append(result, providerView{
			apiProvider:     p,
			EffectivePrefix: effPrefix,
			PrefixedModels:  prefixedModelsFor(effPrefix, p.Models),
			Keys:            count,
		})
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
	if input.ModelPrefix != nil {
		normalizedPrefix, prefixErr := normalizeProviderPrefix(*input.ModelPrefix)
		if prefixErr != nil {
			return providerView{}, prefixErr
		}
		record.ModelPrefix = normalizedPrefix
	}
	record.BaseURL = strings.TrimRight(strings.TrimSpace(input.BaseURL), "/")
	record.APIProtocol = effectiveProtocol(input.APIProtocol)
	if record.BaseURL == "" {
		record.BaseURL = defaultBaseURLForProtocol(record.APIProtocol)
	}
	record.SpoofProfile = strings.ToLower(strings.TrimSpace(input.SpoofProfile))
	record.UpdatedAt = now
	if input.Enabled != nil {
		record.Enabled = *input.Enabled
	}
	candidateProviders := append([]apiProvider(nil), store.providers...)
	targetIndex := i
	if targetIndex < 0 {
		candidateProviders = append(candidateProviders, record)
		targetIndex = len(candidateProviders) - 1
	} else {
		candidateProviders[targetIndex] = record
	}
	for idx, p := range store.providers {
		if p.ID != id && strings.EqualFold(p.Name, record.Name) {
			return providerView{}, errors.New("provider name already exists")
		}
		if p.ID != id && record.ModelPrefix != "" && p.ModelPrefix != "" && strings.EqualFold(p.ModelPrefix, record.ModelPrefix) {
			return providerView{}, errors.New("provider model_prefix already exists")
		}
		_ = idx
	}
	// Check if explicit ModelPrefix collides with another provider's effective prefix.
	if record.ModelPrefix != "" {
		otherOnly := make([]apiProvider, 0, len(store.providers))
		for _, p := range store.providers {
			if p.ID != id {
				otherOnly = append(otherOnly, p)
			}
		}
		for _, otherEff := range effectiveProviderPrefixesSlice(otherOnly) {
			if strings.EqualFold(otherEff, record.ModelPrefix) {
				return providerView{}, errors.New("provider model_prefix already exists")
			}
		}
	}
	candidatePrefixes := effectiveProviderPrefixesSlice(candidateProviders)
	effPrefix := candidatePrefixes[targetIndex]
	record.Models = normalizeModels(stripOwnProviderPrefix(input.Models, effPrefix))
	candidateProviders[targetIndex] = record
	if err := validateProvider(record); err != nil {
		return providerView{}, err
	}
	old := append([]apiProvider(nil), store.providers...)
	store.providers = candidateProviders
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
	return providerView{
		apiProvider:     record,
		EffectivePrefix: effPrefix,
		PrefixedModels:  prefixedModelsFor(effPrefix, record.Models),
		Keys:            count,
	}, nil
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
	explicitPrefixes := make(map[string]bool)
	for _, p := range file.Providers {
		if p.ID == "" || ids[p.ID] || names[strings.ToLower(p.Name)] {
			return errors.New("invalid or duplicate provider")
		}
		if p.ModelPrefix != "" {
			norm, err := normalizeProviderPrefix(p.ModelPrefix)
			if err != nil || explicitPrefixes[norm] {
				return errors.New("invalid or duplicate provider model_prefix")
			}
			explicitPrefixes[norm] = true
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

// resolveModelRouteLocked splits "<prefix>/<upstreamModel>" on the first slash
// when <prefix> matches a configured provider's effective prefix. Unprefixed IDs
// or upstream IDs whose first segment is not a provider prefix (such as
// "zai-org/glm-5.3-flash") return matchedPrefix=false for full compatibility.
func (store *apiKeyStore) resolveModelRouteLocked(model string) (string, string, bool) {
	trimmed := strings.TrimSpace(model)
	candPrefix, rest, hasSlash := strings.Cut(trimmed, "/")
	if !hasSlash || candPrefix == "" || rest == "" {
		return "", trimmed, false
	}
	prefixes := store.effectiveProviderPrefixesLocked()
	for i, p := range store.providers {
		if strings.EqualFold(prefixes[i], candPrefix) {
			return p.ID, rest, true
		}
	}
	return "", trimmed, false
}

func (store *apiKeyStore) resolveModelRoute(model string) (string, string, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.resolveModelRouteLocked(model)
}

func (store *apiKeyStore) prefixedModelCatalog() []map[string]any {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil || len(store.providers) == 0 {
		return nil
	}
	prefixes := store.effectiveProviderPrefixesLocked()
	var catalog []map[string]any
	for i, p := range store.providers {
		if !p.Enabled || len(p.Models) == 0 {
			continue
		}
		created := p.CreatedAt.Unix()
		if created <= 0 {
			created = 1700000000
		}
		effPrefix := prefixes[i]
		for _, m := range p.Models {
			id := m
			if effPrefix != "" {
				id = effPrefix + "/" + m
			}
			catalog = append(catalog, map[string]any{
				"id":       id,
				"object":   "model",
				"created":  created,
				"owned_by": p.Name,
			})
		}
	}
	return catalog
}

func (store *apiKeyStore) modelManagedLocked(model string) bool {
	if model == "" {
		return false
	}
	if _, _, matchedPrefix := store.resolveModelRouteLocked(model); matchedPrefix {
		return true
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

func protocolFilterMatches(keyProtocol, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.HasPrefix(filter, "/") {
		return protocolSupportsPath(keyProtocol, filter)
	}
	return effectiveProtocol(keyProtocol) == filter
}

func (store *apiKeyStore) keyEligibleLocked(key persistedAPIKey, excluded map[string]bool, model, protocol string, now time.Time) bool {
	effective, enabled := store.providerForKeyLocked(key)
	if !enabled {
		return false
	}
	targetProviderID, checkModel, matchedPrefix := store.resolveModelRouteLocked(model)
	if matchedPrefix {
		if key.ProviderID != targetProviderID || len(effective.Models) == 0 {
			return false
		}
	} else if model != "" {
		if store.modelManagedLocked(model) && key.ProviderID == "" {
			return false
		}
		if key.ProviderID != "" && len(effective.Models) == 0 {
			return false
		}
	}
	return keyAvailable(effective, excluded, checkModel, now) && protocolFilterMatches(effective.APIProtocol, protocol)
}

func (store *apiKeyStore) hasCompatibleKey(model, protocolFilter string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil || len(store.keys) == 0 {
		return false
	}
	now := time.Now().UTC()
	for i := range store.keys {
		record := &store.keys[i]
		resetUsagePeriods(record, now)
		if store.proxyAvailableLocked(*record) && store.keyEligibleLocked(*record, nil, model, protocolFilter, now) {
			return true
		}
	}
	return false
}

// hasEnabledMatchingKey reports whether at least one enabled key (on an enabled
// provider) matches model and protocol, ignoring runtime cooldowns, daily limits,
// and budgets. When false, keys are intentionally disabled or unconfigured.
func (store *apiKeyStore) hasEnabledMatchingKey(model, protocolFilter string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil || len(store.keys) == 0 {
		return false
	}
	targetProviderID, checkModel, matchedPrefix := store.resolveModelRouteLocked(model)
	for _, key := range store.keys {
		if !key.Enabled {
			continue
		}
		effective, providerEnabled := store.providerForKeyLocked(key)
		if !providerEnabled {
			continue
		}
		if !protocolFilterMatches(effective.APIProtocol, protocolFilter) {
			continue
		}
		if matchedPrefix {
			if key.ProviderID != targetProviderID || len(effective.Models) == 0 {
				continue
			}
		} else if model != "" {
			if store.modelManagedLocked(model) && key.ProviderID == "" {
				continue
			}
			if key.ProviderID != "" && len(effective.Models) == 0 {
				continue
			}
		}
		if checkModel == "" || len(effective.Models) == 0 {
			return true
		}
		for _, allowed := range effective.Models {
			if allowed == "*" || strings.EqualFold(allowed, checkModel) {
				return true
			}
		}
	}
	return false
}

func (store *apiKeyStore) hasProtocolBlockedKey(excluded map[string]bool, model, protocolFilter string) bool {
	if protocolFilter == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now().UTC()
	for i := range store.keys {
		record := &store.keys[i]
		resetUsagePeriods(record, now)
		if store.proxyAvailableLocked(*record) && store.keyEligibleLocked(*record, excluded, model, "", now) && !store.keyEligibleLocked(*record, excluded, model, protocolFilter, now) {
			return true
		}
	}
	return false
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
	if effectiveProtocol(input.APIProtocol) == protocolGenAI && strings.TrimSpace(input.BaseURL) == "" {
		input.BaseURL = DefaultGenAIBaseURL
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
