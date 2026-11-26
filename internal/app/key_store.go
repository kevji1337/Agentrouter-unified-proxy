package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var errNoEnabledAPIKeys = errors.New("no enabled API keys in the key pool")

type persistedKeyFile struct {
	AdminPasswords []savedAdminPassword    `json:"admin_passwords,omitempty"`
	AdminSessions  []savedAdminSession     `json:"admin_sessions,omitempty"`
	AdminUsers     []persistedAdminUser    `json:"admin_users,omitempty"`
	Version        int                     `json:"version"`
	Providers      []apiProvider           `json:"providers,omitempty"`
	Proxies        []persistedNetworkProxy `json:"network_proxies,omitempty"`
	Keys           []persistedAPIKey       `json:"keys"`
	ClientKeys     []persistedClientKey    `json:"client_keys,omitempty"`
	Settings       persistedKeySettings    `json:"settings,omitempty"`
}

type persistedClientKey struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Enabled           bool      `json:"enabled"`
	Mask              string    `json:"mask"`
	Nonce             string    `json:"nonce"`
	Ciphertext        string    `json:"ciphertext"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	Uses              uint64    `json:"uses,omitempty"`
	LastUsed          time.Time `json:"last_used,omitempty"`
	InputTokens       uint64    `json:"input_tokens,omitempty"`
	OutputTokens      uint64    `json:"output_tokens,omitempty"`
	DailyRequestLimit int       `json:"daily_request_limit,omitempty"`
	UsageDay          string    `json:"usage_day,omitempty"`
	DailyRequests     int       `json:"daily_requests,omitempty"`
	digest            [32]byte
	hasDigest         bool
}

type clientKeyView struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Enabled           bool       `json:"enabled"`
	Mask              string     `json:"mask"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	Uses              uint64     `json:"uses"`
	LastUsed          *time.Time `json:"last_used,omitempty"`
	InputTokens       uint64     `json:"input_tokens"`
	OutputTokens      uint64     `json:"output_tokens"`
	DailyRequestLimit int        `json:"daily_request_limit"`
	DailyRequests     int        `json:"daily_requests"`
}

type clientAuthResult struct {
	ID            string
	Name          string
	Authenticated bool
	RateLimited   bool
}

type persistedKeySettings struct {
	SelectionMode    string `json:"selection_mode,omitempty"`
	NetworkProxyPool bool   `json:"network_proxy_pool,omitempty"`
}

type persistedAPIKey struct {
	ProviderID           string    `json:"provider_id,omitempty"`
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Enabled              bool      `json:"enabled"`
	Mask                 string    `json:"mask"`
	Nonce                string    `json:"nonce"`
	Ciphertext           string    `json:"ciphertext"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	Priority             int       `json:"priority,omitempty"`
	Weight               int       `json:"weight,omitempty"`
	Models               []string  `json:"models,omitempty"`
	DailyRequestLimit    int       `json:"daily_request_limit,omitempty"`
	MonthlyBudgetUSD     float64   `json:"monthly_budget_usd,omitempty"`
	InputCostPerMillion  float64   `json:"input_cost_per_million,omitempty"`
	OutputCostPerMillion float64   `json:"output_cost_per_million,omitempty"`
	Uses                 uint64    `json:"uses,omitempty"`
	Failures             uint64    `json:"failures,omitempty"`
	LastUsed             time.Time `json:"last_used,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
	CooldownUntil        time.Time `json:"cooldown_until,omitempty"`
	UsageDay             string    `json:"usage_day,omitempty"`
	DailyRequests        int       `json:"daily_requests,omitempty"`
	UsageMonth           string    `json:"usage_month,omitempty"`
	MonthlySpendUSD      float64   `json:"monthly_spend_usd,omitempty"`
	InputTokens          uint64    `json:"input_tokens,omitempty"`
	OutputTokens         uint64    `json:"output_tokens,omitempty"`
	ProxyMode            string    `json:"proxy_mode,omitempty"`
	ProxyID              string    `json:"proxy_id,omitempty"`
	APIProtocol          string    `json:"api_protocol,omitempty"`
	BaseURL              string    `json:"base_url,omitempty"`
	SpoofProfile         string    `json:"spoof_profile,omitempty"`
}

type apiKeyView struct {
	ProviderID           string     `json:"provider_id,omitempty"`
	ProviderName         string     `json:"provider_name,omitempty"`
	ProviderPrefix       string     `json:"provider_prefix,omitempty"`
	NetworkBlocked       bool       `json:"network_blocked"`
	ProviderBlocked      bool       `json:"provider_blocked"`
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Enabled              bool       `json:"enabled"`
	Mask                 string     `json:"mask"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	Uses                 uint64     `json:"uses"`
	Failures             uint64     `json:"failures"`
	LastUsed             *time.Time `json:"last_used,omitempty"`
	LastError            string     `json:"last_error,omitempty"`
	CooldownUntil        *time.Time `json:"cooldown_until,omitempty"`
	Priority             int        `json:"priority"`
	Weight               int        `json:"weight"`
	Models               []string   `json:"models,omitempty"`
	DailyRequestLimit    int        `json:"daily_request_limit"`
	DailyRequests        int        `json:"daily_requests"`
	MonthlyBudgetUSD     float64    `json:"monthly_budget_usd"`
	MonthlySpendUSD      float64    `json:"monthly_spend_usd"`
	InputCostPerMillion  float64    `json:"input_cost_per_million"`
	OutputCostPerMillion float64    `json:"output_cost_per_million"`
	InputTokens          uint64     `json:"input_tokens"`
	OutputTokens         uint64     `json:"output_tokens"`
	ProxyMode            string     `json:"proxy_mode"`
	ProxyID              string     `json:"proxy_id,omitempty"`
	APIProtocol          string     `json:"api_protocol"`
	BaseURL              string     `json:"base_url,omitempty"`
	SpoofProfile         string     `json:"spoof_profile,omitempty"`
}

type apiKeyPolicy struct {
	ProviderID           *string  `json:"provider_id,omitempty"`
	Priority             int      `json:"priority"`
	Weight               int      `json:"weight"`
	Models               []string `json:"models"`
	DailyRequestLimit    int      `json:"daily_request_limit"`
	MonthlyBudgetUSD     float64  `json:"monthly_budget_usd"`
	InputCostPerMillion  float64  `json:"input_cost_per_million"`
	OutputCostPerMillion float64  `json:"output_cost_per_million"`
	ProxyMode            string   `json:"proxy_mode"`
	ProxyID              string   `json:"proxy_id"`
	APIProtocol          string   `json:"api_protocol"`
	BaseURL              string   `json:"base_url"`
	SpoofProfile         string   `json:"spoof_profile"`
}

type selectedAPIKey struct {
	Mask         string
	ProviderID   string
	ProviderName string
	ProxyMode    string
	NetworkProxy *selectedNetworkProxy
	ID           string
	Name         string
	Key          string
	BaseURL      string
	APIProtocol  string
	SpoofProfile string
}

type apiKeyStore struct {
	adminPasswords     []savedAdminPassword
	savedAdminSessions []savedAdminSession
	adminUsers         []persistedAdminUser
	mu                 sync.Mutex
	path               string
	aead               cipher.AEAD
	providers          []apiProvider
	proxies            []persistedNetworkProxy
	keys               []persistedAPIKey
	clientKeys         []persistedClientKey
	next               uint64
	loadErr            error
	readOnly           bool
	settings           persistedKeySettings
	stateRevision      uint64
	dirtyTelemetry     bool
	lastTelemetrySave  time.Time
	saveHook           func([]byte) error
	versionedSaveHook  func([]byte, uint64) (uint64, error)
	onStateConflict    func()
}

type apiKeyStoreStatus struct {
	Ready             bool    `json:"ready"`
	Error             string  `json:"error,omitempty"`
	Total             int     `json:"total"`
	Enabled           int     `json:"enabled"`
	Available         int     `json:"available"`
	InputTokens       uint64  `json:"input_tokens"`
	OutputTokens      uint64  `json:"output_tokens"`
	MonthlySpendUSD   float64 `json:"monthly_spend_usd"`
	ClientKeys        int     `json:"client_keys"`
	EnabledClientKeys int     `json:"enabled_client_keys"`
}

func newAPIKeyStore(path, secret string) *apiKeyStore {
	store := &apiKeyStore{path: strings.TrimSpace(path)}
	if strings.TrimSpace(secret) == "" {
		store.readOnly = true
		return store
	}
	digest := sha256.Sum256([]byte("agentrouter-unified-proxy/key-store/v1\x00" + secret))
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		store.loadErr = err
		return store
	}
	store.aead, err = cipher.NewGCM(block)
	if err != nil {
		store.loadErr = err
		return store
	}
	if store.path != "" {
		store.loadErr = store.load()
	}
	return store
}

func (store *apiKeyStore) load() error {
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read key store: %w", err)
	}
	var file persistedKeyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("decode key store: %w", err)
	}
	if file.Version != 1 && file.Version != 2 {
		return fmt.Errorf("unsupported key store version %d", file.Version)
	}
	if err := validateAdminAccessFile(file); err != nil {
		return err
	}
	if err := store.validateProviderFile(file); err != nil {
		return err
	}
	if err := store.validateProxyFile(file); err != nil {
		return err
	}
	for i := range file.Keys {
		normalizeKeyPolicy(&file.Keys[i])
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return fmt.Errorf("decrypt key %q: check KEY_STORE_SECRET: %w", file.Keys[i].Name, err)
		}
	}
	for i := range file.ClientKeys {
		plain, err := store.decryptClientKey(file.ClientKeys[i])
		if err != nil {
			return fmt.Errorf("decrypt client key %q: check KEY_STORE_SECRET: %w", file.ClientKeys[i].Name, err)
		}
		file.ClientKeys[i].digest = sha256.Sum256([]byte(plain))
		file.ClientKeys[i].hasDigest = true
	}
	store.adminPasswords = file.AdminPasswords
	store.savedAdminSessions = file.AdminSessions
	store.adminUsers = file.AdminUsers
	store.keys = file.Keys
	store.providers = file.Providers
	store.proxies = file.Proxies
	store.clientKeys = file.ClientKeys
	store.settings = file.Settings
	if len(store.proxies) > 0 {
		store.settings.NetworkProxyPool = true
	}
	store.rebalanceProxiesLocked()
	return nil
}

func (store *apiKeyStore) marshalStateLocked() ([]byte, error) {
	file := persistedKeyFile{
		AdminPasswords: store.adminPasswords, AdminSessions: store.savedAdminSessions,
		AdminUsers: store.adminUsers,
		Version:    2, Providers: store.providers, Proxies: store.proxies,
		Keys: store.keys, ClientKeys: store.clientKeys, Settings: store.settings,
	}
	return json.MarshalIndent(file, "", "  ")
}

func (store *apiKeyStore) writeLocalFileLocked(raw []byte) error {
	if store.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create key store directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".keys-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, store.path); err != nil {
		return fmt.Errorf("replace key store: %w", err)
	}
	return nil
}

func (store *apiKeyStore) saveLocked() error {
	if store.path == "" && store.saveHook == nil && store.versionedSaveHook == nil {
		return nil
	}
	raw, err := store.marshalStateLocked()
	if err != nil {
		return err
	}
	if err := store.writeLocalFileLocked(raw); err != nil {
		return err
	}
	if store.versionedSaveHook != nil {
		newRev, err := store.versionedSaveHook(raw, store.stateRevision)
		if err != nil {
			if errors.Is(err, errGatewayStateConflict) && store.onStateConflict != nil {
				go store.onStateConflict()
			}
			return fmt.Errorf("persist key store: %w", err)
		}
		store.stateRevision = newRev
	} else if store.saveHook != nil {
		if err := store.saveHook(raw); err != nil {
			return fmt.Errorf("persist key store: %w", err)
		}
	}
	store.dirtyTelemetry = false
	store.lastTelemetrySave = time.Now().UTC()
	return nil
}

func (store *apiKeyStore) saveTelemetryLocked(now time.Time) error {
	store.dirtyTelemetry = true
	if !store.lastTelemetrySave.IsZero() && now.Sub(store.lastTelemetrySave) < 5*time.Second {
		return nil
	}
	return store.saveLocked()
}

func (store *apiKeyStore) flushTelemetry() {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.dirtyTelemetry {
		return
	}
	_ = store.saveLocked()
}

func (store *apiKeyStore) revision() uint64 {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.stateRevision
}

func (store *apiKeyStore) setVersionedSaveHook(hook func([]byte, uint64) (uint64, error), onConflict func()) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.versionedSaveHook = hook
	store.onStateConflict = onConflict
}

func (store *apiKeyStore) setSaveHook(hook func([]byte) error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.saveHook = hook
}

func (store *apiKeyStore) encrypt(plain string) (nonce, ciphertext string, err error) {
	buffer := make([]byte, store.aead.NonceSize())
	if _, err = rand.Read(buffer); err != nil {
		return "", "", err
	}
	sealed := store.aead.Seal(nil, buffer, []byte(plain), nil)
	return base64.RawStdEncoding.EncodeToString(buffer), base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (store *apiKeyStore) decrypt(record persistedAPIKey) (string, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return "", err
	}
	if len(nonce) != store.aead.NonceSize() {
		return "", errors.New("invalid encrypted key nonce")
	}
	plain, err := store.aead.Open(nil, nonce, ciphertext, nil)
	return string(plain), err
}

func (store *apiKeyStore) decryptClientKey(record persistedClientKey) (string, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return "", err
	}
	if len(nonce) != store.aead.NonceSize() {
		return "", errors.New("invalid encrypted client key nonce")
	}
	plain, err := store.aead.Open(nil, nonce, ciphertext, nil)
	return string(plain), err
}

func (store *apiKeyStore) ready() error {
	if store.loadErr != nil {
		return store.loadErr
	}
	if store.readOnly || store.aead == nil {
		return errors.New("key store is locked: configure ADMIN_TOKEN and KEY_STORE_SECRET")
	}
	return nil
}

func (store *apiKeyStore) add(name, key string, enabled bool) (apiKeyView, error) {
	return store.addWithPolicy(name, key, enabled, apiKeyPolicy{Weight: 1})
}

func (store *apiKeyStore) addWithPolicy(name, key string, enabled bool, policy apiKeyPolicy) (apiKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return apiKeyView{}, err
	}
	name, key = strings.TrimSpace(name), strings.TrimSpace(key)
	if name == "" || len(name) > 80 {
		return apiKeyView{}, errors.New("name must contain 1 to 80 characters")
	}
	if len(key) < 8 || len(key) > 4096 || strings.ContainsAny(key, "\r\n\t ") {
		return apiKeyView{}, errors.New("API key must contain 8 to 4096 non-whitespace characters")
	}
	for _, existing := range store.keys {
		if strings.EqualFold(existing.Name, name) {
			return apiKeyView{}, errors.New("a key with this name already exists")
		}
	}
	nonce, ciphertext, err := store.encrypt(key)
	if err != nil {
		return apiKeyView{}, err
	}
	now := time.Now().UTC()
	record := persistedAPIKey{
		ID: randomKeyID(), Name: name, Enabled: enabled, Mask: maskAPIKey(key),
		Nonce: nonce, Ciphertext: ciphertext, CreatedAt: now, UpdatedAt: now,
		Priority: policy.Priority, Weight: policy.Weight, Models: normalizeModels(policy.Models),
		DailyRequestLimit: policy.DailyRequestLimit, MonthlyBudgetUSD: policy.MonthlyBudgetUSD,
		InputCostPerMillion: policy.InputCostPerMillion, OutputCostPerMillion: policy.OutputCostPerMillion,
		BaseURL: strings.TrimRight(strings.TrimSpace(policy.BaseURL), "/"), SpoofProfile: strings.ToLower(strings.TrimSpace(policy.SpoofProfile)),
		APIProtocol: policy.APIProtocol, ProxyMode: policy.ProxyMode, ProxyID: policy.ProxyID,
	}
	if policy.ProviderID != nil {
		record.ProviderID = *policy.ProviderID
	}
	if record.ProviderID != "" && store.providerIndexLocked(record.ProviderID) < 0 {
		return apiKeyView{}, errors.New("provider not found")
	}
	clearProviderOverrides(&record)
	if err := validateKeyPolicy(record); err != nil {
		return apiKeyView{}, err
	}
	if record.ProxyMode == "fixed" && store.proxyIndexLocked(record.ProxyID) < 0 {
		return apiKeyView{}, errors.New("network proxy not found")
	}
	if record.ProxyMode != "fixed" {
		record.ProxyID = ""
	}
	oldKeys := append([]persistedAPIKey(nil), store.keys...)
	normalizeKeyPolicy(&record)
	store.keys = append(store.keys, record)
	store.rebalanceProxiesLocked()
	if err := store.saveLocked(); err != nil {
		store.keys = oldKeys
		return apiKeyView{}, err
	}
	return store.keyViewLocked(store.keys[len(store.keys)-1]), nil
}

func (store *apiKeyStore) list() ([]apiKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	views := make([]apiKeyView, 0, len(store.keys))
	for _, record := range store.keys {
		views = append(views, store.keyViewLocked(record))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].CreatedAt.Before(views[j].CreatedAt) })
	return views, nil
}

func (store *apiKeyStore) status() apiKeyStoreStatus {
	store.mu.Lock()
	defer store.mu.Unlock()
	status := apiKeyStoreStatus{Ready: store.loadErr == nil && !store.readOnly && store.aead != nil, Total: len(store.keys)}
	if store.loadErr != nil {
		status.Error = store.loadErr.Error()
	} else if store.readOnly || store.aead == nil {
		status.Error = "key store is locked"
	}
	now := time.Now().UTC()
	for i := range store.keys {
		key := &store.keys[i]
		resetUsagePeriods(key, now)
		if key.Enabled {
			status.Enabled++
			if store.keyEligibleLocked(*key, nil, "", "", now) && store.proxyAvailableLocked(*key) {
				status.Available++
			}
		}
		status.InputTokens += key.InputTokens
		status.OutputTokens += key.OutputTokens
		status.MonthlySpendUSD += key.MonthlySpendUSD
	}
	status.ClientKeys = len(store.clientKeys)
	for _, key := range store.clientKeys {
		if key.Enabled {
			status.EnabledClientKeys++
		}
	}
	return status
}

func validateAPIKey(key string) error {
	if len(key) < 8 || len(key) > 4096 || strings.ContainsAny(key, "\r\n\t ") {
		return errors.New("API key must contain 8 to 4096 non-whitespace characters")
	}
	return nil
}

func (store *apiKeyStore) update(id string, name *string, enabled *bool) (apiKeyView, error) {
	return store.updateCredential(id, name, enabled, nil)
}

func (store *apiKeyStore) updateCredential(id string, name *string, enabled *bool, replacement *string) (apiKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return apiKeyView{}, err
	}
	index := store.indexLocked(id)
	if index < 0 {
		return apiKeyView{}, os.ErrNotExist
	}
	old := store.keys[index]
	updated := old
	if replacement != nil && strings.TrimSpace(*replacement) != "" {
		key := strings.TrimSpace(*replacement)
		if err := validateAPIKey(key); err != nil {
			return apiKeyView{}, err
		}
		nonce, ciphertext, err := store.encrypt(key)
		if err != nil {
			return apiKeyView{}, err
		}
		updated.Nonce, updated.Ciphertext, updated.Mask = nonce, ciphertext, maskAPIKey(key)
		// A new credential may recover from the old key's auth/rate-limit failure.
		// Preserve provider/proxy bindings, limits and historical usage.
		updated.LastError = ""
		updated.CooldownUntil = time.Time{}
	}
	if name != nil {
		trimmed := strings.TrimSpace(*name)
		if trimmed == "" || len(trimmed) > 80 {
			return apiKeyView{}, errors.New("name must contain 1 to 80 characters")
		}
		for i, existing := range store.keys {
			if i != index && strings.EqualFold(existing.Name, trimmed) {
				return apiKeyView{}, errors.New("a key with this name already exists")
			}
		}
		updated.Name = trimmed
	}
	if enabled != nil {
		updated.Enabled = *enabled
	}
	updated.UpdatedAt = time.Now().UTC()
	store.keys[index] = updated
	if err := store.saveLocked(); err != nil {
		store.keys[index] = old
		return apiKeyView{}, err
	}
	return store.keyViewLocked(store.keys[index]), nil
}

func (store *apiKeyStore) updatePolicy(id string, policy apiKeyPolicy) (apiKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return apiKeyView{}, err
	}
	index := store.indexLocked(id)
	if index < 0 {
		return apiKeyView{}, os.ErrNotExist
	}
	oldKeys := append([]persistedAPIKey(nil), store.keys...)
	old := store.keys[index]
	if policy.ProviderID != nil {
		if *policy.ProviderID != "" && store.providerIndexLocked(*policy.ProviderID) < 0 {
			return apiKeyView{}, errors.New("provider not found")
		}
		store.keys[index].ProviderID = *policy.ProviderID
	}
	store.keys[index].Priority = policy.Priority
	store.keys[index].Weight = policy.Weight
	store.keys[index].Models = normalizeModels(policy.Models)
	store.keys[index].DailyRequestLimit = policy.DailyRequestLimit
	store.keys[index].MonthlyBudgetUSD = policy.MonthlyBudgetUSD
	store.keys[index].InputCostPerMillion = policy.InputCostPerMillion
	store.keys[index].OutputCostPerMillion = policy.OutputCostPerMillion
	store.keys[index].BaseURL = strings.TrimRight(strings.TrimSpace(policy.BaseURL), "/")
	store.keys[index].SpoofProfile = strings.ToLower(strings.TrimSpace(policy.SpoofProfile))
	if policy.ProxyMode != "" {
		if !validProxyBinding(policy.ProxyMode, policy.ProxyID) {
			store.keys[index] = old
			return apiKeyView{}, errors.New("invalid proxy binding")
		}
		if policy.ProxyMode == "fixed" && store.proxyIndexLocked(policy.ProxyID) < 0 {
			store.keys[index] = old
			return apiKeyView{}, errors.New("network proxy not found")
		}
		store.keys[index].ProxyMode = policy.ProxyMode
		if policy.ProxyMode == "fixed" {
			store.keys[index].ProxyID = policy.ProxyID
		} else if policy.ProxyMode == "direct" {
			store.keys[index].ProxyID = ""
		}
	}
	// Old clients do not send api_protocol: preserve the existing selection.
	if policy.APIProtocol != "" {
		store.keys[index].APIProtocol = policy.APIProtocol
	}
	clearProviderOverrides(&store.keys[index])
	if err := validateKeyPolicy(store.keys[index]); err != nil {
		store.keys[index] = old
		return apiKeyView{}, err
	}
	normalizeKeyPolicy(&store.keys[index])
	store.rebalanceProxiesLocked()
	store.keys[index].UpdatedAt = time.Now().UTC()
	if err := store.saveLocked(); err != nil {
		store.keys = oldKeys
		return apiKeyView{}, err
	}
	return store.keyViewLocked(store.keys[index]), nil
}

func (store *apiKeyStore) delete(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	index := store.indexLocked(id)
	if index < 0 {
		return os.ErrNotExist
	}
	old := append([]persistedAPIKey(nil), store.keys...)
	store.keys = append(store.keys[:index], store.keys[index+1:]...)
	store.rebalanceProxiesLocked()
	if store.next >= uint64(len(store.keys)) {
		store.next = 0
	}
	if err := store.saveLocked(); err != nil {
		store.keys = old
		return err
	}
	return nil
}

func (store *apiKeyStore) selectNext(excluded map[string]bool) (*selectedAPIKey, error) {
	return store.selectNextForModel(excluded, "")
}

func (store *apiKeyStore) selectNextForModel(excluded map[string]bool, model string) (*selectedAPIKey, error) {
	return store.selectNextForModelLoads(excluded, model, nil)
}

func (store *apiKeyStore) selectNextForModelLoads(excluded map[string]bool, model string, loads map[string]int64) (*selectedAPIKey, error) {
	return store.selectNextCompatible(excluded, model, loads, "")
}

func (store *apiKeyStore) selectNextCompatible(excluded map[string]bool, model string, loads map[string]int64, requiredProtocol string) (*selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	if len(store.keys) == 0 {
		return nil, errNoEnabledAPIKeys
	}
	now := time.Now().UTC()
	eligible := make([]int, 0, len(store.keys))
	highestPriority := -1 << 30
	for index := range store.keys {
		record := &store.keys[index]
		resetUsagePeriods(record, now)
		if !store.proxyAvailableLocked(*record) || !store.keyEligibleLocked(*record, excluded, model, requiredProtocol, now) {
			continue
		}
		if record.Priority > highestPriority {
			highestPriority = record.Priority
			eligible = eligible[:0]
		}
		if record.Priority == highestPriority {
			eligible = append(eligible, index)
		}
	}
	if len(eligible) == 0 {
		return nil, errNoEnabledAPIKeys
	}
	if len(loads) > 0 {
		minimum := int64(1 << 62)
		for _, index := range eligible {
			if load := loads[store.keys[index].ID]; load < minimum {
				minimum = load
			}
		}
		filtered := eligible[:0]
		for _, index := range eligible {
			if loads[store.keys[index].ID] == minimum {
				filtered = append(filtered, index)
			}
		}
		eligible = filtered
	}
	totalWeight := 0
	for _, index := range eligible {
		totalWeight += store.keys[index].Weight
	}
	slot := int(store.next % uint64(totalWeight))
	store.next++
	selectedIndex := eligible[0]
	for _, index := range eligible {
		if slot < store.keys[index].Weight {
			selectedIndex = index
			break
		}
		slot -= store.keys[index].Weight
	}
	record := &store.keys[selectedIndex]
	plain, err := store.decrypt(*record)
	if err != nil {
		return nil, err
	}
	record.Uses++
	record.DailyRequests++
	record.LastUsed = now
	if err := store.saveTelemetryLocked(now); err != nil {
		logEvent("warn", "key_store_telemetry_save_failed", map[string]any{"error": err.Error()})
	}
	return store.selectedKeyLocked(*record, plain)
}

func (store *apiKeyStore) allKeyIDs() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	ids := make([]string, 0, len(store.keys))
	for _, key := range store.keys {
		ids = append(ids, key.ID)
	}
	return ids
}

func (store *apiKeyStore) byID(id string) (*selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.indexLocked(id)
	if index < 0 {
		return nil, os.ErrNotExist
	}
	plain, err := store.decrypt(store.keys[index])
	if err != nil {
		return nil, err
	}
	return store.selectedKeyLocked(store.keys[index], plain)
}

func (store *apiKeyStore) recordResult(id string, status int, message string, cooldown time.Duration) {
	if id == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.indexLocked(id)
	if index < 0 {
		return
	}
	changed := false
	if status >= 400 {
		store.keys[index].Failures++
		store.keys[index].LastError = message
		if cooldown > 0 && (status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusTooManyRequests) {
			store.keys[index].CooldownUntil = time.Now().UTC().Add(cooldown)
		}
		changed = true
	} else if store.keys[index].LastError != "" || !store.keys[index].CooldownUntil.IsZero() {
		store.keys[index].LastError = ""
		store.keys[index].CooldownUntil = time.Time{}
		changed = true
	}
	if changed {
		_ = store.saveLocked()
	}
}

func (store *apiKeyStore) recordUsage(id string, inputTokens, outputTokens uint64) {
	if id == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.indexLocked(id)
	if index < 0 {
		return
	}
	record := &store.keys[index]
	now := time.Now().UTC()
	resetUsagePeriods(record, now)
	record.InputTokens += inputTokens
	record.OutputTokens += outputTokens
	record.MonthlySpendUSD += float64(inputTokens)*record.InputCostPerMillion/1_000_000 + float64(outputTokens)*record.OutputCostPerMillion/1_000_000
	_ = store.saveTelemetryLocked(now)
}

func (store *apiKeyStore) enabledForProbe() ([]selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	result := make([]selectedAPIKey, 0)
	for _, record := range store.keys {
		_, providerEnabled := store.providerForKeyLocked(record)
		if !record.Enabled || !providerEnabled || !store.proxyAvailableLocked(record) {
			continue
		}
		plain, err := store.decrypt(record)
		if err != nil {
			return nil, err
		}
		selected, err := store.selectedKeyLocked(record, plain)
		if err != nil {
			return nil, err
		}
		result = append(result, *selected)
	}
	return result, nil
}

func (store *apiKeyStore) coolingKeysForProbe() ([]selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	result := make([]selectedAPIKey, 0)
	now := time.Now().UTC()
	for _, record := range store.keys {
		_, providerEnabled := store.providerForKeyLocked(record)
		if !record.Enabled || !providerEnabled || !store.proxyAvailableLocked(record) {
			continue
		}
		if record.CooldownUntil.IsZero() || !now.Before(record.CooldownUntil) {
			continue
		}
		plain, err := store.decrypt(record)
		if err != nil {
			return nil, err
		}
		selected, err := store.selectedKeyLocked(record, plain)
		if err != nil {
			return nil, err
		}
		result = append(result, *selected)
	}
	return result, nil
}

func (store *apiKeyStore) exportBackup() ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(persistedKeyFile{AdminPasswords: store.adminPasswords, AdminUsers: store.adminUsers, Version: 2, Providers: store.providers, Proxies: store.proxies, Keys: store.keys, ClientKeys: store.clientKeys, Settings: store.settings}, "", "  ")
}

func (store *apiKeyStore) importBackup(raw []byte) error {
	return store.importState(raw, false)
}

// Startup state hydration is not an operator backup restore: keep current
// browser sessions across a PostgreSQL-backed deployment.
func (store *apiKeyStore) importState(raw []byte, restoreSessions bool) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	var file persistedKeyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return err
	}
	if file.Version != 1 && file.Version != 2 {
		return fmt.Errorf("unsupported backup version %d", file.Version)
	}
	if err := validateAdminAccessFile(file); err != nil {
		return err
	}
	if err := store.validateProviderFile(file); err != nil {
		return err
	}
	if err := store.validateProxyFile(file); err != nil {
		return err
	}
	for i := range file.Keys {
		normalizeKeyPolicy(&file.Keys[i])
		if err := validateKeyPolicy(file.Keys[i]); err != nil {
			return err
		}
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return fmt.Errorf("backup cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
	}
	for i := range file.ClientKeys {
		plain, err := store.decryptClientKey(file.ClientKeys[i])
		if err != nil {
			return fmt.Errorf("backup client key cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
		file.ClientKeys[i].digest = sha256.Sum256([]byte(plain))
		file.ClientKeys[i].hasDigest = true
	}
	oldPasswords, oldSessions, oldAdminUsers := store.adminPasswords, store.savedAdminSessions, store.adminUsers
	old := store.keys
	oldProviders := store.providers
	oldProxies := store.proxies
	oldClientKeys := store.clientKeys
	oldSettings := store.settings
	store.adminPasswords = file.AdminPasswords
	store.adminUsers = file.AdminUsers
	store.savedAdminSessions = nil
	if restoreSessions {
		store.savedAdminSessions = file.AdminSessions
	}
	store.keys = file.Keys
	store.providers = file.Providers
	store.proxies = file.Proxies
	store.clientKeys = file.ClientKeys
	store.settings = file.Settings
	if len(store.proxies) > 0 {
		store.settings.NetworkProxyPool = true
	}
	store.rebalanceProxiesLocked()
	if err := store.saveLocked(); err != nil {
		store.adminPasswords, store.savedAdminSessions, store.adminUsers = oldPasswords, oldSessions, oldAdminUsers
		store.keys = old
		store.providers = oldProviders
		store.proxies = oldProxies
		store.clientKeys = oldClientKeys
		store.settings = oldSettings
		return err
	}
	return nil
}

// applyRemoteState hydrates in-memory state from a newer cluster revision
// without triggering saveHook back to PostgreSQL, while preserving higher
// monotonic runtime telemetry accumulated on this replica.
func (store *apiKeyStore) applyRemoteState(raw []byte, revision uint64) (string, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return "", false, err
	}
	if revision > 0 && revision <= store.stateRevision {
		return "", false, nil
	}
	var file persistedKeyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return "", false, err
	}
	if file.Version != 1 && file.Version != 2 {
		return "", false, fmt.Errorf("unsupported backup version %d", file.Version)
	}
	if err := validateAdminAccessFile(file); err != nil {
		return "", false, err
	}
	if err := store.validateProviderFile(file); err != nil {
		return "", false, err
	}
	if err := store.validateProxyFile(file); err != nil {
		return "", false, err
	}
	for i := range file.Keys {
		normalizeKeyPolicy(&file.Keys[i])
		if err := validateKeyPolicy(file.Keys[i]); err != nil {
			return "", false, err
		}
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return "", false, fmt.Errorf("remote state cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
	}
	for i := range file.ClientKeys {
		plain, err := store.decryptClientKey(file.ClientKeys[i])
		if err != nil {
			return "", false, fmt.Errorf("remote client key cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
		file.ClientKeys[i].digest = sha256.Sum256([]byte(plain))
		file.ClientKeys[i].hasDigest = true
	}

	localByID := make(map[string]persistedAPIKey, len(store.keys))
	for _, k := range store.keys {
		localByID[k.ID] = k
	}
	for i := range file.Keys {
		rk := &file.Keys[i]
		if lk, ok := localByID[rk.ID]; ok && lk.Ciphertext == rk.Ciphertext {
			if lk.Uses > rk.Uses {
				rk.Uses = lk.Uses
			}
			if lk.Failures > rk.Failures {
				rk.Failures = lk.Failures
			}
			if lk.LastUsed.After(rk.LastUsed) {
				rk.LastUsed = lk.LastUsed
			}
			if lk.UsageDay != "" && lk.UsageDay == rk.UsageDay && lk.DailyRequests > rk.DailyRequests {
				rk.DailyRequests = lk.DailyRequests
			}
			if lk.UsageMonth != "" && lk.UsageMonth == rk.UsageMonth {
				if lk.InputTokens > rk.InputTokens {
					rk.InputTokens = lk.InputTokens
				}
				if lk.OutputTokens > rk.OutputTokens {
					rk.OutputTokens = lk.OutputTokens
				}
				if lk.MonthlySpendUSD > rk.MonthlySpendUSD {
					rk.MonthlySpendUSD = lk.MonthlySpendUSD
				}
			}
			if lk.CooldownUntil.After(rk.CooldownUntil) && lk.UpdatedAt.Equal(rk.UpdatedAt) {
				rk.CooldownUntil = lk.CooldownUntil
				rk.LastError = lk.LastError
			}
		}
	}

	localClients := make(map[string]persistedClientKey, len(store.clientKeys))
	for _, ck := range store.clientKeys {
		localClients[ck.ID] = ck
	}
	for i := range file.ClientKeys {
		rck := &file.ClientKeys[i]
		if lck, ok := localClients[rck.ID]; ok {
			if lck.Uses > rck.Uses {
				rck.Uses = lck.Uses
			}
			if lck.LastUsed.After(rck.LastUsed) {
				rck.LastUsed = lck.LastUsed
			}
			if lck.InputTokens > rck.InputTokens {
				rck.InputTokens = lck.InputTokens
			}
			if lck.OutputTokens > rck.OutputTokens {
				rck.OutputTokens = lck.OutputTokens
			}
			if lck.UsageDay != "" && lck.UsageDay == rck.UsageDay && lck.DailyRequests > rck.DailyRequests {
				rck.DailyRequests = lck.DailyRequests
			}
		}
	}

	store.adminPasswords = file.AdminPasswords
	store.savedAdminSessions = file.AdminSessions
	store.adminUsers = file.AdminUsers
	store.keys = file.Keys
	store.providers = file.Providers
	store.proxies = file.Proxies
	store.clientKeys = file.ClientKeys
	store.settings = file.Settings
	if len(store.proxies) > 0 {
		store.settings.NetworkProxyPool = true
	}
	store.rebalanceProxiesLocked()
	if revision > 0 {
		store.stateRevision = revision
	}
	store.dirtyTelemetry = false
	store.lastTelemetrySave = time.Now().UTC()
	if mergedRaw, err := store.marshalStateLocked(); err == nil {
		_ = store.writeLocalFileLocked(mergedRaw)
	}
	return store.settings.SelectionMode, true, nil
}

func (store *apiKeyStore) savedSelectionMode() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.settings.SelectionMode
}

func (store *apiKeyStore) saveSelectionMode(mode string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	old := store.settings.SelectionMode
	store.settings.SelectionMode = mode
	if err := store.saveLocked(); err != nil {
		store.settings.SelectionMode = old
		return err
	}
	return nil
}

func (store *apiKeyStore) createClientKey(name string) (clientKeyView, string, error) {
	return store.createClientKeyWithLimit(name, 0)
}

func (store *apiKeyStore) createClientKeyWithLimit(name string, dailyLimit int) (clientKeyView, string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return clientKeyView{}, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return clientKeyView{}, "", errors.New("name must contain 1 to 80 characters")
	}
	if dailyLimit < 0 || dailyLimit > 10_000_000 {
		return clientKeyView{}, "", errors.New("daily_request_limit must be between 0 and 10000000")
	}
	for _, existing := range store.clientKeys {
		if strings.EqualFold(existing.Name, name) {
			return clientKeyView{}, "", errors.New("a client key with this name already exists")
		}
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return clientKeyView{}, "", err
	}
	plain := "arp_" + base64.RawURLEncoding.EncodeToString(random)
	nonce, ciphertext, err := store.encrypt(plain)
	if err != nil {
		return clientKeyView{}, "", err
	}
	now := time.Now().UTC()
	record := persistedClientKey{
		ID: "client_" + randomKeyID()[4:], Name: name, Enabled: true, Mask: maskAPIKey(plain),
		Nonce: nonce, Ciphertext: ciphertext, CreatedAt: now, UpdatedAt: now,
		DailyRequestLimit: dailyLimit, UsageDay: now.Format("2006-01-02"),
		digest: sha256.Sum256([]byte(plain)), hasDigest: true,
	}
	store.clientKeys = append(store.clientKeys, record)
	if err := store.saveLocked(); err != nil {
		store.clientKeys = store.clientKeys[:len(store.clientKeys)-1]
		return clientKeyView{}, "", err
	}
	return clientKeyViewOf(record, now), plain, nil
}

func (store *apiKeyStore) listClientKeys() ([]clientKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	now := time.Now().UTC()
	result := make([]clientKeyView, 0, len(store.clientKeys))
	for _, record := range store.clientKeys {
		result = append(result, clientKeyViewOf(record, now))
	}
	return result, nil
}

func (store *apiKeyStore) revealClientKey(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.clientKeyIndexLocked(id)
	if index < 0 {
		return "", os.ErrNotExist
	}
	return store.decryptClientKey(store.clientKeys[index])
}

func (store *apiKeyStore) updateClientKey(id string, enabled *bool, name *string) (clientKeyView, error) {
	return store.updateClientKeyWithLimit(id, enabled, name, nil)
}

func (store *apiKeyStore) updateClientKeyWithLimit(id string, enabled *bool, name *string, dailyLimit *int) (clientKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return clientKeyView{}, err
	}
	index := store.clientKeyIndexLocked(id)
	if index < 0 {
		return clientKeyView{}, os.ErrNotExist
	}
	old := store.clientKeys[index]
	if enabled != nil {
		store.clientKeys[index].Enabled = *enabled
	}
	if name != nil {
		trimmed := strings.TrimSpace(*name)
		if trimmed == "" || len(trimmed) > 80 {
			store.clientKeys[index] = old
			return clientKeyView{}, errors.New("name must contain 1 to 80 characters")
		}
		for i, existing := range store.clientKeys {
			if i != index && strings.EqualFold(existing.Name, trimmed) {
				store.clientKeys[index] = old
				return clientKeyView{}, errors.New("a client key with this name already exists")
			}
		}
		store.clientKeys[index].Name = trimmed
	}
	if dailyLimit != nil {
		if *dailyLimit < 0 || *dailyLimit > 10_000_000 {
			store.clientKeys[index] = old
			return clientKeyView{}, errors.New("daily_request_limit must be between 0 and 10000000")
		}
		store.clientKeys[index].DailyRequestLimit = *dailyLimit
	}
	now := time.Now().UTC()
	store.clientKeys[index].UpdatedAt = now
	if err := store.saveLocked(); err != nil {
		store.clientKeys[index] = old
		return clientKeyView{}, err
	}
	return clientKeyViewOf(store.clientKeys[index], now), nil
}

func (store *apiKeyStore) deleteClientKey(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	index := store.clientKeyIndexLocked(id)
	if index < 0 {
		return os.ErrNotExist
	}
	old := append([]persistedClientKey(nil), store.clientKeys...)
	store.clientKeys = append(store.clientKeys[:index], store.clientKeys[index+1:]...)
	if err := store.saveLocked(); err != nil {
		store.clientKeys = old
		return err
	}
	return nil
}

func (store *apiKeyStore) authenticateClientKey(plain string) (string, bool) {
	res := store.authenticateClientKeyDetailed(plain)
	if !res.Authenticated || res.RateLimited {
		return "", false
	}
	return res.ID, true
}

func (store *apiKeyStore) authenticateClientKeyDetailed(plain string) clientAuthResult {
	if plain == "" {
		return clientAuthResult{}
	}
	providedDigest := sha256.Sum256([]byte(plain))
	store.mu.Lock()
	defer store.mu.Unlock()
	matched := -1
	for i := range store.clientKeys {
		record := &store.clientKeys[i]
		if !record.Enabled {
			continue
		}
		if !record.hasDigest {
			candidate, err := store.decryptClientKey(*record)
			if err != nil {
				continue
			}
			record.digest = sha256.Sum256([]byte(candidate))
			record.hasDigest = true
		}
		if subtle.ConstantTimeCompare(record.digest[:], providedDigest[:]) == 1 && matched < 0 {
			matched = i
		}
	}
	if matched < 0 {
		return clientAuthResult{}
	}
	record := &store.clientKeys[matched]
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	if record.UsageDay != day {
		record.UsageDay = day
		record.DailyRequests = 0
	}
	if record.DailyRequestLimit > 0 && record.DailyRequests >= record.DailyRequestLimit {
		return clientAuthResult{ID: record.ID, Name: record.Name, Authenticated: true, RateLimited: true}
	}
	record.Uses++
	record.DailyRequests++
	record.LastUsed = now
	_ = store.saveTelemetryLocked(now)
	return clientAuthResult{ID: record.ID, Name: record.Name, Authenticated: true}
}

func (store *apiKeyStore) recordClientUsage(id string, inputTokens, outputTokens uint64) {
	if id == "" || (inputTokens == 0 && outputTokens == 0) {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	index := store.clientKeyIndexLocked(id)
	if index < 0 {
		return
	}
	store.clientKeys[index].InputTokens += inputTokens
	store.clientKeys[index].OutputTokens += outputTokens
	_ = store.saveTelemetryLocked(time.Now().UTC())
}

func (store *apiKeyStore) hasEnabledClientKeys() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, record := range store.clientKeys {
		if record.Enabled {
			return true
		}
	}
	return false
}

func (store *apiKeyStore) clientKeyIndexLocked(id string) int {
	for i := range store.clientKeys {
		if store.clientKeys[i].ID == id {
			return i
		}
	}
	return -1
}

func clientKeyViewOf(record persistedClientKey, now time.Time) clientKeyView {
	dailyReq := record.DailyRequests
	if record.UsageDay != now.Format("2006-01-02") {
		dailyReq = 0
	}
	view := clientKeyView{
		ID: record.ID, Name: record.Name, Enabled: record.Enabled, Mask: record.Mask,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, Uses: record.Uses,
		InputTokens: record.InputTokens, OutputTokens: record.OutputTokens,
		DailyRequestLimit: record.DailyRequestLimit, DailyRequests: dailyReq,
	}
	if !record.LastUsed.IsZero() {
		lastUsed := record.LastUsed
		view.LastUsed = &lastUsed
	}
	return view
}

func (store *apiKeyStore) indexLocked(id string) int {
	for i := range store.keys {
		if store.keys[i].ID == id {
			return i
		}
	}
	return -1
}

func (store *apiKeyStore) keyViewLocked(record persistedAPIKey) apiKeyView {
	effective, providerEnabled := store.providerForKeyLocked(record)
	view := keyView(effective)
	view.ProviderBlocked = !providerEnabled
	view.ProviderID = record.ProviderID
	if i := store.providerIndexLocked(record.ProviderID); i >= 0 {
		view.ProviderName = store.providers[i].Name
		prefixes := store.effectiveProviderPrefixesLocked()
		if i < len(prefixes) {
			view.ProviderPrefix = prefixes[i]
		}
	}
	view.NetworkBlocked = !store.proxyAvailableLocked(record)
	return view
}

func keyView(record persistedAPIKey) apiKeyView {
	view := apiKeyView{
		ID: record.ID, Name: record.Name, Enabled: record.Enabled, Mask: record.Mask,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, Uses: record.Uses,
		Failures: record.Failures, LastError: record.LastError,
		Priority: record.Priority, Weight: record.Weight, Models: append([]string(nil), record.Models...),
		DailyRequestLimit: record.DailyRequestLimit, DailyRequests: record.DailyRequests,
		MonthlyBudgetUSD: record.MonthlyBudgetUSD, MonthlySpendUSD: record.MonthlySpendUSD,
		InputCostPerMillion: record.InputCostPerMillion, OutputCostPerMillion: record.OutputCostPerMillion,
		InputTokens: record.InputTokens, OutputTokens: record.OutputTokens,
		ProxyMode: record.ProxyMode, ProxyID: record.ProxyID, BaseURL: record.BaseURL, SpoofProfile: record.SpoofProfile, APIProtocol: effectiveProtocol(record.APIProtocol),
	}
	if !record.LastUsed.IsZero() {
		lastUsed := record.LastUsed
		view.LastUsed = &lastUsed
	}
	if !record.CooldownUntil.IsZero() && time.Now().Before(record.CooldownUntil) {
		cooldownUntil := record.CooldownUntil
		view.CooldownUntil = &cooldownUntil
	}
	return view
}

func normalizeKeyPolicy(record *persistedAPIKey) {
	if record.Weight < 1 {
		record.Weight = 1
	}
	if record.Weight > 100 {
		record.Weight = 100
	}
	if effectiveProtocol(record.APIProtocol) == protocolGenAI && record.BaseURL == "" && record.ProviderID == "" {
		record.BaseURL = DefaultGenAIBaseURL
	}
	record.Models = normalizeModels(record.Models)
	resetUsagePeriods(record, time.Now().UTC())
}

func validateKeyPolicy(record persistedAPIKey) error {
	if !validProxyBinding(record.ProxyMode, record.ProxyID) {
		return errors.New("invalid network proxy binding")
	}
	if !validProtocol(record.APIProtocol) {
		return errors.New("api_protocol must be responses, chat-completions, or genai")
	}
	if record.Weight < 0 || record.Weight > 100 {
		return errors.New("weight must be between 1 and 100")
	}
	if record.Priority < -1000 || record.Priority > 1000 {
		return errors.New("priority must be between -1000 and 1000")
	}
	if record.DailyRequestLimit < 0 || record.MonthlyBudgetUSD < 0 || record.InputCostPerMillion < 0 || record.OutputCostPerMillion < 0 {
		return errors.New("limits and prices cannot be negative")
	}
	if record.BaseURL != "" {
		if _, err := parseUpstreamURL(record.BaseURL); err != nil {
			return err
		}
	}
	if record.SpoofProfile != "" && record.SpoofProfile != "claude-code" && record.SpoofProfile != "codex" && record.SpoofProfile != "generic" {
		return errors.New("spoof_profile must be claude-code, codex, or generic")
	}
	return nil
}

func normalizeModels(models []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" || seen[strings.ToLower(model)] {
			continue
		}
		seen[strings.ToLower(model)] = true
		result = append(result, model)
	}
	sort.Strings(result)
	return result
}

func resetUsagePeriods(record *persistedAPIKey, now time.Time) {
	day := now.Format("2006-01-02")
	month := now.Format("2006-01")
	if record.UsageDay != day {
		record.UsageDay = day
		record.DailyRequests = 0
	}
	if record.UsageMonth != month {
		record.UsageMonth = month
		record.MonthlySpendUSD = 0
	}
}

func keyAvailable(record persistedAPIKey, excluded map[string]bool, model string, now time.Time) bool {
	if !record.Enabled || excluded[record.ID] || (!record.CooldownUntil.IsZero() && now.Before(record.CooldownUntil)) {
		return false
	}
	if record.DailyRequestLimit > 0 && record.DailyRequests >= record.DailyRequestLimit {
		return false
	}
	if record.MonthlyBudgetUSD > 0 && record.MonthlySpendUSD >= record.MonthlyBudgetUSD {
		return false
	}
	if model == "" || len(record.Models) == 0 {
		return true
	}
	for _, allowed := range record.Models {
		if allowed == "*" || strings.EqualFold(allowed, model) {
			return true
		}
	}
	return false
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "••••" + key[max(0, len(key)-2):]
	}
	prefix := key[:min(4, len(key))]
	return prefix + "••••••••" + key[len(key)-4:]
}

func randomKeyID() string {
	buffer := make([]byte, 12)
	_, _ = rand.Read(buffer)
	return "key_" + hex.EncodeToString(buffer)
}
