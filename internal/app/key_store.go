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
	Version    int                  `json:"version"`
	Keys       []persistedAPIKey    `json:"keys"`
	ClientKeys []persistedClientKey `json:"client_keys,omitempty"`
	Settings   persistedKeySettings `json:"settings,omitempty"`
}

type persistedClientKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Mask       string    `json:"mask"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Uses       uint64    `json:"uses,omitempty"`
	LastUsed   time.Time `json:"last_used,omitempty"`
}

type clientKeyView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Enabled   bool       `json:"enabled"`
	Mask      string     `json:"mask"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Uses      uint64     `json:"uses"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

type persistedKeySettings struct {
	SelectionMode string `json:"selection_mode,omitempty"`
}

type persistedAPIKey struct {
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
}

type apiKeyView struct {
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
}

type apiKeyPolicy struct {
	Priority             int      `json:"priority"`
	Weight               int      `json:"weight"`
	Models               []string `json:"models"`
	DailyRequestLimit    int      `json:"daily_request_limit"`
	MonthlyBudgetUSD     float64  `json:"monthly_budget_usd"`
	InputCostPerMillion  float64  `json:"input_cost_per_million"`
	OutputCostPerMillion float64  `json:"output_cost_per_million"`
}

type selectedAPIKey struct {
	ID   string
	Name string
	Key  string
}

type apiKeyStore struct {
	mu         sync.Mutex
	path       string
	aead       cipher.AEAD
	keys       []persistedAPIKey
	clientKeys []persistedClientKey
	next       uint64
	loadErr    error
	readOnly   bool
	settings   persistedKeySettings
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
	for i := range file.Keys {
		normalizeKeyPolicy(&file.Keys[i])
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return fmt.Errorf("decrypt key %q: check KEY_STORE_SECRET: %w", file.Keys[i].Name, err)
		}
	}
	for _, clientKey := range file.ClientKeys {
		if _, err := store.decryptClientKey(clientKey); err != nil {
			return fmt.Errorf("decrypt client key %q: check KEY_STORE_SECRET: %w", clientKey.Name, err)
		}
	}
	store.keys = file.Keys
	store.clientKeys = file.ClientKeys
	store.settings = file.Settings
	return nil
}

func (store *apiKeyStore) saveLocked() error {
	if store.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create key store directory: %w", err)
	}
	file := persistedKeyFile{Version: 2, Keys: store.keys, ClientKeys: store.clientKeys, Settings: store.settings}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
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
	}
	if err := validateKeyPolicy(record); err != nil {
		return apiKeyView{}, err
	}
	normalizeKeyPolicy(&record)
	store.keys = append(store.keys, record)
	if err := store.saveLocked(); err != nil {
		store.keys = store.keys[:len(store.keys)-1]
		return apiKeyView{}, err
	}
	return keyView(record), nil
}

func (store *apiKeyStore) list() ([]apiKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	views := make([]apiKeyView, 0, len(store.keys))
	for _, record := range store.keys {
		views = append(views, keyView(record))
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
			if keyAvailable(*key, nil, "", now) {
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

func (store *apiKeyStore) update(id string, name *string, enabled *bool) (apiKeyView, error) {
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
		store.keys[index].Name = trimmed
	}
	if enabled != nil {
		store.keys[index].Enabled = *enabled
	}
	store.keys[index].UpdatedAt = time.Now().UTC()
	if err := store.saveLocked(); err != nil {
		store.keys[index] = old
		return apiKeyView{}, err
	}
	return keyView(store.keys[index]), nil
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
	old := store.keys[index]
	store.keys[index].Priority = policy.Priority
	store.keys[index].Weight = policy.Weight
	store.keys[index].Models = normalizeModels(policy.Models)
	store.keys[index].DailyRequestLimit = policy.DailyRequestLimit
	store.keys[index].MonthlyBudgetUSD = policy.MonthlyBudgetUSD
	store.keys[index].InputCostPerMillion = policy.InputCostPerMillion
	store.keys[index].OutputCostPerMillion = policy.OutputCostPerMillion
	if err := validateKeyPolicy(store.keys[index]); err != nil {
		store.keys[index] = old
		return apiKeyView{}, err
	}
	normalizeKeyPolicy(&store.keys[index])
	store.keys[index].UpdatedAt = time.Now().UTC()
	if err := store.saveLocked(); err != nil {
		store.keys[index] = old
		return apiKeyView{}, err
	}
	return keyView(store.keys[index]), nil
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
		if !keyAvailable(*record, excluded, model, now) {
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
	if err := store.saveLocked(); err != nil {
		return nil, err
	}
	return &selectedAPIKey{ID: record.ID, Name: record.Name, Key: plain}, nil
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
	return &selectedAPIKey{ID: id, Name: store.keys[index].Name, Key: plain}, nil
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
	if status >= 400 {
		store.keys[index].Failures++
		store.keys[index].LastError = message
		if cooldown > 0 && (status == http.StatusUnauthorized || status == http.StatusPaymentRequired || status == http.StatusTooManyRequests) {
			store.keys[index].CooldownUntil = time.Now().UTC().Add(cooldown)
		}
	} else {
		store.keys[index].LastError = ""
		store.keys[index].CooldownUntil = time.Time{}
	}
	_ = store.saveLocked()
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
	resetUsagePeriods(record, time.Now().UTC())
	record.InputTokens += inputTokens
	record.OutputTokens += outputTokens
	record.MonthlySpendUSD += float64(inputTokens)*record.InputCostPerMillion/1_000_000 + float64(outputTokens)*record.OutputCostPerMillion/1_000_000
	_ = store.saveLocked()
}

func (store *apiKeyStore) enabledForProbe() ([]selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	result := make([]selectedAPIKey, 0)
	for _, record := range store.keys {
		if !record.Enabled {
			continue
		}
		plain, err := store.decrypt(record)
		if err != nil {
			return nil, err
		}
		result = append(result, selectedAPIKey{ID: record.ID, Name: record.Name, Key: plain})
	}
	return result, nil
}

func (store *apiKeyStore) exportBackup() ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(persistedKeyFile{Version: 2, Keys: store.keys, ClientKeys: store.clientKeys, Settings: store.settings}, "", "  ")
}

func (store *apiKeyStore) importBackup(raw []byte) error {
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
	for i := range file.Keys {
		normalizeKeyPolicy(&file.Keys[i])
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return fmt.Errorf("backup cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
	}
	for _, clientKey := range file.ClientKeys {
		if _, err := store.decryptClientKey(clientKey); err != nil {
			return fmt.Errorf("backup client key cannot be decrypted with current KEY_STORE_SECRET: %w", err)
		}
	}
	old := store.keys
	oldClientKeys := store.clientKeys
	oldSettings := store.settings
	store.keys = file.Keys
	store.clientKeys = file.ClientKeys
	store.settings = file.Settings
	if err := store.saveLocked(); err != nil {
		store.keys = old
		store.clientKeys = oldClientKeys
		store.settings = oldSettings
		return err
	}
	return nil
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
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return clientKeyView{}, "", err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return clientKeyView{}, "", errors.New("name must contain 1 to 80 characters")
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
	record := persistedClientKey{ID: "client_" + randomKeyID()[4:], Name: name, Enabled: true, Mask: maskAPIKey(plain), Nonce: nonce, Ciphertext: ciphertext, CreatedAt: now, UpdatedAt: now}
	store.clientKeys = append(store.clientKeys, record)
	if err := store.saveLocked(); err != nil {
		store.clientKeys = store.clientKeys[:len(store.clientKeys)-1]
		return clientKeyView{}, "", err
	}
	return clientKeyViewOf(record), plain, nil
}

func (store *apiKeyStore) listClientKeys() ([]clientKeyView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	result := make([]clientKeyView, 0, len(store.clientKeys))
	for _, record := range store.clientKeys {
		result = append(result, clientKeyViewOf(record))
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
	store.mu.Lock()
	defer store.mu.Unlock()
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
			return clientKeyView{}, errors.New("name must contain 1 to 80 characters")
		}
		store.clientKeys[index].Name = trimmed
	}
	store.clientKeys[index].UpdatedAt = time.Now().UTC()
	if err := store.saveLocked(); err != nil {
		store.clientKeys[index] = old
		return clientKeyView{}, err
	}
	return clientKeyViewOf(store.clientKeys[index]), nil
}

func (store *apiKeyStore) deleteClientKey(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
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
	store.mu.Lock()
	defer store.mu.Unlock()
	matched := -1
	for i, record := range store.clientKeys {
		if !record.Enabled {
			continue
		}
		candidate, err := store.decryptClientKey(record)
		if err != nil || len(candidate) != len(plain) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(plain)) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return "", false
	}
	record := &store.clientKeys[matched]
	record.Uses++
	record.LastUsed = time.Now().UTC()
	_ = store.saveLocked()
	return record.ID, true
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

func clientKeyViewOf(record persistedClientKey) clientKeyView {
	view := clientKeyView{ID: record.ID, Name: record.Name, Enabled: record.Enabled, Mask: record.Mask, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, Uses: record.Uses}
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
	record.Models = normalizeModels(record.Models)
	resetUsagePeriods(record, time.Now().UTC())
}

func validateKeyPolicy(record persistedAPIKey) error {
	if record.Weight < 0 || record.Weight > 100 {
		return errors.New("weight must be between 1 and 100")
	}
	if record.Priority < -1000 || record.Priority > 1000 {
		return errors.New("priority must be between -1000 and 1000")
	}
	if record.DailyRequestLimit < 0 || record.MonthlyBudgetUSD < 0 || record.InputCostPerMillion < 0 || record.OutputCostPerMillion < 0 {
		return errors.New("limits and prices cannot be negative")
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
