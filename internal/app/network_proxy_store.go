package app

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var errNetworkProxyUnavailable = errors.New("assigned network proxy is unavailable; direct fallback is disabled")

type persistedNetworkProxy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	Nonce       string    `json:"nonce"`
	Ciphertext  string    `json:"ciphertext"`
	HasAuth     bool      `json:"has_auth"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastChecked time.Time `json:"last_checked,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

type networkProxyView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Enabled      bool      `json:"enabled"`
	HasAuth      bool      `json:"has_auth"`
	AssignedKeys int       `json:"assigned_keys"`
	LastChecked  time.Time `json:"last_checked,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

type networkProxyInput struct {
	Name     string  `json:"name"`
	URL      string  `json:"url"`
	Enabled  *bool   `json:"enabled"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

type proxyCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Snapshots never escape admin views or logs. Each request keeps its original
// network route even when the pool is rebalanced concurrently.
type selectedNetworkProxy struct {
	ID       string
	URL      string
	Username string
	Password string
}

func parseNetworkProxyURL(raw string) (*url.URL, error) {
	parsed, err := parseUpstreamURL(raw)
	// The URL grammar is identical except for SOCKS5 and a mandatory port.
	if strings.HasPrefix(strings.TrimSpace(raw), "socks5://") {
		parsed, err = parseUpstreamURL("http://" + strings.TrimPrefix(strings.TrimSpace(raw), "socks5://"))
		if err == nil {
			parsed.Scheme = "socks5"
		}
	}
	if err != nil || parsed.Port() == "" || parsed.Path != "" {
		return nil, errors.New("proxy url must be http://, https://, or socks5://host:port without credentials, path, query or fragment")
	}
	return parsed, nil
}

func (store *apiKeyStore) proxyIndexLocked(id string) int {
	for i := range store.proxies {
		if store.proxies[i].ID == id {
			return i
		}
	}
	return -1
}

func (store *apiKeyStore) decryptProxy(record persistedNetworkProxy) (*selectedNetworkProxy, error) {
	raw, err := store.decrypt(persistedAPIKey{Nonce: record.Nonce, Ciphertext: record.Ciphertext})
	if err != nil {
		return nil, errors.New("cannot decrypt network proxy credentials: check KEY_STORE_SECRET")
	}
	var credentials proxyCredentials
	if err := json.Unmarshal([]byte(raw), &credentials); err != nil {
		return nil, errors.New("invalid encrypted proxy credentials")
	}
	return &selectedNetworkProxy{ID: record.ID, URL: record.URL, Username: credentials.Username, Password: credentials.Password}, nil
}

func (store *apiKeyStore) listNetworkProxies() []networkProxyView {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]networkProxyView, 0, len(store.proxies))
	for _, p := range store.proxies {
		count := 0
		for _, k := range store.keys {
			if k.ProxyID == p.ID {
				count++
			}
		}
		result = append(result, networkProxyView{ID: p.ID, Name: p.Name, URL: p.URL, Enabled: p.Enabled, HasAuth: p.HasAuth, AssignedKeys: count, LastChecked: p.LastChecked, LastError: p.LastError})
	}
	return result
}

func (store *apiKeyStore) networkProxyByID(id string) (*selectedNetworkProxy, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return nil, err
	}
	i := store.proxyIndexLocked(id)
	if i < 0 {
		return nil, os.ErrNotExist
	}
	return store.decryptProxy(store.proxies[i])
}

func (store *apiKeyStore) saveNetworkProxy(id string, input networkProxyInput) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return "", err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 80 {
		return "", errors.New("proxy name must contain 1 to 80 characters")
	}
	parsed, err := parseNetworkProxyURL(input.URL)
	if err != nil {
		return "", err
	}
	i := store.proxyIndexLocked(id)
	if id != "" && i < 0 {
		return "", os.ErrNotExist
	}
	for _, p := range store.proxies {
		if p.ID != id && (strings.EqualFold(p.Name, name) || strings.EqualFold(p.URL, parsed.String())) {
			return "", errors.New("proxy name and endpoint must be unique")
		}
	}
	credentials := proxyCredentials{}
	oldProxies := append([]persistedNetworkProxy(nil), store.proxies...)
	oldKeys := append([]persistedAPIKey(nil), store.keys...)
	oldSettings := store.settings
	now := time.Now().UTC()
	record := persistedNetworkProxy{ID: "proxy_" + randomKeyID()[4:], CreatedAt: now, Enabled: true}
	if i >= 0 {
		record = store.proxies[i]
		secret, err := store.decryptProxy(record)
		if err != nil {
			return "", err
		}
		credentials = proxyCredentials{Username: secret.Username, Password: secret.Password}
	}
	if input.Username != nil {
		credentials.Username = *input.Username
	}
	if input.Password != nil {
		credentials.Password = *input.Password
	}
	if len(credentials.Username) > 255 || len(credentials.Password) > 255 || strings.ContainsAny(credentials.Username+credentials.Password, "\r\n") {
		return "", errors.New("proxy credentials must be at most 255 bytes without CR/LF")
	}
	if credentials.Password != "" && credentials.Username == "" {
		return "", errors.New("proxy username is required with password")
	}
	raw, _ := json.Marshal(credentials)
	record.Nonce, record.Ciphertext, err = store.encrypt(string(raw))
	if err != nil {
		return "", err
	}
	record.Name, record.URL, record.UpdatedAt, record.HasAuth = name, parsed.String(), now, credentials.Username != ""
	record.LastChecked, record.LastError = time.Time{}, ""
	if input.Enabled != nil {
		record.Enabled = *input.Enabled
	}
	if i >= 0 {
		store.proxies[i] = record
	} else {
		store.proxies = append(store.proxies, record)
	}
	store.settings.NetworkProxyPool = true
	store.rebalanceProxiesLocked()
	if err := store.saveLocked(); err != nil {
		store.proxies, store.keys, store.settings = oldProxies, oldKeys, oldSettings
		return "", err
	}
	return record.ID, nil
}

func (store *apiKeyStore) deleteNetworkProxy(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	i := store.proxyIndexLocked(id)
	if i < 0 {
		return os.ErrNotExist
	}
	for _, k := range store.keys {
		if k.ProxyMode == "fixed" && k.ProxyID == id {
			return errors.New("proxy is pinned to a key; change its binding before deletion")
		}
	}
	oldProxies := append([]persistedNetworkProxy(nil), store.proxies...)
	oldKeys := append([]persistedAPIKey(nil), store.keys...)
	store.proxies = append(store.proxies[:i], store.proxies[i+1:]...)
	store.rebalanceProxiesLocked()
	if err := store.saveLocked(); err != nil {
		store.proxies, store.keys = oldProxies, oldKeys
		return err
	}
	return nil
}

func (store *apiKeyStore) recordProxyProbe(id string, ok bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	i := store.proxyIndexLocked(id)
	if i < 0 {
		return
	}
	store.proxies[i].LastChecked = time.Now().UTC()
	store.proxies[i].LastError = ""
	if !ok {
		store.proxies[i].LastError = "network proxy connection failed"
	}
	_ = store.saveLocked()
}

func validProxyBinding(mode, id string) bool {
	switch mode {
	case "", "auto":
		return true
	case "direct":
		return id == ""
	case "fixed":
		return id != ""
	}
	return false
}

func (store *apiKeyStore) networkPoolConfigured() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.settings.NetworkProxyPool
}

func (store *apiKeyStore) blockedByProxy(excluded map[string]bool, model, protocol string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	now := time.Now().UTC()
	for _, k := range store.keys {
		if store.keyEligibleLocked(k, excluded, model, protocol, now) && !store.proxyAvailableLocked(k) {
			return true
		}
	}
	return false
}

func (store *apiKeyStore) proxyAvailableLocked(key persistedAPIKey) bool {
	if key.ProxyMode == "direct" {
		return true
	}
	if key.ProxyID == "" {
		return !store.settings.NetworkProxyPool && key.ProxyMode != "fixed"
	}
	i := store.proxyIndexLocked(key.ProxyID)
	return i >= 0 && store.proxies[i].Enabled
}

func (store *apiKeyStore) selectedKeyLocked(record persistedAPIKey, plain string) (*selectedAPIKey, error) {
	if !store.proxyAvailableLocked(record) {
		return nil, errNetworkProxyUnavailable
	}
	record, enabled := store.providerForKeyLocked(record)
	if !enabled {
		return nil, errNoEnabledAPIKeys
	}
	selected := &selectedAPIKey{ID: record.ID, Name: record.Name, Key: plain, BaseURL: record.BaseURL, SpoofProfile: record.SpoofProfile, APIProtocol: effectiveProtocol(record.APIProtocol), ProxyMode: record.ProxyMode}
	if record.ProxyID != "" {
		var err error
		selected.NetworkProxy, err = store.decryptProxy(store.proxies[store.proxyIndexLocked(record.ProxyID)])
		if err != nil {
			return nil, err
		}
	}
	return selected, nil
}

// Balance assignment COUNTS, including manual pins and disabled keys (which
// retain their route). Move only automatic keys and only while imbalance >1.
// Stable ordering and oldest LastUsed first avoid churn on busy credentials.
// No decisions based on transient health probes or lifetime request counters.
func (store *apiKeyStore) rebalanceProxiesLocked() {
	ids := make([]string, 0)
	counts := make(map[string]int)
	for _, p := range store.proxies {
		if p.Enabled {
			ids = append(ids, p.ID)
			counts[p.ID] = 0
		}
	}
	sort.Strings(ids)
	automatic := make([]int, 0)
	for i := range store.keys {
		k := &store.keys[i]
		if k.ProxyMode == "direct" {
			k.ProxyID = ""
			continue
		}
		if k.ProxyMode != "fixed" {
			automatic = append(automatic, i)
			if _, ok := counts[k.ProxyID]; !ok {
				k.ProxyID = ""
			}
		}
		if _, ok := counts[k.ProxyID]; ok {
			counts[k.ProxyID]++
		}
	}
	if len(ids) == 0 {
		return
	}
	sort.SliceStable(automatic, func(i, j int) bool {
		a, b := store.keys[automatic[i]], store.keys[automatic[j]]
		if !a.LastUsed.Equal(b.LastUsed) {
			return a.LastUsed.Before(b.LastUsed)
		}
		return a.ID < b.ID
	})
	least := func() string {
		best := ids[0]
		for _, id := range ids {
			if counts[id] < counts[best] {
				best = id
			}
		}
		return best
	}
	for _, i := range automatic {
		if store.keys[i].ProxyID == "" {
			id := least()
			store.keys[i].ProxyID = id
			counts[id]++
		}
	}
	for {
		target := least()
		source := ""
		candidate := -1
		for _, i := range automatic {
			id := store.keys[i].ProxyID
			if counts[id] > counts[target]+1 && (source == "" || counts[id] > counts[source]) {
				source = id
				candidate = i
			}
		}
		if candidate < 0 {
			return
		}
		store.keys[candidate].ProxyID = target
		counts[source]--
		counts[target]++
	}
}

func (store *apiKeyStore) validateProxyFile(file persistedKeyFile) error {
	seen := make(map[string]bool)
	endpoints := make(map[string]bool)
	for _, p := range file.Proxies {
		if p.ID == "" || seen[p.ID] || endpoints[strings.ToLower(p.URL)] {
			return errors.New("invalid or duplicate network proxy ID")
		}
		seen[p.ID] = true
		endpoints[strings.ToLower(p.URL)] = true
		if _, err := parseNetworkProxyURL(p.URL); err != nil {
			return err
		}
		if _, err := store.decryptProxy(p); err != nil {
			return err
		}
	}
	for _, k := range file.Keys {
		if !validProxyBinding(k.ProxyMode, k.ProxyID) {
			return errors.New("invalid key network proxy binding")
		}
		if k.ProxyID != "" && !seen[k.ProxyID] {
			return errors.New("key references missing network proxy")
		}
	}
	return nil
}
