package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var errNoEnabledAPIKeys = errors.New("no enabled API keys in the key pool")

type persistedKeyFile struct {
	Version int               `json:"version"`
	Keys    []persistedAPIKey `json:"keys"`
}

type persistedAPIKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Mask       string    `json:"mask"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	Uses      uint64    `json:"-"`
	Failures  uint64    `json:"-"`
	LastUsed  time.Time `json:"-"`
	LastError string    `json:"-"`
}

type apiKeyView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Enabled   bool       `json:"enabled"`
	Mask      string     `json:"mask"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Uses      uint64     `json:"uses"`
	Failures  uint64     `json:"failures"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

type selectedAPIKey struct {
	ID   string
	Name string
	Key  string
}

type apiKeyStore struct {
	mu       sync.Mutex
	path     string
	aead     cipher.AEAD
	keys     []persistedAPIKey
	next     int
	loadErr  error
	readOnly bool
}

type apiKeyStoreStatus struct {
	Ready   bool   `json:"ready"`
	Error   string `json:"error,omitempty"`
	Total   int    `json:"total"`
	Enabled int    `json:"enabled"`
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
	if file.Version != 1 {
		return fmt.Errorf("unsupported key store version %d", file.Version)
	}
	for i := range file.Keys {
		if _, err := store.decrypt(file.Keys[i]); err != nil {
			return fmt.Errorf("decrypt key %q: check KEY_STORE_SECRET: %w", file.Keys[i].Name, err)
		}
	}
	store.keys = file.Keys
	return nil
}

func (store *apiKeyStore) saveLocked() error {
	if store.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("create key store directory: %w", err)
	}
	file := persistedKeyFile{Version: 1, Keys: store.keys}
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
	}
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
	for _, key := range store.keys {
		if key.Enabled {
			status.Enabled++
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
	if store.next >= len(store.keys) {
		store.next = 0
	}
	if err := store.saveLocked(); err != nil {
		store.keys = old
		return err
	}
	return nil
}

func (store *apiKeyStore) selectNext(excluded map[string]bool) (*selectedAPIKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	if len(store.keys) == 0 {
		return nil, errNoEnabledAPIKeys
	}
	for offset := 0; offset < len(store.keys); offset++ {
		index := (store.next + offset) % len(store.keys)
		record := &store.keys[index]
		if !record.Enabled || excluded[record.ID] {
			continue
		}
		plain, err := store.decrypt(*record)
		if err != nil {
			return nil, err
		}
		store.next = (index + 1) % len(store.keys)
		record.Uses++
		record.LastUsed = time.Now().UTC()
		return &selectedAPIKey{ID: record.ID, Name: record.Name, Key: plain}, nil
	}
	return nil, errNoEnabledAPIKeys
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

func (store *apiKeyStore) recordResult(id string, status int, message string) {
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
	} else {
		store.keys[index].LastError = ""
	}
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
	}
	if !record.LastUsed.IsZero() {
		lastUsed := record.LastUsed
		view.LastUsed = &lastUsed
	}
	return view
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
