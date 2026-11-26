package app

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var errAdminCSRF = errors.New("same-origin admin request required")

const adminSessionCookie = "arp_admin_session"
const adminPasswordIterations = 600000
const maxSavedAdminSessions = 100

var adminPasswordWork = make(chan struct{}, 2)

type savedAdminPassword struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Salt        string `json:"salt"`
	Hash        string `json:"hash"`
}

type savedAdminSession struct {
	PasswordVersion string    `json:"password_version,omitempty"`
	Hash            string    `json:"hash"`
	Name            string    `json:"name"`
	Fingerprint     string    `json:"fingerprint"`
	Expires         time.Time `json:"expires"`
}

type persistedAdminUser struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	Salt      string    `json:"salt"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type adminUserView struct {
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Enabled     bool       `json:"enabled"`
	Source      string     `json:"source"`
	HasTOTP     bool       `json:"has_totp"`
	PasswordSet bool       `json:"password_set"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func validateAdminUserName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if len(name) < 2 || len(name) > 64 {
		return "", errors.New("account name must contain 2 to 64 characters")
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		valid := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '@'
		if !valid {
			return "", errors.New("account name may contain only letters, digits, '.', '_', '-', or '@'")
		}
	}
	return name, nil
}

func hashAdminPassword(password string) (string, string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", "", errors.New("password must contain 12 to 1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	if !acquirePasswordWork(2 * time.Second) {
		return "", "", errors.New("password service busy; retry shortly")
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, adminPasswordIterations, 32)
	<-adminPasswordWork
	if err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash), nil
}

type loginAttemptWindow struct {
	Started  time.Time
	Attempts int
}

func adminFingerprint(account *adminAccount) string {
	raw, _ := json.Marshal(account)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func sessionHash(id string) string {
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:])
}

func (store *apiKeyStore) passwordVersionLocked(name, fingerprint string) (savedAdminPassword, bool) {
	for _, p := range store.adminPasswords {
		if p.Name == name && p.Fingerprint == fingerprint {
			return p, true
		}
	}
	for _, u := range store.adminUsers {
		if !u.Enabled || u.Name != name {
			continue
		}
		acc := adminAccount{Name: u.Name, Role: u.Role}
		if adminFingerprint(&acc) == fingerprint {
			return savedAdminPassword{Name: u.Name, Fingerprint: fingerprint, Salt: u.Salt, Hash: u.Hash}, true
		}
	}
	return savedAdminPassword{}, false
}

func (store *apiKeyStore) adminPassword(account *adminAccount) (savedAdminPassword, bool) {
	if account == nil {
		return savedAdminPassword{}, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.passwordVersionLocked(account.Name, adminFingerprint(account))
}

func acquirePasswordWork(timeout time.Duration) bool {
	select {
	case adminPasswordWork <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case adminPasswordWork <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func passwordMatches(password string, record savedAdminPassword) bool {
	if len(password) > 1024 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(record.Salt)
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(record.Hash)
	if err != nil || len(expected) != 32 {
		return false
	}
	if !acquirePasswordWork(2 * time.Second) {
		return false
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, adminPasswordIterations, 32)
	<-adminPasswordWork
	return err == nil && subtle.ConstantTimeCompare(hash, expected) == 1
}

func (store *apiKeyStore) setAdminPassword(account *adminAccount, password string) error {
	saltStr, hashStr, err := hashAdminPassword(password)
	if err != nil {
		return err
	}
	record := savedAdminPassword{Name: account.Name, Fingerprint: adminFingerprint(account), Salt: saltStr, Hash: hashStr}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return err
	}
	old := append([]savedAdminPassword(nil), store.adminPasswords...)
	oldUsers := append([]persistedAdminUser(nil), store.adminUsers...)
	oldSessions := append([]savedAdminSession(nil), store.savedAdminSessions...)
	updatedUIUser := false
	if account.Token == "" {
		for i := range store.adminUsers {
			if store.adminUsers[i].Name == account.Name {
				store.adminUsers[i].Salt = saltStr
				store.adminUsers[i].Hash = hashStr
				store.adminUsers[i].UpdatedAt = time.Now().UTC()
				updatedUIUser = true
				break
			}
		}
	}
	if !updatedUIUser {
		found := false
		for i, p := range store.adminPasswords {
			if p.Name == account.Name {
				store.adminPasswords[i] = record
				found = true
				break
			}
		}
		if !found {
			store.adminPasswords = append(store.adminPasswords, record)
		}
	}
	// Password changes revoke remembered sessions for this account.
	retained := make([]savedAdminSession, 0, len(store.savedAdminSessions))
	for _, s := range store.savedAdminSessions {
		if !strings.EqualFold(s.Name, account.Name) {
			retained = append(retained, s)
		}
	}
	store.savedAdminSessions = retained
	if err := store.saveLocked(); err != nil {
		store.adminPasswords = old
		store.adminUsers = oldUsers
		store.savedAdminSessions = oldSessions
		return err
	}
	return nil
}

func (store *apiKeyStore) enabledAdminAccounts() []adminAccount {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]adminAccount, 0, len(store.adminUsers))
	for _, u := range store.adminUsers {
		if u.Enabled {
			out = append(out, adminAccount{Name: u.Name, Role: u.Role})
		}
	}
	return out
}

func (store *apiKeyStore) listAdminUsers() []persistedAdminUser {
	store.mu.Lock()
	defer store.mu.Unlock()
	out := make([]persistedAdminUser, len(store.adminUsers))
	copy(out, store.adminUsers)
	return out
}

func (store *apiKeyStore) createAdminUser(name, role, password string, enabled bool, reservedNames map[string]bool) (adminUserView, error) {
	cleanName, err := validateAdminUserName(name)
	if err != nil {
		return adminUserView{}, err
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "admin" && role != "viewer" {
		return adminUserView{}, errors.New("role must be admin or viewer")
	}
	if reservedNames[strings.ToLower(cleanName)] {
		return adminUserView{}, errors.New("an account with this name already exists in environment configuration")
	}
	saltStr, hashStr, err := hashAdminPassword(password)
	if err != nil {
		return adminUserView{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return adminUserView{}, err
	}
	for _, existing := range store.adminUsers {
		if strings.EqualFold(existing.Name, cleanName) {
			return adminUserView{}, errors.New("an account with this name already exists")
		}
	}
	now := time.Now().UTC()
	record := persistedAdminUser{
		Name: cleanName, Role: role, Enabled: enabled,
		Salt: saltStr, Hash: hashStr, CreatedAt: now, UpdatedAt: now,
	}
	old := append([]persistedAdminUser(nil), store.adminUsers...)
	store.adminUsers = append(store.adminUsers, record)
	if err := store.saveLocked(); err != nil {
		store.adminUsers = old
		return adminUserView{}, err
	}
	return adminUserViewOf(record), nil
}

func (store *apiKeyStore) updateAdminUser(name string, role *string, enabled *bool, password *string) (adminUserView, error) {
	var saltStr, hashStr string
	if password != nil && *password != "" {
		var err error
		saltStr, hashStr, err = hashAdminPassword(*password)
		if err != nil {
			return adminUserView{}, err
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return adminUserView{}, err
	}
	idx := -1
	for i := range store.adminUsers {
		if strings.EqualFold(store.adminUsers[i].Name, strings.TrimSpace(name)) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return adminUserView{}, os.ErrNotExist
	}
	oldUsers := append([]persistedAdminUser(nil), store.adminUsers...)
	oldSessions := append([]savedAdminSession(nil), store.savedAdminSessions...)
	updated := store.adminUsers[idx]
	revokeSessions := false
	if role != nil {
		r := strings.ToLower(strings.TrimSpace(*role))
		if r != "admin" && r != "viewer" {
			return adminUserView{}, errors.New("role must be admin or viewer")
		}
		if updated.Role != r {
			updated.Role = r
			revokeSessions = true
		}
	}
	if enabled != nil {
		if updated.Enabled != *enabled {
			updated.Enabled = *enabled
			if !updated.Enabled {
				revokeSessions = true
			}
		}
	}
	if hashStr != "" {
		updated.Salt = saltStr
		updated.Hash = hashStr
		revokeSessions = true
	}
	updated.UpdatedAt = time.Now().UTC()
	store.adminUsers[idx] = updated
	if revokeSessions {
		kept := make([]savedAdminSession, 0, len(store.savedAdminSessions))
		for _, s := range store.savedAdminSessions {
			if !strings.EqualFold(s.Name, updated.Name) {
				kept = append(kept, s)
			}
		}
		store.savedAdminSessions = kept
	}
	if err := store.saveLocked(); err != nil {
		store.adminUsers = oldUsers
		store.savedAdminSessions = oldSessions
		return adminUserView{}, err
	}
	return adminUserViewOf(updated), nil
}

func (store *apiKeyStore) deleteAdminUser(name string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return "", err
	}
	idx := -1
	for i := range store.adminUsers {
		if strings.EqualFold(store.adminUsers[i].Name, strings.TrimSpace(name)) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", os.ErrNotExist
	}
	actualName := store.adminUsers[idx].Name
	oldUsers := append([]persistedAdminUser(nil), store.adminUsers...)
	oldSessions := append([]savedAdminSession(nil), store.savedAdminSessions...)
	store.adminUsers = append(store.adminUsers[:idx], store.adminUsers[idx+1:]...)
	kept := make([]savedAdminSession, 0, len(store.savedAdminSessions))
	for _, s := range store.savedAdminSessions {
		if !strings.EqualFold(s.Name, actualName) {
			kept = append(kept, s)
		}
	}
	store.savedAdminSessions = kept
	if err := store.saveLocked(); err != nil {
		store.adminUsers = oldUsers
		store.savedAdminSessions = oldSessions
		return "", err
	}
	return actualName, nil
}

func adminUserViewOf(u persistedAdminUser) adminUserView {
	created := u.CreatedAt
	updated := u.UpdatedAt
	return adminUserView{
		Name: u.Name, Role: u.Role, Enabled: u.Enabled,
		Source: "ui", HasTOTP: false, PasswordSet: true,
		CreatedAt: &created, UpdatedAt: &updated,
	}
}

func (store *apiKeyStore) saveBrowserSession(account *adminAccount, remember bool) (string, time.Time, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", time.Time{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(random)
	lifetime := 12 * time.Hour
	if remember {
		lifetime = 30 * 24 * time.Hour
	}
	expires := time.Now().UTC().Add(lifetime)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(); err != nil {
		return "", time.Time{}, err
	}
	old := append([]savedAdminSession(nil), store.savedAdminSessions...)
	sessions := make([]savedAdminSession, 0, len(old)+1)
	for _, s := range old {
		if time.Now().Before(s.Expires) {
			sessions = append(sessions, s)
		}
	}
	if len(sessions) >= maxSavedAdminSessions {
		sessions = sessions[len(sessions)-maxSavedAdminSessions+1:]
	}
	fp := adminFingerprint(account)
	version := ""
	if p, ok := store.passwordVersionLocked(account.Name, fp); ok {
		version = p.Hash
	}
	store.savedAdminSessions = append(sessions, savedAdminSession{PasswordVersion: version, Hash: sessionHash(id), Name: account.Name, Fingerprint: fp, Expires: expires})
	if err := store.saveLocked(); err != nil {
		store.savedAdminSessions = old
		return "", time.Time{}, err
	}
	return id, expires, nil
}

func (store *apiKeyStore) browserSessionAccount(id string, accounts []adminAccount) *adminAccount {
	if len(id) != 43 {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	hash := sessionHash(id)
	for _, s := range store.savedAdminSessions {
		if subtle.ConstantTimeCompare([]byte(s.Hash), []byte(hash)) != 1 || !time.Now().Before(s.Expires) {
			continue
		}
		for i := range accounts {
			if accounts[i].Name == s.Name && adminFingerprint(&accounts[i]) == s.Fingerprint {
				version := ""
				if p, ok := store.passwordVersionLocked(s.Name, s.Fingerprint); ok {
					version = p.Hash
				}
				if version != s.PasswordVersion {
					return nil
				}
				return &accounts[i]
			}
		}
	}
	return nil
}

func (store *apiKeyStore) revokeBrowserSession(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	old := append([]savedAdminSession(nil), store.savedAdminSessions...)
	kept := make([]savedAdminSession, 0, len(old))
	hash := sessionHash(id)
	for _, s := range old {
		if s.Hash != hash {
			kept = append(kept, s)
		}
	}
	store.savedAdminSessions = kept
	if err := store.saveLocked(); err != nil {
		store.savedAdminSessions = old
		return err
	}
	return nil
}

func validateAdminAccessFile(file persistedKeyFile) error {
	names := make(map[string]bool)
	for _, p := range file.AdminPasswords {
		salt, e1 := base64.RawStdEncoding.DecodeString(p.Salt)
		hash, e2 := base64.RawStdEncoding.DecodeString(p.Hash)
		if p.Name == "" || names[p.Name] || len(p.Fingerprint) != 64 || e1 != nil || e2 != nil || len(salt) != 16 || len(hash) != 32 {
			return errors.New("invalid saved admin password")
		}
		names[p.Name] = true
	}
	if len(file.AdminSessions) > maxSavedAdminSessions {
		return errors.New("too many saved admin sessions")
	}
	for _, s := range file.AdminSessions {
		if len(s.Hash) != 64 || len(s.Fingerprint) != 64 || s.Name == "" || s.Expires.IsZero() {
			return errors.New("invalid saved admin session")
		}
	}
	uiNames := make(map[string]bool, len(file.AdminUsers))
	for _, u := range file.AdminUsers {
		cleanName, nameErr := validateAdminUserName(u.Name)
		salt, e1 := base64.RawStdEncoding.DecodeString(u.Salt)
		hash, e2 := base64.RawStdEncoding.DecodeString(u.Hash)
		if nameErr != nil || uiNames[strings.ToLower(cleanName)] || (u.Role != "admin" && u.Role != "viewer") || e1 != nil || e2 != nil || len(salt) != 16 || len(hash) != 32 {
			return errors.New("invalid saved admin user")
		}
		uiNames[strings.ToLower(cleanName)] = true
	}
	return nil
}

// Cookies are Secure even behind Dokploy TLS termination; only direct localhost
// development may use HTTP. Never trust arbitrary forwarded-proto headers.
func browserCookie(r *http.Request, id string, expires time.Time, remember bool) *http.Cookie {
	hostname := r.Host
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}
	local := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
	cookie := &http.Cookie{Name: adminSessionCookie, Value: id, Path: "/api/admin", HttpOnly: true, Secure: r.TLS != nil || !local, SameSite: http.SameSiteStrictMode}
	if remember {
		cookie.Expires = expires
		cookie.MaxAge = int(time.Until(expires).Seconds())
	}
	if id == "" {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	return cookie
}

func (server *proxyServer) allowAdminLogin(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	server.adminMu.Lock()
	defer server.adminMu.Unlock()
	if server.loginAttempts == nil {
		server.loginAttempts = make(map[string]loginAttemptWindow)
	}
	now := time.Now()
	for key, w := range server.loginAttempts {
		if now.Sub(w.Started) > time.Minute {
			delete(server.loginAttempts, key)
		}
	}
	window := server.loginAttempts[host]
	if window.Started.IsZero() {
		window.Started = now
	}
	if window.Attempts >= 10 {
		return false
	}
	if len(server.loginAttempts) >= 256 && window.Attempts == 0 {
		return false
	}
	window.Attempts++
	server.loginAttempts[host] = window
	return true
}

func cookieMutationAllowed(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if r.Header.Get("X-Admin-CSRF") != "1" {
		return false
	}
	// The custom header blocks cross-origin forms. Also reject explicit foreign
	// origins without relying on untrusted forwarded host/scheme values.
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == "https://"+r.Host || origin == "http://"+r.Host
	}
	return !strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site")
}

func (server *proxyServer) handleAdminPassword(w http.ResponseWriter, r *http.Request, account *adminAccount) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "use POST")
		return
	}
	if !server.allowAdminLogin(r) {
		writeError(w, 429, "admin_login_rate_limited", "too many attempts")
		return
	}
	var input struct {
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
		Token           string `json:"token"`
		TOTP            string `json:"totp"`
	}
	if decodeAdminJSON(w, r, &input) != nil {
		return
	}
	verified, err := server.authenticateAdminCredentials(account.Name, input.CurrentPassword, input.Token, input.TOTP)
	if err != nil || verified.Name != account.Name {
		writeError(w, 401, "admin_reauth_required", "confirm current password or administrator token and TOTP")
		return
	}
	if err := server.keys.setAdminPassword(account, input.Password); err != nil {
		writeError(w, 400, "admin_password_invalid", err.Error())
		return
	}
	// Persistent sessions for the account were revoked. Issue a fresh remembered
	// session for this browser; header sessions become invalid via PasswordVersion.
	id, expires, err := server.keys.saveBrowserSession(account, true)
	if err != nil {
		writeError(w, 503, "admin_session_store_unavailable", "password saved; sign in again")
		return
	}
	http.SetCookie(w, browserCookie(r, id, expires, true))
	logEvent("info", "admin_password_changed", map[string]any{"admin": account.Name})
	writeJSON(w, 200, map[string]any{"password_set": true, "expires_at": expires})
}

func (server *proxyServer) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "use POST")
		return
	}
	if cookie, err := r.Cookie(adminSessionCookie); err == nil {
		if err := server.keys.revokeBrowserSession(cookie.Value); err != nil {
			writeError(w, 503, "admin_logout_failed", "could not revoke session")
			return
		}
	}
	if id := r.Header.Get("X-Admin-Session"); id != "" {
		server.adminMu.Lock()
		delete(server.adminSessions, id)
		server.adminMu.Unlock()
		server.infra.deleteAdminSession(r.Context(), id)
	}
	http.SetCookie(w, browserCookie(r, "", time.Time{}, false))
	w.WriteHeader(http.StatusNoContent)
}
