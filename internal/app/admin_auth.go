package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type adminAccount struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Role       string `json:"role"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

type adminAccountContextKey struct{}

type adminSession struct {
	PasswordVersion string
	Account         adminAccount
	Expires         time.Time
}

func parseAdminAccounts(raw, legacyToken string) ([]adminAccount, error) {
	var accounts []adminAccount
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &accounts); err != nil {
			return nil, fmt.Errorf("ADMIN_ACCOUNTS_JSON: %w", err)
		}
	}
	hasOwner := false
	for i := range accounts {
		if strings.TrimSpace(accounts[i].Name) == "owner" {
			hasOwner = true
			break
		}
	}
	if legacyToken != "" && !hasOwner {
		accounts = append(accounts, adminAccount{Name: "owner", Token: legacyToken, Role: "admin"})
	}
	seenNames := make(map[string]bool, len(accounts))
	for i := range accounts {
		accounts[i].Name = strings.TrimSpace(accounts[i].Name)
		accounts[i].Role = strings.ToLower(strings.TrimSpace(accounts[i].Role))
		if accounts[i].Name == "" || len(accounts[i].Token) < 16 || (accounts[i].Role != "admin" && accounts[i].Role != "viewer") {
			return nil, fmt.Errorf("ADMIN_ACCOUNTS_JSON account %d requires name, token >=16 chars, and role admin/viewer", i)
		}
		if seenNames[accounts[i].Name] {
			return nil, fmt.Errorf("ADMIN_ACCOUNTS_JSON contains duplicate account %q", accounts[i].Name)
		}
		seenNames[accounts[i].Name] = true
	}
	return accounts, nil
}

func (server *proxyServer) effectiveAdminAccounts() []adminAccount {
	envNames := make(map[string]bool, len(server.cfg.AdminAccounts))
	out := make([]adminAccount, 0, len(server.cfg.AdminAccounts)+4)
	for _, acc := range server.cfg.AdminAccounts {
		out = append(out, acc)
		envNames[strings.ToLower(acc.Name)] = true
	}
	if server.keys != nil {
		for _, acc := range server.keys.enabledAdminAccounts() {
			if !envNames[strings.ToLower(acc.Name)] {
				out = append(out, acc)
			}
		}
	}
	return out
}

func (server *proxyServer) revokeInMemorySessionsForUser(name string) {
	server.adminMu.Lock()
	var evicted []string
	for id, sess := range server.adminSessions {
		if strings.EqualFold(sess.Account.Name, name) {
			delete(server.adminSessions, id)
			evicted = append(evicted, id)
		}
	}
	server.adminMu.Unlock()
	for _, id := range evicted {
		server.infra.deleteAdminSession(context.Background(), id)
	}
}

func (server *proxyServer) accountForSession(session adminSession) *adminAccount {
	if !time.Now().Before(session.Expires) {
		return nil
	}
	accounts := server.effectiveAdminAccounts()
	for i := range accounts {
		account := &accounts[i]
		if session.Account.Name != account.Name || adminFingerprint(&session.Account) != adminFingerprint(account) {
			continue
		}
		password, _ := server.keys.adminPassword(account)
		if session.PasswordVersion != password.Hash {
			return nil
		}
		return account
	}
	return nil
}

func (server *proxyServer) authenticateAdmin(r *http.Request) (*adminAccount, error) {
	if sessionID := r.Header.Get("X-Admin-Session"); sessionID != "" {
		if session, ok := server.infra.loadAdminSession(r.Context(), sessionID); ok {
			if account := server.accountForSession(session); account != nil {
				return account, nil
			}
		}
		server.adminMu.Lock()
		session, ok := server.adminSessions[sessionID]
		if ok && !time.Now().Before(session.Expires) {
			delete(server.adminSessions, sessionID)
			ok = false
		}
		server.adminMu.Unlock()
		if ok {
			if account := server.accountForSession(session); account != nil {
				return account, nil
			}
		}
	}
	if cookie, err := r.Cookie(adminSessionCookie); err == nil {
		account := server.keys.browserSessionAccount(cookie.Value, server.effectiveAdminAccounts())
		if account == nil && server.syncStateIfBehind(r.Context()) {
			account = server.keys.browserSessionAccount(cookie.Value, server.effectiveAdminAccounts())
		}
		if account != nil {
			if !cookieMutationAllowed(r) {
				return nil, errAdminCSRF
			}
			return account, nil
		}
	}
	return server.authenticateAdminCredentials("", "", r.Header.Get("X-Admin-Token"), r.Header.Get("X-Admin-TOTP"))
}

func (server *proxyServer) authenticateAdminCredentials(name, password, token, totp string) (*adminAccount, error) {
	var matched *adminAccount
	if token != "" {
		for i := range server.cfg.AdminAccounts {
			account := &server.cfg.AdminAccounts[i]
			if len(token) == len(account.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(account.Token)) == 1 && matched == nil {
				matched = account
			}
		}
	} else if strings.TrimSpace(name) != "" && password != "" {
		trimmedName := strings.TrimSpace(name)
		record, ok := savedAdminPassword{}, false
		accounts := server.effectiveAdminAccounts()
		for i := range accounts {
			if accounts[i].Name != trimmedName && !(accounts[i].Token == "" && strings.EqualFold(accounts[i].Name, trimmedName)) {
				continue
			}
			if candidate, exists := server.keys.adminPassword(&accounts[i]); exists {
				record, ok = candidate, true
				matched = &accounts[i]
				break
			}
		}
		// Unknown accounts perform the same KDF without revealing account existence.
		if !ok {
			record = savedAdminPassword{Salt: "AAAAAAAAAAAAAAAAAAAAAA", Hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		}
		if !passwordMatches(password, record) || !ok {
			matched = nil
		}
	}

	if matched == nil {
		return nil, errors.New("invalid administrator credentials")
	}
	if matched.TOTPSecret != "" && !validTOTP(matched.TOTPSecret, totp, time.Now()) {
		return nil, errors.New("invalid administrator credentials or TOTP code")
	}
	return matched, nil
}

func (server *proxyServer) createAdminSession(account *adminAccount) (string, time.Time) {
	id := newRequestID() + newRequestID()
	now := time.Now().UTC()
	expires := now.Add(12 * time.Hour)
	password, _ := server.keys.adminPassword(account)
	session := adminSession{Account: *account, Expires: expires, PasswordVersion: password.Hash}
	server.adminMu.Lock()
	for existingID, existing := range server.adminSessions {
		if !now.Before(existing.Expires) {
			delete(server.adminSessions, existingID)
		}
	}
	for len(server.adminSessions) >= maxSavedAdminSessions {
		oldestID := ""
		var oldestExpires time.Time
		for existingID, existing := range server.adminSessions {
			if oldestID == "" || existing.Expires.Before(oldestExpires) {
				oldestID = existingID
				oldestExpires = existing.Expires
			}
		}
		if oldestID == "" {
			break
		}
		delete(server.adminSessions, oldestID)
	}
	server.adminSessions[id] = session
	server.adminMu.Unlock()
	server.infra.saveAdminSession(context.Background(), id, session)
	return id, expires
}

func withAdminAccount(ctx context.Context, account *adminAccount) context.Context {
	return context.WithValue(ctx, adminAccountContextKey{}, account)
}

func adminAccountFromContext(ctx context.Context) *adminAccount {
	account, _ := ctx.Value(adminAccountContextKey{}).(*adminAccount)
	return account
}

func validTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "="))
	if err != nil {
		return false
	}
	step := now.Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(key, uint64(step+offset)))) == 1 {
			return true
		}
	}
	return false
}

func totpCode(key []byte, counter uint64) string {
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buffer)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}
