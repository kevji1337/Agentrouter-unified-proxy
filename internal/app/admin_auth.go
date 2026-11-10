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
	if legacyToken != "" {
		accounts = append(accounts, adminAccount{Name: "owner", Token: legacyToken, Role: "admin"})
	}
	for i := range accounts {
		accounts[i].Name = strings.TrimSpace(accounts[i].Name)
		accounts[i].Role = strings.ToLower(strings.TrimSpace(accounts[i].Role))
		if accounts[i].Name == "" || len(accounts[i].Token) < 16 || (accounts[i].Role != "admin" && accounts[i].Role != "viewer") {
			return nil, fmt.Errorf("ADMIN_ACCOUNTS_JSON account %d requires name, token >=16 chars, and role admin/viewer", i)
		}
	}
	return accounts, nil
}

func (server *proxyServer) accountForSession(session adminSession) *adminAccount {
	if !time.Now().Before(session.Expires) {
		return nil
	}
	for i := range server.cfg.AdminAccounts {
		account := &server.cfg.AdminAccounts[i]
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
		server.adminMu.Unlock()
		if ok {
			if account := server.accountForSession(session); account != nil {
				return account, nil
			}
		}
	}
	if cookie, err := r.Cookie(adminSessionCookie); err == nil {
		if account := server.keys.browserSessionAccount(cookie.Value, server.cfg.AdminAccounts); account != nil {
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
			if len(token) == len(account.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(account.Token)) == 1 {
				matched = account
			}
		}
	} else if name != "" && password != "" {
		record, ok := savedAdminPassword{}, false
		for i := range server.cfg.AdminAccounts {
			if server.cfg.AdminAccounts[i].Name != name {
				continue
			}
			if candidate, exists := server.keys.adminPassword(&server.cfg.AdminAccounts[i]); exists {
				record, ok = candidate, true
				matched = &server.cfg.AdminAccounts[i]
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
	expires := time.Now().UTC().Add(12 * time.Hour)
	password, _ := server.keys.adminPassword(account)
	session := adminSession{Account: *account, Expires: expires, PasswordVersion: password.Hash}
	server.adminMu.Lock()
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
