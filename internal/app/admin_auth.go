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
	Account adminAccount
	Expires time.Time
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

func (server *proxyServer) authenticateAdmin(r *http.Request) (*adminAccount, error) {
	if sessionID := r.Header.Get("X-Admin-Session"); sessionID != "" {
		server.adminMu.Lock()
		session, ok := server.adminSessions[sessionID]
		if ok && time.Now().Before(session.Expires) {
			account := session.Account
			server.adminMu.Unlock()
			return &account, nil
		}
		delete(server.adminSessions, sessionID)
		server.adminMu.Unlock()
	}
	provided := r.Header.Get("X-Admin-Token")
	for i := range server.cfg.AdminAccounts {
		account := &server.cfg.AdminAccounts[i]
		if len(provided) != len(account.Token) || subtle.ConstantTimeCompare([]byte(provided), []byte(account.Token)) != 1 {
			continue
		}
		if account.TOTPSecret != "" && !validTOTP(account.TOTPSecret, r.Header.Get("X-Admin-TOTP"), time.Now()) {
			return nil, errors.New("invalid TOTP code")
		}
		return account, nil
	}
	return nil, errors.New("invalid administrator token")
}

func (server *proxyServer) createAdminSession(account *adminAccount) (string, time.Time) {
	id := newRequestID() + newRequestID()
	expires := time.Now().UTC().Add(12 * time.Hour)
	server.adminMu.Lock()
	server.adminSessions[id] = adminSession{Account: *account, Expires: expires}
	server.adminMu.Unlock()
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
