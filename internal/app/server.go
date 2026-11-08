package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const maxRequestBytes = 20 << 20

type config struct {
	UpstreamURL           *url.URL
	ListenAddress         string
	Port                  int
	Profile               string
	ProxyAuthToken        string
	ResponseHeaderTimeout time.Duration
	SSEIdleTimeout        time.Duration
	WarmupInterval        time.Duration
	RetryDelay            time.Duration
	MaxRetries            int
	RetryOn5xx            bool
	MaxBodyBytes          int64
	ForceSequentialTools  bool
	StatelessResponses    bool
	AdminToken            string
	AdminAccounts         []adminAccount
	KeyStorePath          string
	KeyStoreSecret        string
	KeySelectionMode      string
	KeyFailover           bool
	KeyCooldown           time.Duration
	KeyHealthInterval     time.Duration
	DatabaseURL           string
	RedisURL              string
	StorageBackend        string
	TelegramBotToken      string
	TelegramChatID        string
	AlertCooldown         time.Duration
}

func loadConfig() (config, error) {
	if err := loadDotEnv(".env"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return config{}, fmt.Errorf("load .env: %w", err)
	}
	rawURL := envDefault("UPSTREAM_URL", "https://agentrouter.org")
	upstream, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || upstream.Host == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
		return config{}, fmt.Errorf("UPSTREAM_URL must be an absolute http(s) URL")
	}
	if upstream.RawQuery != "" || upstream.Fragment != "" {
		return config{}, fmt.Errorf("UPSTREAM_URL must not contain a query or fragment")
	}
	port, err := strconv.Atoi(envDefault("PORT", "8080"))
	if err != nil || port < 1 || port > 65535 {
		return config{}, fmt.Errorf("PORT must be between 1 and 65535")
	}
	profile := strings.ToLower(strings.TrimSpace(envDefault("SPOOF_PROFILE", "claude-code")))
	if profile == "claude" {
		profile = "claude-code"
	}
	if profile != "claude-code" && profile != "codex" {
		return config{}, fmt.Errorf("SPOOF_PROFILE must be claude-code or codex")
	}
	responseTimeout, err := envDuration("RESPONSE_HEADER_TIMEOUT", 5*time.Minute)
	if err != nil {
		return config{}, err
	}
	sseTimeout, err := envDuration("SSE_IDLE_TIMEOUT", 10*time.Minute)
	if err != nil {
		return config{}, err
	}
	warmupInterval, err := envDuration("WARMUP_INTERVAL", 3*time.Minute)
	if err != nil {
		return config{}, err
	}
	retryDelay, err := envDuration("RETRY_DELAY", time.Second)
	if err != nil {
		return config{}, err
	}
	maxRetries, err := envInt("MAX_RETRIES", 2, 0, 10)
	if err != nil {
		return config{}, err
	}
	maxBodyBytes, err := envInt64("MAX_BODY_BYTES", 20<<20, 1<<20, 1<<30)
	if err != nil {
		return config{}, err
	}
	retryOn5xx, err := strconv.ParseBool(envDefault("RETRY_ON_5XX", "false"))
	if err != nil {
		return config{}, fmt.Errorf("RETRY_ON_5XX must be true or false")
	}
	forceSequentialTools, err := strconv.ParseBool(envDefault("FORCE_SEQUENTIAL_TOOLS", "true"))
	if err != nil {
		return config{}, fmt.Errorf("FORCE_SEQUENTIAL_TOOLS must be true or false")
	}
	statelessResponses, err := strconv.ParseBool(envDefault("STATELESS_RESPONSES", "true"))
	if err != nil {
		return config{}, fmt.Errorf("STATELESS_RESPONSES must be true or false")
	}
	keySelectionMode := strings.ToLower(envDefault("KEY_SELECTION_MODE", "inbound-first"))
	if keySelectionMode != "inbound-first" && keySelectionMode != "pool-first" && keySelectionMode != "pool-only" {
		return config{}, fmt.Errorf("KEY_SELECTION_MODE must be inbound-first, pool-first, or pool-only")
	}
	keyFailover, err := strconv.ParseBool(envDefault("KEY_FAILOVER", "true"))
	if err != nil {
		return config{}, fmt.Errorf("KEY_FAILOVER must be true or false")
	}
	keyCooldown, err := envDuration("KEY_COOLDOWN", 5*time.Minute)
	if err != nil {
		return config{}, err
	}
	keyHealthInterval, err := envDuration("KEY_HEALTH_INTERVAL", 5*time.Minute)
	if err != nil {
		return config{}, err
	}
	alertCooldown, err := envDuration("ALERT_COOLDOWN", 5*time.Minute)
	if err != nil {
		return config{}, err
	}
	storageBackend := strings.ToLower(envDefault("STORAGE_BACKEND", "file"))
	if storageBackend != "file" && storageBackend != "postgres" {
		return config{}, fmt.Errorf("STORAGE_BACKEND must be file or postgres")
	}
	adminToken := strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))
	adminAccounts, err := parseAdminAccounts(os.Getenv("ADMIN_ACCOUNTS_JSON"), adminToken)
	if err != nil {
		return config{}, err
	}
	keyStoreSecret := strings.TrimSpace(os.Getenv("KEY_STORE_SECRET"))
	if keyStoreSecret == "" {
		keyStoreSecret = adminToken
	}
	return config{
		UpstreamURL: upstream, ListenAddress: envDefault("LISTEN_ADDRESS", "0.0.0.0"),
		Port: port, Profile: profile, ProxyAuthToken: strings.TrimSpace(os.Getenv("PROXY_AUTH_TOKEN")),
		ResponseHeaderTimeout: responseTimeout, SSEIdleTimeout: sseTimeout,
		WarmupInterval: warmupInterval, RetryDelay: retryDelay, MaxRetries: maxRetries,
		RetryOn5xx: retryOn5xx, MaxBodyBytes: maxBodyBytes, ForceSequentialTools: forceSequentialTools,
		StatelessResponses: statelessResponses,
		AdminToken:         adminToken, AdminAccounts: adminAccounts, KeyStorePath: envDefault("KEY_STORE_PATH", "/data/keys.json"),
		KeyStoreSecret: keyStoreSecret, KeySelectionMode: keySelectionMode, KeyFailover: keyFailover,
		KeyCooldown:       keyCooldown,
		KeyHealthInterval: keyHealthInterval,
		DatabaseURL:       strings.TrimSpace(os.Getenv("DATABASE_URL")), RedisURL: strings.TrimSpace(os.Getenv("REDIS_URL")),
		StorageBackend: storageBackend, TelegramBotToken: strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")),
		TelegramChatID: strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")), AlertCooldown: alertCooldown,
	}, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := envDefault(key, fallback.String())
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration (for example 30s or 5m)", key)
	}
	return duration, nil
}

func envInt(key string, fallback, minimum, maximum int) (int, error) {
	value, err := strconv.Atoi(envDefault(key, strconv.Itoa(fallback)))
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func envInt64(key string, fallback, minimum, maximum int64) (int64, error) {
	value, err := strconv.ParseInt(envDefault(key, strconv.FormatInt(fallback, 10)), 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func envDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

// loadDotEnv is intentionally small and dependency-free. Existing process
// environment variables win over values from the file.
func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		} else if index := strings.Index(value, " #"); index >= 0 {
			value = strings.TrimSpace(value[:index])
		}
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func spoofHeaders(profile string) http.Header {
	headers := make(http.Header)
	if profile == "generic" {
		headers.Set("User-Agent", "agentrouter-unified-proxy/3.0")
		return headers
	}
	if profile == "codex" {
		headers.Set("User-Agent", "codex-cli/0.52.0 (external, codex)")
		headers.Set("X-App", "codex")
		headers.Set("Anthropic-Version", "2023-06-01")
		headers.Set("Anthropic-Beta", "interleaved-thinking-2025-05-14")
		headers.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
		return headers
	}

	// Claude Code fingerprint. These values are proxy-owned and cannot be
	// overridden by inbound client headers.
	headers.Set("User-Agent", "claude-cli/2.1.92 (external, sdk-cli)")
	headers.Set("X-App", "cli")
	headers.Set("X-Stainless-Helper-Method", "stream")
	headers.Set("X-Stainless-Retry-Count", "0")
	headers.Set("X-Stainless-Runtime-Version", "v24.14.0")
	headers.Set("X-Stainless-Package-Version", "0.80.0")
	headers.Set("X-Stainless-Runtime", "node")
	headers.Set("X-Stainless-Lang", "js")
	headers.Set("X-Stainless-Arch", "arm64")
	headers.Set("X-Stainless-Os", "Linux")
	headers.Set("X-Stainless-Timeout", "600")
	headers.Set("Anthropic-Version", "2023-06-01")
	headers.Set("Anthropic-Beta", "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24,structured-outputs-2025-12-15,fast-mode-2026-02-01,token-efficient-tools-2026-03-28")
	headers.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	return headers
}

var allowedWafCookies = map[string]struct{}{
	"acw_tc": {}, "acw_sc__v2": {}, "acw_sc__v3": {}, "cdn_sec_tc": {},
}

type cookieStore struct {
	mu         sync.RWMutex
	cookies    map[string]string
	lastUpdate time.Time
	lastWarmup time.Time
	warmupMu   sync.Mutex
}

func newCookieStore() *cookieStore {
	return &cookieStore{cookies: make(map[string]string)}
}

func (store *cookieStore) capture(headers http.Header) int {
	setCookies := headers.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return 0
	}
	updated := 0
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, value := range setCookies {
		pair := value
		if index := strings.IndexByte(pair, ';'); index >= 0 {
			pair = pair[:index]
		}
		name, cookieValue, found := strings.Cut(pair, "=")
		name, cookieValue = strings.TrimSpace(name), strings.TrimSpace(cookieValue)
		if !found || cookieValue == "" {
			continue
		}
		if _, ok := allowedWafCookies[name]; !ok {
			continue
		}
		if store.cookies[name] != cookieValue {
			store.cookies[name] = cookieValue
			updated++
		}
	}
	if updated > 0 {
		store.lastUpdate = time.Now().UTC()
	}
	return updated
}

func (store *cookieStore) header() string {
	store.mu.RLock()
	defer store.mu.RUnlock()
	names := make([]string, 0, len(store.cookies))
	for name := range store.cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+store.cookies[name])
	}
	return strings.Join(pairs, "; ")
}

func (store *cookieStore) status() (bool, []string, time.Time, time.Time) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	names := make([]string, 0, len(store.cookies))
	for name := range store.cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	return len(names) > 0, names, store.lastUpdate, store.lastWarmup
}

func (store *cookieStore) warmup(ctx context.Context, upstream *url.URL) bool {
	store.warmupMu.Lock()
	defer store.warmupMu.Unlock()

	warmupURL := *upstream
	if warmupURL.Path == "" {
		warmupURL.Path = "/"
	}
	warmupURL.RawQuery = ""
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             http.ProxyFromEnvironment,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	backoff := []time.Duration{time.Second, 2 * time.Second}
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, warmupURL.String(), nil)
		if err != nil {
			return false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		resp, err := client.Do(req)
		if err == nil {
			count := store.capture(resp.Header)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			store.mu.Lock()
			store.lastWarmup = time.Now().UTC()
			store.mu.Unlock()
			if count > 0 || store.header() != "" {
				logEvent("info", "waf_warmup_succeeded", map[string]any{
					"status": resp.StatusCode, "captured": count,
				})
				return true
			}
		}
		if attempt < len(backoff) {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(backoff[attempt]):
			}
		}
	}
	logEvent("warn", "waf_warmup_no_cookie", nil)
	return false
}

type proxyServer struct {
	cfg           config
	cookies       *cookieStore
	client        *http.Client
	metrics       *proxyMetrics
	keys          *apiKeyStore
	routingMode   atomic.Value
	lastKeyHealth atomic.Value
	adminMu       sync.Mutex
	adminSessions map[string]adminSession
	infra         *infrastructure
}

func newProxyServer(cfg config) *proxyServer {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = maxRequestBytes
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = time.Second
	}
	if cfg.SSEIdleTimeout <= 0 {
		cfg.SSEIdleTimeout = 10 * time.Minute
	}
	if cfg.KeySelectionMode == "" {
		cfg.KeySelectionMode = "inbound-first"
	}
	if len(cfg.AdminAccounts) == 0 && cfg.AdminToken != "" {
		cfg.AdminAccounts = []adminAccount{{Name: "owner", Token: cfg.AdminToken, Role: "admin"}}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 50
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout
	transport.ForceAttemptHTTP2 = true
	server := &proxyServer{
		cfg: cfg, cookies: newCookieStore(), metrics: &proxyMetrics{},
		keys: newAPIKeyStore(cfg.KeyStorePath, cfg.KeyStoreSecret),
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		adminSessions: make(map[string]adminSession),
	}
	server.routingMode.Store(cfg.KeySelectionMode)
	if savedMode := server.keys.savedSelectionMode(); validKeySelectionMode(savedMode) {
		server.routingMode.Store(savedMode)
	}
	server.lastKeyHealth.Store(time.Time{})
	return server
}

func (server *proxyServer) currentKeySelectionMode() string {
	mode, _ := server.routingMode.Load().(string)
	if mode == "" {
		return server.cfg.KeySelectionMode
	}
	return mode
}

func (server *proxyServer) keyHealthLoop(ctx context.Context) {
	if server.cfg.KeyHealthInterval <= 0 {
		return
	}
	ticker := time.NewTicker(server.cfg.KeyHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.probeAllKeys(ctx)
		}
	}
}

func (server *proxyServer) probeAllKeys(ctx context.Context) {
	keys, err := server.keys.enabledForProbe()
	if err != nil {
		logEvent("error", "key_health_load_failed", map[string]any{"error": err.Error()})
		return
	}
	for _, key := range keys {
		if ctx.Err() != nil {
			return
		}
		status, message := server.probeAPIKey(ctx, key)
		server.keys.recordResult(key.ID, status, message, server.cfg.KeyCooldown)
	}
	now := time.Now().UTC()
	server.lastKeyHealth.Store(now)
	logEvent("info", "key_health_completed", map[string]any{"checked": len(keys)})
}

func validKeySelectionMode(mode string) bool {
	return mode == "inbound-first" || mode == "pool-first" || mode == "pool-only"
}

func (server *proxyServer) upstreamURL(path string) string {
	return server.upstreamURLFor(server.cfg.UpstreamURL, path)
}

func (server *proxyServer) upstreamURLFor(base *url.URL, path string) string {
	target := *base
	pathOnly, rawQuery, _ := strings.Cut(path, "?")
	target.Path = strings.TrimRight(target.Path, "/") + pathOnly
	target.RawPath = ""
	target.RawQuery = rawQuery
	return target.String()
}

func (server *proxyServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", server.handleAdminPage)
	mux.HandleFunc("/openapi.json", server.handleOpenAPI)
	mux.HandleFunc("/docs", server.handleAPIDocs)
	mux.HandleFunc("/api/admin/", server.handleAdminAPI)
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/metrics", server.metrics.handler(server.cookies, server.keys))
	mux.HandleFunc("/v1/models", server.handleModels)
	mux.HandleFunc("/models", server.handleModels)
	mux.HandleFunc("/v1/chat/completions", server.handleChatCompletions)
	mux.HandleFunc("/v1/responses", server.handleResponses)
	for _, path := range []string{"/v1/completions", "/v1/embeddings", "/v1/moderations", "/v1/rerank", "/v1/files", "/v1/files/", "/v1/batches", "/v1/batches/", "/v1/images/", "/v1/audio/"} {
		mux.HandleFunc(path, server.handlePassthrough)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
			return
		}
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	})
	return server.requestID(server.logging(cors(server.authenticate(mux))))
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Api-Key, X-Proxy-Token, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (server *proxyServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || r.URL.Path == "/health" || r.URL.Path == "/admin" || r.URL.Path == "/docs" || r.URL.Path == "/openapi.json" || strings.HasPrefix(r.URL.Path, "/api/admin/") {
			next.ServeHTTP(w, r)
			return
		}
		hasClientKeys := server.keys.hasEnabledClientKeys()
		if server.cfg.ProxyAuthToken == "" && !hasClientKeys {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get("X-Proxy-Token")
		staticValid := server.cfg.ProxyAuthToken != "" && len(provided) == len(server.cfg.ProxyAuthToken) &&
			subtle.ConstantTimeCompare([]byte(provided), []byte(server.cfg.ProxyAuthToken)) == 1
		bearer := ""
		if authorization := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authorization), "bearer ") {
			bearer = strings.TrimSpace(authorization[7:])
		}
		_, clientValid := server.keys.authenticateClientKey(bearer)
		if !staticValid && !clientValid {
			writeError(w, http.StatusUnauthorized, "proxy_auth_required", "missing or invalid proxy client API key")
			return
		}
		if clientValid {
			clone := r.Clone(r.Context())
			clone.Header = r.Header.Clone()
			clone.Header.Del("Authorization") // never forward proxy client credentials upstream
			r = clone
		}
		next.ServeHTTP(w, r)
	})
}

func (server *proxyServer) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := validRequestID(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (server *proxyServer) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		duration := time.Since(start)
		server.metrics.observe(r.URL.Path, status, duration)
		logEvent("info", "request_completed", map[string]any{
			"request_id": requestIDFromContext(r.Context()), "method": r.Method,
			"path": r.URL.Path, "status": status, "bytes": recorder.bytes,
			"duration_ms": duration.Milliseconds(), "remote": r.RemoteAddr,
		})
	})
}

func (server *proxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	present, names, updated, warmup := server.cookies.status()
	status := "ok"
	if !present {
		status = "degraded"
	}
	payload := map[string]any{
		"status": status, "upstream": server.cfg.UpstreamURL.String(),
		"spoof_profile": server.cfg.Profile, "waf_cookie": present,
		"waf_cookie_names": names, "force_sequential_tools": server.cfg.ForceSequentialTools,
		"stateless_responses": server.cfg.StatelessResponses,
		"key_pool":            server.keys.status(), "key_selection_mode": server.currentKeySelectionMode(),
		"infrastructure": server.infra.health(),
	}
	if !updated.IsZero() {
		payload["waf_cookie_updated_at"] = updated.Format(time.RFC3339)
	}
	if !warmup.IsZero() {
		payload["last_warmup_at"] = warmup.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, payload)
}

func (server *proxyServer) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	resp, err := server.doUpstream(r.Context(), r.Header, http.MethodGet, "/v1/models", nil, false)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (server *proxyServer) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	body, err := readRequestBody(w, r, server.cfg.MaxBodyBytes)
	if err != nil {
		return
	}
	if server.cfg.StatelessResponses {
		sanitized, _, sanitizeErr := sanitizeResourceBoundState(body)
		if sanitizeErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", sanitizeErr.Error())
			return
		}
		body = sanitized
	}
	obj, err := decodeObject(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	stream, _ := obj["stream"].(bool)
	resp, err := server.doUpstream(r.Context(), r.Header, http.MethodPost, "/v1/responses", body, stream)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if isEventStream(resp.Header) || stream {
		server.metrics.activeSSE.Add(1)
		defer server.metrics.activeSSE.Add(-1)
		streamCopy(w, resp.Body)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (server *proxyServer) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	body, err := readRequestBody(w, r, server.cfg.MaxBodyBytes)
	if err != nil {
		return
	}
	converted, meta, err := convertChatRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if server.cfg.ForceSequentialTools {
		converted, err = enforceSequentialTools(converted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "conversion_error", err.Error())
			return
		}
		meta.ForceSequentialTools = true
	}
	meta.RequestID = requestIDFromContext(r.Context())
	resp, err := server.doUpstream(r.Context(), r.Header, http.MethodPost, "/v1/responses", converted, meta.Stream)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}

	if meta.Stream {
		server.metrics.activeSSE.Add(1)
		defer server.metrics.activeSSE.Add(-1)
		if isEventStream(resp.Header) {
			if err := convertResponsesSSE(w, resp.Body, meta); err != nil {
				logEvent("error", "sse_conversion_failed", map[string]any{
					"request_id": requestIDFromContext(r.Context()), "error": err.Error(),
				})
			}
			return
		}
		// Some compatible upstreams answer JSON even when stream=true.
		raw, err := io.ReadAll(io.LimitReader(resp.Body, server.cfg.MaxBodyBytes+1))
		if err != nil || int64(len(raw)) > server.cfg.MaxBodyBytes {
			writeError(w, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
			return
		}
		chat, err := convertResponsesResponse(raw, meta.Model)
		if err != nil {
			writeError(w, http.StatusBadGateway, "conversion_error", err.Error())
			return
		}
		writeSyntheticChatStream(w, chat, meta.IncludeUsage)
		return
	}

	if isEventStream(resp.Header) {
		writeError(w, http.StatusBadGateway, "upstream_error", "upstream returned SSE for a non-stream request")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, server.cfg.MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
		return
	}
	if int64(len(raw)) > server.cfg.MaxBodyBytes {
		writeError(w, http.StatusBadGateway, "upstream_error", "upstream response exceeds configured limit")
		return
	}
	chat, err := convertResponsesResponse(raw, meta.Model)
	if err != nil {
		writeError(w, http.StatusBadGateway, "conversion_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chat)
}

func (server *proxyServer) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body []byte
	var err error
	if r.Method != http.MethodGet && r.Method != http.MethodDelete && r.Body != nil {
		body, err = readRequestBody(w, r, server.cfg.MaxBodyBytes)
		if err != nil {
			return
		}
	}
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	resp, err := server.doUpstream(r.Context(), r.Header, r.Method, path, body, false)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if isEventStream(resp.Header) {
		streamCopy(w, resp.Body)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func readRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	defer r.Body.Close()
	reader := http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request exceeds configured limit")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		}
		return nil, err
	}
	return body, nil
}

func (server *proxyServer) warmup(ctx context.Context) bool {
	ok := server.cookies.warmup(ctx, server.cfg.UpstreamURL)
	if ok {
		server.metrics.wafRefreshes.Add(1)
	}
	return ok
}

func (server *proxyServer) doUpstream(ctx context.Context, inbound http.Header, method, path string, body []byte, stream bool) (*http.Response, error) {
	retries := 0
	wafRetried := false
	resourceRetried := false
	excludedKeys := make(map[string]bool)
	model := modelFromRequestBody(body)
	authHeader, selectedKey, err := server.selectAuthorization(inbound.Get("Authorization"), excludedKeys, model)
	if err != nil {
		if errors.Is(err, errNoEnabledAPIKeys) {
			logEvent("error", "no_available_api_keys", map[string]any{"model": model})
		}
		return nil, err
	}
	for {
		var requestBody io.Reader
		if body != nil {
			requestBody = bytes.NewReader(body)
		}
		attemptCtx, cancel := context.WithCancel(ctx)
		baseURL := server.cfg.UpstreamURL
		profile := server.cfg.Profile
		if selectedKey != nil {
			if selectedKey.BaseURL != "" {
				if parsed, parseErr := url.Parse(selectedKey.BaseURL); parseErr == nil {
					baseURL = parsed
				}
			}
			if selectedKey.SpoofProfile != "" {
				profile = selectedKey.SpoofProfile
			}
		}
		req, err := http.NewRequestWithContext(attemptCtx, method, server.upstreamURLFor(baseURL, path), requestBody)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header = spoofHeaders(profile)
		if body != nil {
			contentType := inbound.Get("Content-Type")
			if contentType == "" {
				contentType = "application/json"
			}
			req.Header.Set("Content-Type", contentType)
		}
		if stream {
			req.Header.Set("Accept", "text/event-stream")
		} else {
			accept := inbound.Get("Accept")
			if accept == "" {
				accept = "application/json"
			}
			req.Header.Set("Accept", accept)
		}
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		if key := inbound.Get("X-Api-Key"); key != "" {
			req.Header.Set("X-Api-Key", key)
		}
		if requestID := requestIDFromContext(ctx); requestID != "" {
			req.Header.Set("X-Request-ID", requestID)
		}
		if cookie := server.cookies.header(); cookie != "" && baseURL.Host == server.cfg.UpstreamURL.Host {
			req.Header.Set("Cookie", cookie)
		}

		resp, err := server.client.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if retries < server.cfg.MaxRetries {
				retries++
				server.metrics.retries.Add(1)
				logEvent("warn", "upstream_transport_retry", map[string]any{
					"request_id": requestIDFromContext(ctx), "attempt": retries,
					"max_retries": server.cfg.MaxRetries, "error": err.Error(),
				})
				if !sleepContext(ctx, server.cfg.RetryDelay*time.Duration(1<<(retries-1))) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}
		resp.Body = newIdleTimeoutBody(resp.Body, cancel, server.cfg.SSEIdleTimeout)
		server.cookies.capture(resp.Header)
		if !wafRetried && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusMethodNotAllowed) {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			if isWafBlock(resp.StatusCode, raw) {
				wafRetried = true
				server.metrics.retries.Add(1)
				logEvent("warn", "waf_block_retry", map[string]any{
					"request_id": requestIDFromContext(ctx), "status": resp.StatusCode,
				})
				server.warmup(ctx)
				continue
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if !resourceRetried && resp.StatusCode == http.StatusBadRequest && body != nil {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			if isForeignAzureResourceError(resp.StatusCode, raw) {
				sanitized, changed, sanitizeErr := sanitizeResourceBoundState(body)
				if sanitizeErr != nil {
					return nil, sanitizeErr
				}
				if changed {
					body = sanitized
					resourceRetried = true
					server.metrics.retries.Add(1)
					logEvent("warn", "azure_resource_state_retry", map[string]any{
						"request_id": requestIDFromContext(ctx),
					})
					continue
				}
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if selectedKey != nil && server.cfg.KeyFailover &&
			(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusPaymentRequired || resp.StatusCode == http.StatusTooManyRequests) {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			failedKeyID := selectedKey.ID
			server.keys.recordResult(failedKeyID, resp.StatusCode, http.StatusText(resp.StatusCode), server.cfg.KeyCooldown)
			excludedKeys[failedKeyID] = true
			nextAuth, nextKey, selectErr := server.selectPoolAuthorization(excludedKeys, model)
			if selectErr == nil {
				authHeader, selectedKey = nextAuth, nextKey
				server.metrics.retries.Add(1)
				logEvent("warn", "api_key_failover", map[string]any{
					"request_id": requestIDFromContext(ctx), "status": resp.StatusCode,
					"failed_key_id": failedKeyID, "next_key_id": nextKey.ID,
				})
				continue
			}
			selectedKey = nil // failure already recorded; avoid counting it twice
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if server.cfg.RetryOn5xx && resp.StatusCode >= 500 && resp.StatusCode <= 599 && retries < server.cfg.MaxRetries {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			retries++
			server.metrics.retries.Add(1)
			logEvent("warn", "upstream_status_retry", map[string]any{
				"request_id": requestIDFromContext(ctx), "attempt": retries,
				"status": resp.StatusCode, "max_retries": server.cfg.MaxRetries,
			})
			if !sleepContext(ctx, server.cfg.RetryDelay*time.Duration(1<<(retries-1))) {
				return nil, ctx.Err()
			}
			continue
		}
		if selectedKey != nil {
			server.keys.recordResult(selectedKey.ID, resp.StatusCode, http.StatusText(resp.StatusCode), server.cfg.KeyCooldown)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				keyID := selectedKey.ID
				release := server.infra.acquireKey(ctx, keyID)
				resp.Body = newUsageTrackingBody(resp.Body, func(input, output uint64) {
					server.keys.recordUsage(keyID, input, output)
				})
				resp.Body = newReleaseBody(resp.Body, release)
			}
		}
		return resp, nil
	}
}

func (server *proxyServer) selectAuthorization(inbound string, excluded map[string]bool, model string) (string, *selectedAPIKey, error) {
	switch server.currentKeySelectionMode() {
	case "pool-only":
		return server.selectPoolAuthorization(excluded, model)
	case "pool-first":
		auth, key, err := server.selectPoolAuthorization(excluded, model)
		if err == nil {
			return auth, key, nil
		}
		if inbound != "" {
			return inbound, nil, nil
		}
		return "", nil, err
	default:
		if inbound != "" {
			return inbound, nil, nil
		}
		auth, key, err := server.selectPoolAuthorization(excluded, model)
		if errors.Is(err, errNoEnabledAPIKeys) {
			return "", nil, nil
		}
		return auth, key, err
	}
}

func (server *proxyServer) selectPoolAuthorization(excluded map[string]bool, model string) (string, *selectedAPIKey, error) {
	loads := server.infra.keyLoads(context.Background(), server.keys.allKeyIDs())
	key, err := server.keys.selectNextForModelLoads(excluded, model, loads)
	if err != nil {
		return "", nil, err
	}
	return "Bearer " + key.Key, key, nil
}

func modelFromRequestBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var request struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &request)
	return request.Model
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isWafBlock(status int, body []byte) bool {
	if status != http.StatusForbidden && status != http.StatusMethodNotAllowed {
		return false
	}
	text := string(body)
	for _, marker := range []string{"alicdn", "block_message", "renderData", "waf.js", "acw_tc"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
			"te", "trailer", "transfer-encoding", "upgrade", "content-length", "set-cookie":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	if isEventStream(src) {
		dst.Set("Cache-Control", "no-cache")
		dst.Set("X-Accel-Buffering", "no")
	}
}

func isEventStream(headers http.Header) bool {
	return strings.Contains(strings.ToLower(headers.Get("Content-Type")), "text/event-stream")
}

func streamCopy(w http.ResponseWriter, body io.Reader) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	buffer := make([]byte, 32*1024)
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{
		"type": "proxy_error", "code": code, "message": message,
	}})
}

func writeUpstreamError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoEnabledAPIKeys) {
		writeError(w, http.StatusServiceUnavailable, "no_enabled_api_keys", "no enabled API keys are available in the configured pool")
		return
	}
	writeError(w, http.StatusBadGateway, "upstream_error", err.Error())
}

func Run() {
	log.SetFlags(0)
	cfg, err := loadConfig()
	if err != nil {
		logEvent("error", "configuration_error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	infra, err := newInfrastructure(rootCtx, cfg)
	if err != nil {
		logEvent("error", "infrastructure_error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer infra.Close()
	proxy := newProxyServer(cfg)
	proxy.infra = infra
	if proxy.keys.loadErr != nil {
		logEvent("error", "key_store_load_error", map[string]any{"error": proxy.keys.loadErr.Error()})
		os.Exit(1)
	}

	if cfg.StorageBackend == "postgres" {
		state, stateErr := infra.loadGatewayState(rootCtx)
		switch {
		case stateErr == nil && len(state) > 0:
			if err := proxy.keys.importBackup(state); err != nil {
				logEvent("error", "postgres_state_import_failed", map[string]any{"error": err.Error()})
				os.Exit(1)
			}
		case errors.Is(stateErr, sql.ErrNoRows):
			if state, exportErr := proxy.keys.exportBackup(); exportErr == nil {
				_ = infra.saveGatewayState(rootCtx, state)
			}
		case stateErr != nil:
			logEvent("error", "postgres_state_load_failed", map[string]any{"error": stateErr.Error()})
			os.Exit(1)
		}
		proxy.keys.setSaveHook(func(payload []byte) error {
			return infra.saveGatewayState(context.Background(), payload)
		})
	}
	go func() {
		proxy.warmup(rootCtx)
		ticker := time.NewTicker(cfg.WarmupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				proxy.warmup(rootCtx)
			}
		}
	}()
	go proxy.keyHealthLoop(rootCtx)

	httpServer := &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)),
		Handler:           proxy.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		logEvent("info", "proxy_listening", map[string]any{
			"address": httpServer.Addr, "upstream": cfg.UpstreamURL.String(), "profile": cfg.Profile,
		})
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-rootCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logEvent("error", "shutdown_error", map[string]any{"error": err.Error()})
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logEvent("error", "server_error", map[string]any{"error": err.Error()})
			os.Exit(1)
		}
	}
}
