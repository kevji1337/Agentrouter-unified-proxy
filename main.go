package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxRequestBytes = 20 << 20

type config struct {
	UpstreamURL *url.URL
	Port        int
	Profile     string
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
	return config{UpstreamURL: upstream, Port: port, Profile: profile}, nil
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
				log.Printf("WAF warmup succeeded: status=%d captured=%d", resp.StatusCode, count)
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
	log.Printf("WAF warmup finished without a cookie")
	return false
}

type proxyServer struct {
	cfg     config
	cookies *cookieStore
	client  *http.Client
}

func newProxyServer(cfg config) *proxyServer {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 50
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Minute
	transport.ForceAttemptHTTP2 = true
	return &proxyServer{
		cfg: cfg, cookies: newCookieStore(),
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (server *proxyServer) responsesURL() string {
	target := *server.cfg.UpstreamURL
	target.Path = strings.TrimRight(target.Path, "/") + "/v1/responses"
	target.RawPath = ""
	target.RawQuery = ""
	return target.String()
}

func (server *proxyServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/v1/chat/completions", server.handleChatCompletions)
	mux.HandleFunc("/v1/responses", server.handleResponses)
	return server.logging(cors(mux))
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Api-Key")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
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
		log.Printf("%s %s status=%d bytes=%d duration=%s remote=%s",
			r.Method, r.URL.Path, status, recorder.bytes, time.Since(start).Round(time.Millisecond), r.RemoteAddr)
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
		"waf_cookie_names": names,
	}
	if !updated.IsZero() {
		payload["waf_cookie_updated_at"] = updated.Format(time.RFC3339)
	}
	if !warmup.IsZero() {
		payload["last_warmup_at"] = warmup.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, payload)
}

func (server *proxyServer) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	body, err := readRequestBody(w, r)
	if err != nil {
		return
	}
	obj, err := decodeObject(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	stream, _ := obj["stream"].(bool)
	resp, err := server.doUpstream(r.Context(), r.Header, body, stream)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if isEventStream(resp.Header) || stream {
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
	body, err := readRequestBody(w, r)
	if err != nil {
		return
	}
	converted, meta, err := convertChatRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	resp, err := server.doUpstream(r.Context(), r.Header, converted, meta.Stream)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", err.Error())
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
		if isEventStream(resp.Header) {
			if err := convertResponsesSSE(w, resp.Body, meta); err != nil {
				log.Printf("SSE conversion ended with error: %v", err)
			}
			return
		}
		// Some compatible upstreams answer JSON even when stream=true.
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes+1))
		if err != nil || len(raw) > maxRequestBytes {
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBytes+1))
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
		return
	}
	if len(raw) > maxRequestBytes {
		writeError(w, http.StatusBadGateway, "upstream_error", "upstream response exceeds 20 MiB")
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

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	reader := http.MaxBytesReader(w, r.Body, maxRequestBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request exceeds 20 MiB")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
		}
		return nil, err
	}
	return body, nil
}

func (server *proxyServer) doUpstream(ctx context.Context, inbound http.Header, body []byte, stream bool) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.responsesURL(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header = spoofHeaders(server.cfg.Profile)
		req.Header.Set("Content-Type", "application/json")
		if stream {
			req.Header.Set("Accept", "text/event-stream")
		} else {
			req.Header.Set("Accept", "application/json")
		}
		if auth := inbound.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if key := inbound.Get("X-Api-Key"); key != "" {
			req.Header.Set("X-Api-Key", key)
		}
		if cookie := server.cookies.header(); cookie != "" {
			req.Header.Set("Cookie", cookie)
		}

		resp, err := server.client.Do(req)
		if err != nil {
			return nil, err
		}
		server.cookies.capture(resp.Header)
		if attempt == 0 && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusMethodNotAllowed) {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			if isWafBlock(resp.StatusCode, raw) {
				log.Printf("WAF block detected (status=%d), refreshing cookie and retrying once", resp.StatusCode)
				server.cookies.warmup(ctx, server.cfg.UpstreamURL)
				continue
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		return resp, nil
	}
	return nil, errors.New("WAF retry exhausted")
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

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmicroseconds)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	proxy := newProxyServer(cfg)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		proxy.cookies.warmup(rootCtx, cfg.UpstreamURL)
		ticker := time.NewTicker(3 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				proxy.cookies.warmup(rootCtx, cfg.UpstreamURL)
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           proxy.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on :%d upstream=%s profile=%s", cfg.Port, cfg.UpstreamURL, cfg.Profile)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-rootCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}
}
