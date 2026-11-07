package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type requestIDContextKey struct{}

type logRing struct {
	mu    sync.Mutex
	next  uint64
	items []map[string]any
}

var adminLogRing = &logRing{items: make([]map[string]any, 0, 500)}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func newRequestID() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err == nil {
		return hex.EncodeToString(buffer)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func validRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return ""
		}
	}
	return value
}

func logEvent(level, message string, fields map[string]any) {
	record := make(map[string]any, len(fields)+3)
	record["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	record["level"] = level
	record["message"] = message
	for key, value := range fields {
		record[key] = value
	}
	adminLogRing.add(record)
	encoded, err := json.Marshal(record)
	if err != nil {
		log.Printf(`{"level":"error","message":"failed to encode log record"}`)
		return
	}
	log.Print(string(encoded))
}

func (ring *logRing) add(record map[string]any) {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	ring.next++
	copyRecord := make(map[string]any, len(record)+1)
	for key, value := range record {
		copyRecord[key] = value
	}
	copyRecord["seq"] = ring.next
	if len(ring.items) >= 500 {
		copy(ring.items, ring.items[1:])
		ring.items[len(ring.items)-1] = copyRecord
	} else {
		ring.items = append(ring.items, copyRecord)
	}
}

func (ring *logRing) recent(after uint64, limit int) []map[string]any {
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if limit < 1 || limit > 200 {
		limit = 100
	}
	result := make([]map[string]any, 0, limit)
	for _, item := range ring.items {
		seq, _ := item["seq"].(uint64)
		if seq <= after {
			continue
		}
		result = append(result, item)
		if len(result) >= limit {
			break
		}
	}
	return result
}

type proxyMetrics struct {
	requests       atomic.Uint64
	errors         atomic.Uint64
	chatRequests   atomic.Uint64
	responseReqs   atomic.Uint64
	modelRequests  atomic.Uint64
	healthRequests atomic.Uint64
	durationNS     atomic.Uint64
	activeSSE      atomic.Int64
	wafRefreshes   atomic.Uint64
	retries        atomic.Uint64
}

func (metrics *proxyMetrics) observe(path string, status int, duration time.Duration) {
	metrics.requests.Add(1)
	metrics.durationNS.Add(uint64(duration))
	if status >= 400 {
		metrics.errors.Add(1)
	}
	switch path {
	case "/v1/chat/completions":
		metrics.chatRequests.Add(1)
	case "/v1/responses":
		metrics.responseReqs.Add(1)
	case "/v1/models", "/models":
		metrics.modelRequests.Add(1)
	case "/health":
		metrics.healthRequests.Add(1)
	}
}

func (metrics *proxyMetrics) handler(cookies *cookieStore, keys *apiKeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
			return
		}
		cookiePresent, _, _, _ := cookies.status()
		cookieValue := 0
		if cookiePresent {
			cookieValue = 1
		}
		keyStatus := keys.status()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = fmt.Fprintf(w, "# HELP agentrouter_proxy_requests_total Total HTTP requests.\n")
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_requests_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_requests_total %d\n", metrics.requests.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_errors_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_errors_total %d\n", metrics.errors.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_endpoint_requests_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_endpoint_requests_total{endpoint=\"chat_completions\"} %d\n", metrics.chatRequests.Load())
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_endpoint_requests_total{endpoint=\"responses\"} %d\n", metrics.responseReqs.Load())
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_endpoint_requests_total{endpoint=\"models\"} %d\n", metrics.modelRequests.Load())
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_endpoint_requests_total{endpoint=\"health\"} %d\n", metrics.healthRequests.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_request_duration_seconds summary\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_request_duration_seconds_sum %.6f\n", float64(metrics.durationNS.Load())/float64(time.Second))
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_request_duration_seconds_count %d\n", metrics.requests.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_active_sse gauge\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_active_sse %d\n", metrics.activeSSE.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_waf_cookie_present gauge\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_waf_cookie_present %d\n", cookieValue)
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_waf_refreshes_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_waf_refreshes_total %d\n", metrics.wafRefreshes.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_retries_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_retries_total %d\n", metrics.retries.Load())
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_api_keys gauge\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_api_keys{state=\"enabled\"} %d\n", keyStatus.Enabled)
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_api_keys{state=\"total\"} %d\n", keyStatus.Total)
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_tokens_total counter\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_tokens_total{direction=\"input\"} %d\n", keyStatus.InputTokens)
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_tokens_total{direction=\"output\"} %d\n", keyStatus.OutputTokens)
		_, _ = fmt.Fprintf(w, "# TYPE agentrouter_proxy_monthly_spend_usd gauge\n")
		_, _ = fmt.Fprintf(w, "agentrouter_proxy_monthly_spend_usd %.6f\n", keyStatus.MonthlySpendUSD)
	}
}
