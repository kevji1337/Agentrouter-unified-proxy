package app

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSRFMetadataBypassVectors(t *testing.T) {
	blocked := []string{
		"http://[fe80::1%25eth0]:8080",
		"http://[::ffff:169.254.169.254]:80",
		"http://100.100.100.200/latest/meta-data",
		"http://[::ffff:100.100.100.200]/latest",
		"http://[fd00:ec2::254]/latest/meta-data",
		"http://metadata.google.internal./computeMetadata/v1",
		"http://metadata.",
		"http://instance-data.",
		"http://sub.metadata.internal.",
		"http://0xa9fea9fe",
		"http://0251.0376.0251.0376",
		"http://169.254.43518",
		"http://0177.0.0.1",
		"http://0.0.0.0:8080",
		"http://[::]:8080",
		"http://224.0.0.1:8080",
		"http://[ff02::1]:8080",
	}
	for _, raw := range blocked {
		if _, err := parseUpstreamURL(raw); err == nil {
			t.Errorf("expected SSRF vector %q to be rejected", raw)
		}
	}

	allowed := []string{
		"https://agentrouter.org",
		"https://generativelanguage.googleapis.com",
		"http://localhost:11434/v1",
		"http://127.0.0.1:8080/v1",
		"http://[::1]:8080/v1",
		"http://192.168.1.50:8000/v1",
		"https://custom-gemini-proxy.internal",
		"https://0x1.api.example.com/v1",
	}
	for _, raw := range allowed {
		if _, err := parseUpstreamURL(raw); err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", raw, err)
		}
	}
}

func FuzzParseUpstreamURL(f *testing.F) {
	for _, seed := range []string{
		"https://agentrouter.org",
		"http://169.254.169.254",
		"http://[fe80::1%25eth0]:8080",
		"http://0xa9fea9fe:80",
		"http://100.100.100.200",
		"http://metadata.google.internal.",
		"http://localhost:8080/v1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := parseUpstreamURL(raw)
		if err != nil {
			return
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			t.Fatalf("unexpected scheme %q for %q", parsed.Scheme, raw)
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Fatalf("unexpected credentials/query/fragment in %q", parsed.String())
		}
	})
}

type interruptedSSEReader struct {
	payload string
	sent    bool
}

func (r *interruptedSSEReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		n := copy(p, r.payload)
		return n, nil
	}
	return 0, errUpstreamIdleTimeout
}

func TestConvertResponsesSSEInterruptedStreamDoesNotSendDone(t *testing.T) {
	reader := &interruptedSSEReader{
		payload: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Partial sentence\"}\n\n",
	}
	recorder := newFlushRecorder()
	err := convertResponsesSSE(recorder, reader, requestMeta{Model: "m", Stream: true})
	if !errors.Is(err, errUpstreamIdleTimeout) {
		t.Fatalf("expected errUpstreamIdleTimeout, got %v", err)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Partial sentence") {
		t.Fatalf("expected partial delta to be flushed, got:\n%s", body)
	}
	if strings.Contains(body, "[DONE]") || strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("interrupted stream fabricated normal completion:\n%s", body)
	}
}

func TestConvertResponsesSSEFailedEventReturnsError(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_fail","model":"m"}}`,
		``,
		`data: {"type":"response.failed","response":{"id":"resp_fail","status":"failed","error":{"message":"quota exceeded"}}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true})
	if err == nil {
		t.Fatal("expected error on response.failed SSE event")
	}
	if strings.Contains(recorder.Body.String(), "[DONE]") {
		t.Fatalf("failed SSE stream must not emit [DONE]:\n%s", recorder.Body.String())
	}
}

func TestWriteSyntheticChatStreamToolIndexAndReasoning(t *testing.T) {
	chatJSON := []byte(`{
		"id":"chatcmpl-syn",
		"object":"chat.completion",
		"created":1700000000,
		"model":"m",
		"choices":[{
			"index":0,
			"message":{
				"role":"assistant",
				"content":null,
				"reasoning_content":"step by step",
				"tool_calls":[
					{"id":"call_a","type":"function","function":{"name":"fn_a","arguments":"{}"}},
					{"id":"call_b","type":"function","function":{"name":"fn_b","arguments":"{\"x\":1}"}}
				]
			},
			"finish_reason":"tool_calls"
		}]
	}`)
	recorder := newFlushRecorder()
	writeSyntheticChatStream(recorder, chatJSON, false)
	out := recorder.Body.String()
	if !strings.Contains(out, `"reasoning_content":"step by step"`) {
		t.Fatalf("missing reasoning_content in synthetic stream:\n%s", out)
	}
	if !strings.Contains(out, `"index":0`) || !strings.Contains(out, `"index":1`) {
		t.Fatalf("missing tool_calls element index in synthetic stream:\n%s", out)
	}
}

func TestAdminAccountsOwnerTOTPSafeWithLegacyToken(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	raw := `[{"name":"owner","token":"shared-long-admin-token","role":"admin","totp_secret":"` + secret + `"},{"name":"auditor","token":"viewer-long-admin-token","role":"viewer"}]`
	accounts, err := parseAdminAccounts(raw, "shared-long-admin-token")
	if err != nil {
		t.Fatalf("parseAdminAccounts failed: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts without duplicate owner, got %d", len(accounts))
	}
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	gateway.cfg.AdminAccounts = accounts
	if _, err := gateway.authenticateAdminCredentials("", "", "shared-long-admin-token", ""); err == nil {
		t.Fatal("legacy ADMIN_TOKEN bypassed owner TOTP requirement")
	}
	validCode := totpCode([]byte("12345678901234567890"), uint64(time.Now().Unix()/30))
	if _, err := gateway.authenticateAdminCredentials("", "", "shared-long-admin-token", validCode); err != nil {
		t.Fatalf("expected valid TOTP login to succeed: %v", err)
	}

	dupJSON := `[{"name":"auditor","token":"token-one-12345678","role":"viewer"},{"name":"auditor","token":"token-two-12345678","role":"admin"}]`
	if _, err := parseAdminAccounts(dupJSON, ""); err == nil {
		t.Fatal("expected duplicate account names in ADMIN_ACCOUNTS_JSON to fail")
	}
}

func TestAdminHeaderSessionsBoundedAndPruned(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "session-cap-admin-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}

	// Insert an already-expired session and verify pruning.
	gateway.adminMu.Lock()
	gateway.adminSessions["expired-id"] = adminSession{Account: account, Expires: time.Now().Add(-time.Minute)}
	gateway.adminMu.Unlock()

	for i := 0; i < maxSavedAdminSessions+25; i++ {
		gateway.createAdminSession(&account)
	}
	gateway.adminMu.Lock()
	count := len(gateway.adminSessions)
	_, hasExpired := gateway.adminSessions["expired-id"]
	gateway.adminMu.Unlock()
	if hasExpired {
		t.Fatal("expired admin session was not pruned")
	}
	if count > maxSavedAdminSessions {
		t.Fatalf("adminSessions grew beyond cap %d: got %d", maxSavedAdminSessions, count)
	}
}

func TestAdminConcurrentPasswordLoginsQueueGracefully(t *testing.T) {
	gateway := multiUpstreamProxy(t, "https://agentrouter.org")
	account := adminAccount{Name: "owner", Role: "admin", Token: "concurrent-password-token"}
	gateway.cfg.AdminAccounts = []adminAccount{account}
	if err := gateway.keys.setAdminPassword(&account, "concurrent-valid-password-123"); err != nil {
		t.Fatal(err)
	}
	record, ok := gateway.keys.adminPassword(&account)
	if !ok {
		t.Fatal("expected saved password")
	}

	const workers = 5
	var wg sync.WaitGroup
	failures := make(chan int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if !passwordMatches("concurrent-valid-password-123", record) {
				failures <- idx
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for idx := range failures {
		t.Errorf("concurrent valid password check %d spuriously failed", idx)
	}
}
