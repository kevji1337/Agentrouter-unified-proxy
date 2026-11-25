package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDialContextDNSRebindingProtection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())

	parsedOrigin, _ := url.Parse("https://agentrouter.org")
	proxy := newProxyServer(config{
		UpstreamURL:            parsedOrigin,
		AllowedUpstreamOrigins: []string{"http://trusted-local.example:" + port},
	})

	cases := []struct {
		name    string
		address string
		ips     []string
		wantErr bool
	}{
		{
			name:    "rebind to AWS IMDSv1/v2 blocked",
			address: "evil.example:" + port,
			ips:     []string{"169.254.169.254"},
			wantErr: true,
		},
		{
			name:    "rebind to Alibaba IMDS blocked",
			address: "evil.example:" + port,
			ips:     []string{"100.100.100.200"},
			wantErr: true,
		},
		{
			name:    "rebind to AWS IPv6 IMDS blocked",
			address: "evil.example:" + port,
			ips:     []string{"fd00:ec2::254"},
			wantErr: true,
		},
		{
			name:    "rebind to IPv6 link-local blocked",
			address: "evil.example:" + port,
			ips:     []string{"fe80::1"},
			wantErr: true,
		},
		{
			name:    "external domain resolving to loopback 127.0.0.1 blocked",
			address: "rebind-loopback.example:" + port,
			ips:     []string{"127.0.0.1"},
			wantErr: true,
		},
		{
			name:    "dual A-record mixing public IP and metadata IP blocked",
			address: "dual.example:" + port,
			ips:     []string{"127.0.0.1", "169.254.169.254"},
			wantErr: true,
		},
		{
			name:    "localhost resolving to 127.0.0.1 allowed",
			address: "localhost:" + port,
			ips:     []string{"127.0.0.1"},
			wantErr: false,
		},
		{
			name:    "explicitly allowlisted origin resolving to 127.0.0.1 allowed",
			address: "trusted-local.example:" + port,
			ips:     []string{"127.0.0.1"},
			wantErr: false,
		},
		{
			name:    "literal 127.0.0.1 allowed when BlockPrivateUpstreamIPs is false",
			address: "127.0.0.1:" + port,
			ips:     nil,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				out := make([]netip.Addr, 0, len(tc.ips))
				for _, raw := range tc.ips {
					out = append(out, netip.MustParseAddr(raw))
				}
				return out, nil
			}
			dial := proxy.newSafeDialContext(&net.Dialer{Timeout: time.Second}, lookup)
			conn, dialErr := dial(context.Background(), "tcp", tc.address)
			if conn != nil {
				_ = conn.Close()
			}
			if tc.wantErr && !errors.Is(dialErr, errDNSRebindingBlocked) {
				t.Fatalf("expected errDNSRebindingBlocked, got %v", dialErr)
			}
			if !tc.wantErr && dialErr != nil {
				t.Fatalf("expected dial to succeed, got %v", dialErr)
			}
		})
	}

	// Verify BLOCK_PRIVATE_UPSTREAM_IPS=true blocks RFC1918 resolution for non-allowlisted domains.
	strictProxy := newProxyServer(config{
		UpstreamURL:             parsedOrigin,
		BlockPrivateUpstreamIPs: true,
	})
	strictDial := strictProxy.newSafeDialContext(&net.Dialer{Timeout: time.Second}, func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.25")}, nil
	})
	if _, err := strictDial(context.Background(), "tcp", "internal-rebind.example:"+port); !errors.Is(err, errDNSRebindingBlocked) {
		t.Fatalf("expected RFC1918 rebind to be blocked in strict mode, got %v", err)
	}
}

func TestNativeAnthropicMessagesEndpointAndBidirectionalConversion(t *testing.T) {
	// 1. Upstream Responses server receiving translated Anthropic /v1/messages (non-stream + stream).
	responsesUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			t.Errorf("unexpected Responses path: %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var reqObj map[string]any
		_ = json.Unmarshal(raw, &reqObj)
		stream, _ := reqObj["stream"].(bool)
		if !stream {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"id":"resp_anth_1",
				"model":"claude-sonnet-4-5",
				"status":"completed",
				"output":[
					{"type":"reasoning","summary":[{"type":"summary_text","text":"Analyzing file"}]},
					{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Running bash tool."}]},
					{"type":"function_call","call_id":"toolu_01","name":"bash","arguments":"{\"cmd\":\"ls\"}"}
				],
				"usage":{"input_tokens":42,"output_tokens":18}
			}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		events := []string{
			`data: {"type":"response.created","response":{"id":"resp_stream_1","model":"claude-sonnet-4-5"}}`,
			`data: {"type":"response.reasoning_summary_text.delta","delta":"Step 1"}`,
			`data: {"type":"response.output_text.delta","delta":"Hello Claude Code!"}`,
			`data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"toolu_s1","name":"read_file","arguments":""}}`,
			`data: {"type":"response.function_call_arguments.delta","output_index":1,"call_id":"toolu_s1","delta":"{\"path\":\"main.go\"}"}`,
			`data: {"type":"response.completed","response":{"id":"resp_stream_1","model":"claude-sonnet-4-5","status":"completed","output":[{"type":"function_call","call_id":"toolu_s1","name":"read_file","arguments":"{\"path\":\"main.go\"}"}],"usage":{"input_tokens":30,"output_tokens":12}}}`,
		}
		for _, ev := range events {
			_, _ = io.WriteString(w, ev+"\n\n")
			flusher.Flush()
		}
	}))
	defer responsesUpstream.Close()

	gateway := multiUpstreamProxy(t, responsesUpstream.URL)
	addUpstream(t, gateway, "ResponsesPool", responsesUpstream.URL, protocolResponses, "sk-resp-pool-secret", 10, "claude-sonnet-4-5")
	_, clientPlain, err := gateway.keys.createClientKey("claude-code-cli")
	if err != nil {
		t.Fatal(err)
	}

	anthPayload := `{
		"model":"claude-sonnet-4-5",
		"max_tokens":4096,
		"system":[{"type":"text","text":"You are a coding assistant."}],
		"thinking":{"type":"enabled","budget_tokens":8000},
		"tools":[{"name":"bash","description":"Run command","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}],
		"messages":[
			{"role":"user","content":"List files"},
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_prev","name":"bash","input":{"cmd":"pwd"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_prev","content":"/workspace"},{"type":"text","text":"Now list files"}]}
		]
	}`

	// Authenticate using Anthropic's x-api-key header with a proxy client key!
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(anthPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", clientPlain)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	rec := httptest.NewRecorder()
	gateway.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/messages status=%d body=%s", rec.Code, rec.Body.String())
	}
	var anthResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &anthResp); err != nil {
		t.Fatalf("invalid Anthropic JSON: %v", err)
	}
	if anthResp["type"] != "message" || anthResp["stop_reason"] != "tool_use" {
		t.Fatalf("unexpected Anthropic response: %s", rec.Body.String())
	}
	blocks, _ := anthResp["content"].([]any)
	if len(blocks) != 3 {
		t.Fatalf("expected thinking + text + tool_use blocks, got %d: %s", len(blocks), rec.Body.String())
	}

	// Streaming POST /v1/messages -> Responses SSE -> Anthropic SSE.
	streamPayload := `{"model":"claude-sonnet-4-5","max_tokens":1024,"stream":true,"messages":[{"role":"user","content":"stream please"}]}`
	reqStream := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(streamPayload))
	reqStream.Header.Set("X-Api-Key", clientPlain)
	recStream := httptest.NewRecorder()
	gateway.routes().ServeHTTP(recStream, reqStream)
	streamOut := recStream.Body.String()
	for _, token := range []string{"event: message_start", `"thinking_delta"`, `"Hello Claude Code!"`, `"input_json_delta"`, `"stop_reason":"tool_use"`, "event: message_stop"} {
		if !strings.Contains(streamOut, token) {
			t.Fatalf("Anthropic SSE stream missing %s:\n%s", token, streamOut)
		}
	}

	// Token counting fallback on OpenAI-backed pool.
	reqCount := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(anthPayload))
	reqCount.Header.Set("X-Api-Key", clientPlain)
	recCount := httptest.NewRecorder()
	gateway.routes().ServeHTTP(recCount, reqCount)
	if recCount.Code != http.StatusOK || !strings.Contains(recCount.Body.String(), `"input_tokens":`) {
		t.Fatalf("count_tokens failed: %d %s", recCount.Code, recCount.Body.String())
	}

	// 2. Reverse direction: OpenAI client calling /v1/chat/completions routed to native protocolAnthropic upstream!
	var sawAnthropicHeaders atomic.Bool
	anthropicUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") == "sk-ant-native-secret" && r.Header.Get("Anthropic-Version") == "2023-06-01" {
			sawAnthropicHeaders.Store(true)
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if s, _ := in["stream"].(bool); s {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_n1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100}}}\n\n")
			_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n")
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Deep thought\"}}\n\n")
			_, _ = io.WriteString(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
			_, _ = io.WriteString(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
			_, _ = io.WriteString(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Native Claude answer\"}}\n\n")
			_, _ = io.WriteString(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n")
			_, _ = io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":14}}\n\n")
			_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_n2","type":"message","role":"assistant","model":"claude-opus-4-6","content":[{"type":"thinking","thinking":"Hmm"},{"type":"text","text":"Direct reply"}],"stop_reason":"end_turn","usage":{"input_tokens":15,"output_tokens":7}}`)
	}))
	defer anthropicUpstream.Close()

	gateway2 := multiUpstreamProxy(t, anthropicUpstream.URL)
	anthKey := addUpstream(t, gateway2, "NativeClaude", anthropicUpstream.URL, protocolAnthropic, "sk-ant-native-secret", 20, "claude-opus-4-6")

	recChat := requestGateway(gateway2, "/v1/chat/completions", `{"model":"claude-opus-4-6","stream":true,"messages":[{"role":"system","content":"Be brief"},{"role":"user","content":"Hi"}]}`)
	if recChat.Code != http.StatusOK || !sawAnthropicHeaders.Load() {
		t.Fatalf("Chat->Anthropic failed: code=%d headers=%v body=%s", recChat.Code, sawAnthropicHeaders.Load(), recChat.Body.String())
	}
	for _, want := range []string{`"reasoning_content":"Deep thought"`, `"content":"Native Claude answer"`, `"prompt_tokens":125`, `"completion_tokens":14`, "data: [DONE]"} {
		if !strings.Contains(recChat.Body.String(), want) {
			t.Fatalf("Chat<-Anthropic SSE missing %s:\n%s", want, recChat.Body.String())
		}
	}
	views, _ := gateway2.keys.list()
	if views[0].ID != anthKey.ID || views[0].InputTokens != 125 || views[0].OutputTokens != 14 {
		t.Fatalf("Anthropic SSE usage (including cache_read_input_tokens) not tracked: %+v", views[0])
	}
}

// Minimal in-memory SQL driver to test PostgreSQL gateway_state CAS, multi-replica sync,
// cluster-wide audit log pagination, and audit_events retention pruning without external DB.
type mockClusterDB struct {
	mu          sync.Mutex
	payload     []byte
	revision    int64
	updatedBy   string
	auditEvents []mockAuditRow
	nextAuditID int64
}

type mockAuditRow struct {
	id         int64
	occurredAt time.Time
	fields     []byte
}

type mockDriver struct {
	clusters map[string]*mockClusterDB
	mu       sync.Mutex
}

var testSQLDriver = &mockDriver{clusters: make(map[string]*mockClusterDB)}

func init() {
	sql.Register("auditmockpg", testSQLDriver)
}

func newMockClusterSQLDB(t *testing.T, name string) (*sql.DB, *mockClusterDB) {
	t.Helper()
	cluster := &mockClusterDB{}
	testSQLDriver.mu.Lock()
	testSQLDriver.clusters[name] = cluster
	testSQLDriver.mu.Unlock()
	db, err := sql.Open("auditmockpg", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, cluster
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	d.mu.Lock()
	c := d.clusters[name]
	d.mu.Unlock()
	if c == nil {
		return nil, errors.New("cluster not found")
	}
	return &mockConn{cluster: c}, nil
}

type mockConn struct{ cluster *mockClusterDB }

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{cluster: c.cluster, query: query}, nil
}
func (c *mockConn) Close() error              { return nil }
func (c *mockConn) Begin() (driver.Tx, error) { return nil, errors.New("unused") }

type mockStmt struct {
	cluster *mockClusterDB
	query   string
}

func (s *mockStmt) Close() error  { return nil }
func (s *mockStmt) NumInput() int { return -1 }

type mockResult int64

func (r mockResult) LastInsertId() (int64, error) { return 0, nil }
func (r mockResult) RowsAffected() (int64, error) { return int64(r), nil }

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	q := strings.TrimSpace(s.query)
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()

	if strings.HasPrefix(q, "DELETE FROM audit_events") && strings.Contains(q, "interval '1 day'") {
		days := int(args[0].(int64))
		limit := int(args[1].(int64))
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		kept := make([]mockAuditRow, 0, len(s.cluster.auditEvents))
		var deleted int64
		for _, row := range s.cluster.auditEvents {
			if row.occurredAt.Before(cutoff) && int(deleted) < limit {
				deleted++
				continue
			}
			kept = append(kept, row)
		}
		s.cluster.auditEvents = kept
		return mockResult(deleted), nil
	}
	if strings.HasPrefix(q, "INSERT INTO audit_events") {
		s.cluster.nextAuditID++
		var raw []byte
		switch v := args[2].(type) {
		case []byte:
			raw = append([]byte(nil), v...)
		case string:
			raw = []byte(v)
		}
		s.cluster.auditEvents = append(s.cluster.auditEvents, mockAuditRow{
			id:         s.cluster.nextAuditID,
			occurredAt: time.Now(),
			fields:     raw,
		})
		return mockResult(1), nil
	}
	return mockResult(0), nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	q := strings.TrimSpace(s.query)
	s.cluster.mu.Lock()
	defer s.cluster.mu.Unlock()

	switch {
	case strings.HasPrefix(q, "INSERT INTO gateway_state") && strings.Contains(q, "DO NOTHING RETURNING revision"):
		if s.cluster.revision > 0 {
			return &mockRows{cols: []string{"revision"}}, nil
		}
		s.cluster.payload = append([]byte(nil), args[0].([]byte)...)
		s.cluster.revision = 1
		s.cluster.updatedBy = fmt.Sprint(args[1])
		return &mockRows{cols: []string{"revision"}, data: [][]driver.Value{{int64(1)}}}, nil

	case strings.HasPrefix(q, "UPDATE gateway_state SET payload=$1"):
		expected := args[2].(int64)
		if s.cluster.revision != expected {
			return &mockRows{cols: []string{"revision"}}, nil
		}
		s.cluster.payload = append([]byte(nil), args[0].([]byte)...)
		s.cluster.revision++
		s.cluster.updatedBy = fmt.Sprint(args[1])
		return &mockRows{cols: []string{"revision"}, data: [][]driver.Value{{s.cluster.revision}}}, nil

	case strings.HasPrefix(q, "SELECT payload, revision FROM gateway_state"):
		if s.cluster.revision == 0 {
			return &mockRows{cols: []string{"payload", "revision"}}, nil
		}
		return &mockRows{
			cols: []string{"payload", "revision"},
			data: [][]driver.Value{{append([]byte(nil), s.cluster.payload...), s.cluster.revision}},
		}, nil

	case strings.HasPrefix(q, "SELECT revision FROM gateway_state"):
		if s.cluster.revision == 0 {
			return &mockRows{cols: []string{"revision"}}, nil
		}
		return &mockRows{cols: []string{"revision"}, data: [][]driver.Value{{s.cluster.revision}}}, nil

	case strings.HasPrefix(q, "SELECT COALESCE(MAX(id), 0) FROM audit_events"):
		var maxID int64
		for _, r := range s.cluster.auditEvents {
			if r.id > maxID {
				maxID = r.id
			}
		}
		return &mockRows{cols: []string{"max"}, data: [][]driver.Value{{maxID}}}, nil

	case strings.HasPrefix(q, "SELECT id, fields FROM audit_events ORDER BY id DESC LIMIT"):
		limit := int(args[0].(int64))
		var data [][]driver.Value
		for i := len(s.cluster.auditEvents) - 1; i >= 0 && len(data) < limit; i-- {
			r := s.cluster.auditEvents[i]
			data = append(data, []driver.Value{r.id, append([]byte(nil), r.fields...)})
		}
		return &mockRows{cols: []string{"id", "fields"}, data: data}, nil

	case strings.HasPrefix(q, "SELECT id, fields FROM audit_events WHERE id >"):
		after := args[0].(int64)
		limit := int(args[1].(int64))
		var data [][]driver.Value
		for _, r := range s.cluster.auditEvents {
			if r.id > after && len(data) < limit {
				data = append(data, []driver.Value{r.id, append([]byte(nil), r.fields...)})
			}
		}
		return &mockRows{cols: []string{"id", "fields"}, data: data}, nil
	}
	return nil, fmt.Errorf("unhandled mock SQL query: %s", q)
}

type mockRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *mockRows) Columns() []string { return r.cols }
func (r *mockRows) Close() error      { return nil }
func (r *mockRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

func TestMultiReplicaOptimisticLockingSyncAndAuditRetention(t *testing.T) {
	db, cluster := newMockClusterSQLDB(t, "cluster-scale-test")
	parsed, _ := url.Parse("https://agentrouter.org")
	secret := "shared-cluster-encryption-secret-123"

	makeReplica := func(name string) *proxyServer {
		srv := newProxyServer(config{
			UpstreamURL:        parsed,
			KeySelectionMode:   "inbound-first",
			AdminAccounts:      []adminAccount{{Name: "owner", Role: "admin", Token: "cluster-admin-token-12345"}},
			KeyStoreSecret:     secret,
			KeyStorePath:       filepath.Join(t.TempDir(), name+"-keys.json"),
			StorageBackend:     "postgres",
			AuditRetentionDays: 30,
		})
		srv.infra = &infrastructure{
			instanceID:         name,
			db:                 db,
			auditRetentionDays: 30,
			stateSyncInterval:  50 * time.Millisecond,
			stopCh:             make(chan struct{}),
		}
		srv.keys.setVersionedSaveHook(func(payload []byte, expectedRev uint64) (uint64, error) {
			return srv.infra.saveGatewayStateCAS(context.Background(), payload, expectedRev)
		}, func() {
			srv.syncStateIfBehind(context.Background())
		})
		return srv
	}

	replicaA := makeReplica("replica-a")
	replicaB := makeReplica("replica-b")

	// 1. Replica A initializes key_1 (revision 1) and Replica B syncs it.
	key1, err := replicaA.keys.add("Primary-Shared", "sk-shared-cluster-key-1", true)
	if err != nil {
		t.Fatalf("replicaA add key1: %v", err)
	}
	if replicaA.keys.revision() != 1 {
		t.Fatalf("expected revision 1 on replicaA, got %d", replicaA.keys.revision())
	}
	if !replicaB.syncStateIfBehind(context.Background()) || replicaB.keys.revision() != 1 {
		t.Fatalf("replicaB failed initial sync: rev=%d", replicaB.keys.revision())
	}

	// 2. Replica B accumulates token usage in memory while Replica A adds key_2 and switches mode via Admin API (revision 2 & 3).
	replicaB.keys.recordUsage(key1.ID, 500, 120)

	addReq := httptest.NewRequest(http.MethodPost, "/api/admin/keys", strings.NewReader(`{"name":"Secondary-From-A","key":"sk-shared-cluster-key-2","enabled":true}`))
	addReq.Header.Set("X-Admin-Token", "cluster-admin-token-12345")
	addRec := httptest.NewRecorder()
	replicaA.routes().ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("replicaA POST /api/admin/keys status=%d body=%s", addRec.Code, addRec.Body.String())
	}

	modeReq := httptest.NewRequest(http.MethodPatch, "/api/admin/settings", strings.NewReader(`{"selection_mode":"pool-only"}`))
	modeReq.Header.Set("X-Admin-Token", "cluster-admin-token-12345")
	modeRec := httptest.NewRecorder()
	replicaA.routes().ServeHTTP(modeRec, modeReq)
	if modeRec.Code != http.StatusOK {
		t.Fatalf("replicaA PATCH /api/admin/settings status=%d body=%s", modeRec.Code, modeRec.Body.String())
	}
	if replicaA.keys.revision() != 3 {
		t.Fatalf("expected revision 3 on replicaA, got %d", replicaA.keys.revision())
	}

	// 3. Stale direct CAS attempt from Replica B at old revision 1 MUST fail with errGatewayStateConflict (never overwriting Replica A!).
	_, conflictErr := replicaB.infra.saveGatewayStateCAS(context.Background(), []byte(`{}`), 1)
	if !errors.Is(conflictErr, errGatewayStateConflict) {
		t.Fatalf("expected errGatewayStateConflict on stale revision, got %v", conflictErr)
	}

	// 4. Replica B syncs from Postgres: gets Secondary-From-A + pool-only mode AND preserves its monotonic 500/120 token usage!
	if !replicaB.syncStateIfBehind(context.Background()) {
		t.Fatal("expected replicaB syncStateIfBehind to apply revision 3")
	}
	if replicaB.currentKeySelectionMode() != "pool-only" || replicaB.keys.revision() != 3 {
		t.Fatalf("replicaB state mismatch: mode=%s rev=%d", replicaB.currentKeySelectionMode(), replicaB.keys.revision())
	}
	bKeys, _ := replicaB.keys.list()
	if len(bKeys) != 2 {
		t.Fatalf("expected 2 keys on replicaB after sync, got %d", len(bKeys))
	}
	var foundUsage bool
	for _, k := range bKeys {
		if k.ID == key1.ID && k.InputTokens == 500 && k.OutputTokens == 120 {
			foundUsage = true
		}
	}
	if !foundUsage {
		t.Fatalf("monotonic token usage on replicaB was lost during remote state merge: %+v", bKeys)
	}

	// 5. Verify PostgreSQL audit_events retention pruning and cluster-wide /api/admin/logs pagination.
	cluster.mu.Lock()
	cluster.auditEvents = []mockAuditRow{
		{id: 1, occurredAt: time.Now().Add(-45 * 24 * time.Hour), fields: []byte(`{"message":"old_1","level":"info"}`)},
		{id: 2, occurredAt: time.Now().Add(-31 * 24 * time.Hour), fields: []byte(`{"message":"old_2","level":"info"}`)},
		{id: 3, occurredAt: time.Now().Add(-2 * time.Hour), fields: []byte(`{"message":"recent_1","level":"info"}`)},
		{id: 4, occurredAt: time.Now().Add(-1 * time.Minute), fields: []byte(`{"message":"recent_2","level":"warn"}`)},
	}
	cluster.nextAuditID = 4
	cluster.mu.Unlock()

	deleted, err := replicaA.infra.pruneAuditEvents(context.Background())
	if err != nil || deleted != 2 {
		t.Fatalf("expected 2 expired audit rows pruned, got deleted=%d err=%v", deleted, err)
	}

	page, ok := replicaB.infra.queryAuditPage(context.Background(), 0, 10)
	if !ok || page.Instance != "postgres-cluster" || len(page.Data) != 2 || page.NextAfter != 4 {
		t.Fatalf("unexpected cluster audit page: ok=%v page=%+v", ok, page)
	}
	incPage, ok := replicaA.infra.queryAuditPage(context.Background(), 3, 10)
	if !ok || len(incPage.Data) != 1 || incPage.Data[0]["message"] != "recent_2" {
		t.Fatalf("unexpected incremental cluster audit page: %+v", incPage)
	}
}
