package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

const stateSyncChannel = "agentrouter:state-sync"

var errGatewayStateConflict = errors.New("gateway state revision conflict")

type stateSyncMessage struct {
	Instance string `json:"instance"`
	Revision uint64 `json:"revision"`
}

type infrastructure struct {
	instanceID         string
	db                 *sql.DB
	redis              *redis.Client
	httpClient         *http.Client
	events             chan map[string]any
	stopCh             chan struct{}
	closeOnce          sync.Once
	wg                 sync.WaitGroup
	auditRetentionDays int
	stateSyncInterval  time.Duration
	syncMu             sync.Mutex
	telegramToken      string
	telegramChatID     string
	alertCooldown      time.Duration
	alertMu            sync.Mutex
	lastAlerts         map[string]time.Time
}

func newInfrastructure(ctx context.Context, cfg config) (*infrastructure, error) {
	syncInterval := cfg.StateSyncInterval
	if syncInterval <= 0 {
		syncInterval = 5 * time.Second
	}
	infra := &infrastructure{
		instanceID:         newRequestID(),
		events:             make(chan map[string]any, 512),
		stopCh:             make(chan struct{}),
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		auditRetentionDays: cfg.AuditRetentionDays,
		stateSyncInterval:  syncInterval,
		telegramToken:      cfg.TelegramBotToken,
		telegramChatID:     cfg.TelegramChatID,
		alertCooldown:      cfg.AlertCooldown,
		lastAlerts:         make(map[string]time.Time),
	}
	if cfg.DatabaseURL != "" {
		db, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(3)
		db.SetConnMaxLifetime(30 * time.Minute)
		db.SetConnMaxIdleTime(5 * time.Minute)
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := db.PingContext(probe); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres ping: %w", err)
		}
		infra.db = db
		migrateCtx, migrateCancel := context.WithTimeout(ctx, 30*time.Second)
		defer migrateCancel()
		if err := infra.migrate(migrateCtx); err != nil {
			_ = db.Close()
			return nil, err
		}
	} else if cfg.StorageBackend == "postgres" {
		return nil, errors.New("STORAGE_BACKEND=postgres requires DATABASE_URL")
	}
	if cfg.RedisURL != "" {
		options, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			if infra.db != nil {
				_ = infra.db.Close()
			}
			return nil, fmt.Errorf("parse REDIS_URL: %w", err)
		}
		infra.redis = redis.NewClient(options)
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := infra.redis.Ping(probe).Err(); err != nil {
			_ = infra.redis.Close()
			if infra.db != nil {
				_ = infra.db.Close()
			}
			return nil, fmt.Errorf("redis ping: %w", err)
		}
	}
	infra.wg.Add(2)
	go infra.eventWorker()
	go infra.monitor(ctx)
	setPersistentLogSink(func(record map[string]any) {
		clone := make(map[string]any, len(record))
		for k, v := range record {
			clone[k] = v
		}
		select {
		case infra.events <- clone:
		default:
		}
	})
	return infra, nil
}

func (infra *infrastructure) Close() {
	if infra == nil {
		return
	}
	infra.closeOnce.Do(func() {
		setPersistentLogSink(nil)
		if infra.stopCh != nil {
			close(infra.stopCh)
		}
		infra.wg.Wait()
		if infra.httpClient != nil {
			infra.httpClient.CloseIdleConnections()
		}
		if infra.redis != nil {
			_ = infra.redis.Close()
		}
		if infra.db != nil {
			_ = infra.db.Close()
		}
	})
}

func (infra *infrastructure) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS gateway_state (id TEXT PRIMARY KEY, payload BYTEA NOT NULL, revision BIGINT NOT NULL DEFAULT 1, updated_by TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
		`ALTER TABLE gateway_state ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1`,
		`ALTER TABLE gateway_state ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS audit_events (id BIGSERIAL PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(), level TEXT NOT NULL, message TEXT NOT NULL, fields JSONB NOT NULL DEFAULT '{}'::jsonb)`,
		`CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at DESC)`,
		`DELETE FROM audit_events WHERE message='request_completed' AND fields->>'path' IN ('/api/admin/logs','/health','/metrics')`,
	}
	for _, statement := range statements {
		if _, err := infra.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("postgres migration: %w", err)
		}
	}
	return nil
}

func (infra *infrastructure) pruneAuditEvents(ctx context.Context) (int64, error) {
	if infra == nil || infra.db == nil || infra.auditRetentionDays <= 0 {
		return 0, nil
	}
	var totalDeleted int64
	const batchSize = 5000
	for batch := 0; batch < 10; batch++ {
		pruneCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		res, err := infra.db.ExecContext(pruneCtx, `
			DELETE FROM audit_events
			WHERE id IN (
				SELECT id FROM audit_events
				WHERE occurred_at < now() - ($1 * interval '1 day')
				ORDER BY occurred_at ASC
				LIMIT $2
			)`, infra.auditRetentionDays, batchSize)
		cancel()
		if err != nil {
			return totalDeleted, err
		}
		affected, _ := res.RowsAffected()
		totalDeleted += affected
		if affected < batchSize {
			break
		}
	}
	if totalDeleted > 0 {
		logEvent("info", "audit_events_pruned", map[string]any{
			"deleted":        totalDeleted,
			"retention_days": infra.auditRetentionDays,
		})
	}
	return totalDeleted, nil
}

func (infra *infrastructure) loadGatewayState(ctx context.Context) ([]byte, error) {
	payload, _, err := infra.loadGatewayStateWithRevision(ctx)
	return payload, err
}

func (infra *infrastructure) loadGatewayStateWithRevision(ctx context.Context) ([]byte, uint64, error) {
	if infra == nil || infra.db == nil {
		return nil, 0, sql.ErrNoRows
	}
	var payload []byte
	var revision int64
	err := infra.db.QueryRowContext(ctx, `SELECT payload, revision FROM gateway_state WHERE id='key-store'`).Scan(&payload, &revision)
	if err != nil {
		return nil, 0, err
	}
	return payload, uint64(max(revision, 1)), nil
}

func (infra *infrastructure) gatewayStateRevision(ctx context.Context) (uint64, error) {
	if infra == nil || infra.db == nil {
		return 0, sql.ErrNoRows
	}
	var revision int64
	err := infra.db.QueryRowContext(ctx, `SELECT revision FROM gateway_state WHERE id='key-store'`).Scan(&revision)
	if err != nil {
		return 0, err
	}
	return uint64(max(revision, 1)), nil
}

func (infra *infrastructure) saveGatewayState(ctx context.Context, payload []byte) error {
	if infra == nil || infra.db == nil {
		return nil
	}
	_, err := infra.db.ExecContext(ctx, `INSERT INTO gateway_state(id,payload,revision,updated_by,updated_at) VALUES('key-store',$1,1,$2,now()) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, revision=gateway_state.revision+1, updated_by=excluded.updated_by, updated_at=now()`, payload, infra.instanceID)
	return err
}

func (infra *infrastructure) saveGatewayStateCAS(ctx context.Context, payload []byte, expectedRev uint64) (uint64, error) {
	if infra == nil || infra.db == nil {
		return expectedRev + 1, nil
	}
	var newRev int64
	var err error
	if expectedRev == 0 {
		err = infra.db.QueryRowContext(ctx,
			`INSERT INTO gateway_state(id,payload,revision,updated_by,updated_at) VALUES('key-store',$1,1,$2,now()) ON CONFLICT(id) DO NOTHING RETURNING revision`,
			payload, infra.instanceID,
		).Scan(&newRev)
	} else {
		err = infra.db.QueryRowContext(ctx,
			`UPDATE gateway_state SET payload=$1, revision=revision+1, updated_by=$2, updated_at=now() WHERE id='key-store' AND revision=$3 RETURNING revision`,
			payload, infra.instanceID, int64(expectedRev),
		).Scan(&newRev)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errGatewayStateConflict
	}
	if err != nil {
		return 0, err
	}
	rev := uint64(max(newRev, 1))
	infra.publishStateSync(ctx, rev)
	return rev, nil
}

func (infra *infrastructure) publishStateSync(ctx context.Context, revision uint64) {
	if infra == nil || infra.redis == nil {
		return
	}
	msg, err := json.Marshal(stateSyncMessage{Instance: infra.instanceID, Revision: revision})
	if err != nil {
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = infra.redis.Publish(pubCtx, stateSyncChannel, msg).Err()
}

func (infra *infrastructure) syncRemoteStateOnce(ctx context.Context, getLocalRev func() uint64, apply func([]byte, uint64) error) bool {
	if infra == nil || infra.db == nil || getLocalRev == nil || apply == nil {
		return false
	}
	infra.syncMu.Lock()
	defer infra.syncMu.Unlock()

	localRev := getLocalRev()
	checkCtx, cancelCheck := context.WithTimeout(ctx, 3*time.Second)
	remoteRev, err := infra.gatewayStateRevision(checkCtx)
	cancelCheck()
	if err != nil || remoteRev <= localRev {
		return false
	}

	loadCtx, cancelLoad := context.WithTimeout(ctx, 5*time.Second)
	payload, loadedRev, err := infra.loadGatewayStateWithRevision(loadCtx)
	cancelLoad()
	if err != nil || loadedRev <= localRev {
		return false
	}
	if err := apply(payload, loadedRev); err != nil {
		logEvent("warn", "gateway_state_sync_failed", map[string]any{"error": err.Error()})
		return false
	}
	return true
}

func (infra *infrastructure) startStateSync(ctx context.Context, getLocalRev func() uint64, apply func([]byte, uint64) error) {
	if infra == nil || infra.db == nil {
		return
	}
	interval := infra.stateSyncInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	infra.wg.Add(1)
	go func() {
		defer infra.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-infra.stopCh:
				return
			case <-ticker.C:
				infra.syncRemoteStateOnce(ctx, getLocalRev, apply)
			}
		}
	}()

	if infra.redis != nil {
		infra.wg.Add(1)
		go func() {
			defer infra.wg.Done()
			pubsub := infra.redis.Subscribe(ctx, stateSyncChannel)
			defer func() { _ = pubsub.Close() }()
			ch := pubsub.Channel()
			for {
				select {
				case <-ctx.Done():
					return
				case <-infra.stopCh:
					return
				case msg, ok := <-ch:
					if !ok || msg == nil {
						return
					}
					var parsed stateSyncMessage
					if json.Unmarshal([]byte(msg.Payload), &parsed) == nil {
						if parsed.Instance == infra.instanceID || parsed.Revision <= getLocalRev() {
							continue
						}
					}
					infra.syncRemoteStateOnce(ctx, getLocalRev, apply)
				}
			}
		}()
	}
}

func (infra *infrastructure) queryAuditPage(ctx context.Context, after uint64, limit int) (logPage, bool) {
	if infra == nil || infra.db == nil {
		return logPage{}, false
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var maxID int64
	if err := infra.db.QueryRowContext(queryCtx, `SELECT COALESCE(MAX(id), 0) FROM audit_events`).Scan(&maxID); err != nil {
		return logPage{}, false
	}
	const clusterInstance = "postgres-cluster"
	if maxID <= 0 {
		return logPage{Data: []map[string]any{}, Instance: clusterInstance, NextAfter: 0}, true
	}
	reset := false
	if after > uint64(maxID) {
		reset = true
		after = 0
	}
	if after == 0 {
		rows, err := infra.db.QueryContext(queryCtx, `SELECT id, fields FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
		if err != nil {
			return logPage{}, false
		}
		defer rows.Close()
		items := make([]map[string]any, 0, limit)
		var nextAfter uint64
		for rows.Next() {
			var id int64
			var raw []byte
			if err := rows.Scan(&id, &raw); err != nil {
				continue
			}
			var entry map[string]any
			if json.Unmarshal(raw, &entry) != nil || entry == nil {
				continue
			}
			seq := uint64(id)
			entry["seq"] = seq
			if seq > nextAfter {
				nextAfter = seq
			}
			items = append(items, entry)
		}
		for l, r := 0, len(items)-1; l < r; l, r = l+1, r-1 {
			items[l], items[r] = items[r], items[l]
		}
		if nextAfter == 0 {
			nextAfter = uint64(maxID)
		}
		return logPage{Data: items, Instance: clusterInstance, NextAfter: nextAfter, Reset: reset}, true
	}

	rows, err := infra.db.QueryContext(queryCtx, `SELECT id, fields FROM audit_events WHERE id > $1 ORDER BY id ASC LIMIT $2`, int64(after), limit+1)
	if err != nil {
		return logPage{}, false
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit+1)
	for rows.Next() {
		var id int64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			continue
		}
		var entry map[string]any
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			continue
		}
		entry["seq"] = uint64(id)
		items = append(items, entry)
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	nextAfter := after
	if len(items) > 0 {
		if seq, ok := items[len(items)-1]["seq"].(uint64); ok {
			nextAfter = seq
		}
	}
	return logPage{Data: items, Instance: clusterInstance, NextAfter: nextAfter, HasMore: hasMore}, true
}

func (infra *infrastructure) eventWorker() {
	defer infra.wg.Done()
	baseCtx := context.Background()
	for {
		select {
		case <-infra.stopCh:
			drainCtx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
			defer cancel()
			for {
				select {
				case event := <-infra.events:
					infra.persistEvent(drainCtx, event)
					infra.maybeAlert(drainCtx, event)
				default:
					return
				}
			}
		case event := <-infra.events:
			infra.persistEvent(baseCtx, event)
			infra.maybeAlert(baseCtx, event)
		}
	}
}

func (infra *infrastructure) persistEvent(ctx context.Context, event map[string]any) {
	if infra.db == nil {
		return
	}
	fields, _ := json.Marshal(event)
	level, _ := event["level"].(string)
	message, _ := event["message"].(string)
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _ = infra.db.ExecContext(writeCtx, `INSERT INTO audit_events(level,message,fields) VALUES($1,$2,$3::jsonb)`, level, message, fields)
}

func (infra *infrastructure) maybeAlert(ctx context.Context, event map[string]any) {
	if infra.telegramToken == "" || infra.telegramChatID == "" {
		return
	}
	if suppress, _ := event["suppress_alert"].(bool); suppress {
		return
	}
	message, _ := event["message"].(string)
	alertMessages := map[string]bool{
		"api_key_failover": true, "waf_block_retry": true, "azure_resource_state_retry": true,
		"key_health_load_failed": true, "server_error": true, "configuration_error": true,
		"no_available_api_keys": true, "postgres_unavailable": true, "redis_unavailable": true,
	}
	if !alertMessages[message] {
		return
	}
	if !infra.claimAlert(ctx, message) {
		return
	}
	text := "AgentRouter alert\nEvent: " + message
	if model, ok := event["model"]; ok && fmt.Sprint(model) != "" {
		text += "\nModel: " + fmt.Sprint(model)
	}
	if status, ok := event["status"]; ok {
		text += "\nStatus: " + fmt.Sprint(status)
	}
	if requestID, ok := event["request_id"]; ok && fmt.Sprint(requestID) != "" {
		text += "\nRequest: " + fmt.Sprint(requestID)
	}
	payload, _ := json.Marshal(map[string]any{"chat_id": infra.telegramChatID, "text": text, "disable_web_page_preview": true})
	alertCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(alertCtx, http.MethodPost, "https://api.telegram.org/bot"+infra.telegramToken+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := infra.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}
}

func (infra *infrastructure) monitor(ctx context.Context) {
	defer infra.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	retentionTicker := time.NewTicker(time.Hour)
	defer retentionTicker.Stop()

	if infra.db != nil && infra.auditRetentionDays > 0 {
		if _, err := infra.pruneAuditEvents(ctx); err != nil && ctx.Err() == nil {
			logEvent("warn", "audit_events_prune_failed", map[string]any{"error": err.Error()})
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-infra.stopCh:
			return
		case <-retentionTicker.C:
			if infra.db != nil && infra.auditRetentionDays > 0 {
				if _, err := infra.pruneAuditEvents(ctx); err != nil && ctx.Err() == nil {
					logEvent("warn", "audit_events_prune_failed", map[string]any{"error": err.Error()})
				}
			}
		case <-ticker.C:
			if infra.db != nil {
				probe, cancel := context.WithTimeout(ctx, 3*time.Second)
				err := infra.db.PingContext(probe)
				cancel()
				if err != nil {
					logEvent("error", "postgres_unavailable", map[string]any{"error": err.Error()})
				}
			}
			if infra.redis != nil {
				probe, cancel := context.WithTimeout(ctx, 3*time.Second)
				err := infra.redis.Ping(probe).Err()
				cancel()
				if err != nil {
					logEvent("error", "redis_unavailable", map[string]any{"error": err.Error()})
				}
			}
		}
	}
}

func (infra *infrastructure) claimAlert(ctx context.Context, key string) bool {
	if infra.alertCooldown <= 0 {
		return true
	}
	if infra.redis != nil {
		ok, err := infra.redis.SetNX(ctx, "agentrouter:alert:"+key, "1", infra.alertCooldown).Result()
		return err == nil && ok
	}
	infra.alertMu.Lock()
	defer infra.alertMu.Unlock()
	if last := infra.lastAlerts[key]; !last.IsZero() && time.Since(last) < infra.alertCooldown {
		return false
	}
	infra.lastAlerts[key] = time.Now()
	return true
}

func (infra *infrastructure) keyLoads(ctx context.Context, ids []string) map[string]int64 {
	result := make(map[string]int64, len(ids))
	if infra == nil || infra.redis == nil || len(ids) == 0 {
		return result
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = "agentrouter:active:" + id
	}
	values, err := infra.redis.MGet(ctx, keys...).Result()
	if err != nil {
		return result
	}
	for i, value := range values {
		if value != nil {
			parsed, _ := strconv.ParseInt(fmt.Sprint(value), 10, 64)
			result[ids[i]] = parsed
		}
	}
	return result
}

func (infra *infrastructure) acquireKey(ctx context.Context, id string) func() {
	if infra == nil || infra.redis == nil || id == "" {
		return func() {}
	}
	key := "agentrouter:active:" + id
	_ = infra.redis.Incr(ctx, key).Err()
	_ = infra.redis.Expire(ctx, key, 30*time.Minute).Err()
	return func() { _ = infra.redis.Decr(context.Background(), key).Err() }
}

func (infra *infrastructure) health() map[string]any {
	instanceID := ""
	retentionDays := 0
	if infra != nil {
		instanceID = infra.instanceID
		retentionDays = infra.auditRetentionDays
	}
	return map[string]any{
		"instance_id":          instanceID,
		"postgres":             infra != nil && infra.db != nil,
		"redis":                infra != nil && infra.redis != nil,
		"telegram":             infra != nil && infra.telegramToken != "" && infra.telegramChatID != "",
		"audit_retention_days": retentionDays,
	}
}

func (infra *infrastructure) saveAdminSession(ctx context.Context, id string, session adminSession) {
	if infra == nil || infra.redis == nil {
		return
	}
	raw, _ := json.Marshal(session)
	_ = infra.redis.Set(ctx, "agentrouter:admin-session:"+id, raw, time.Until(session.Expires)).Err()
}

func (infra *infrastructure) loadAdminSession(ctx context.Context, id string) (adminSession, bool) {
	if infra == nil || infra.redis == nil {
		return adminSession{}, false
	}
	raw, err := infra.redis.Get(ctx, "agentrouter:admin-session:"+id).Bytes()
	if err != nil {
		return adminSession{}, false
	}
	var session adminSession
	if json.Unmarshal(raw, &session) != nil || time.Now().After(session.Expires) {
		return adminSession{}, false
	}
	return session, true
}

func (infra *infrastructure) deleteAdminSession(ctx context.Context, id string) {
	if infra != nil && infra.redis != nil {
		_ = infra.redis.Del(ctx, "agentrouter:admin-session:"+id).Err()
	}
}
