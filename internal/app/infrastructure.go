package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

type infrastructure struct {
	db             *sql.DB
	redis          *redis.Client
	events         chan map[string]any
	telegramToken  string
	telegramChatID string
	alertCooldown  time.Duration
	alertMu        sync.Mutex
	lastAlerts     map[string]time.Time
}

func newInfrastructure(ctx context.Context, cfg config) (*infrastructure, error) {
	infra := &infrastructure{
		events: make(chan map[string]any, 512), telegramToken: cfg.TelegramBotToken,
		telegramChatID: cfg.TelegramChatID, alertCooldown: cfg.AlertCooldown,
		lastAlerts: make(map[string]time.Time),
	}
	if cfg.DatabaseURL != "" {
		db, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(3)
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := db.PingContext(probe); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres ping: %w", err)
		}
		infra.db = db
		if err := infra.migrate(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	} else if cfg.StorageBackend == "postgres" {
		return nil, errors.New("STORAGE_BACKEND=postgres requires DATABASE_URL")
	}
	if cfg.RedisURL != "" {
		options, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			infra.Close()
			return nil, fmt.Errorf("parse REDIS_URL: %w", err)
		}
		infra.redis = redis.NewClient(options)
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := infra.redis.Ping(probe).Err(); err != nil {
			infra.Close()
			return nil, fmt.Errorf("redis ping: %w", err)
		}
	}
	go infra.eventWorker(ctx)
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
	if infra.redis != nil {
		_ = infra.redis.Close()
	}
	if infra.db != nil {
		_ = infra.db.Close()
	}
}

func (infra *infrastructure) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS gateway_state (id TEXT PRIMARY KEY, payload BYTEA NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`,
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

func (infra *infrastructure) loadGatewayState(ctx context.Context) ([]byte, error) {
	if infra == nil || infra.db == nil {
		return nil, sql.ErrNoRows
	}
	var payload []byte
	err := infra.db.QueryRowContext(ctx, `SELECT payload FROM gateway_state WHERE id='key-store'`).Scan(&payload)
	return payload, err
}

func (infra *infrastructure) saveGatewayState(ctx context.Context, payload []byte) error {
	if infra == nil || infra.db == nil {
		return nil
	}
	_, err := infra.db.ExecContext(ctx, `INSERT INTO gateway_state(id,payload,updated_at) VALUES('key-store',$1,now()) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=now()`, payload)
	return err
}

func (infra *infrastructure) eventWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-infra.events:
			infra.persistEvent(ctx, event)
			infra.maybeAlert(ctx, event)
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
	if status, ok := event["status"]; ok {
		text += "\nStatus: " + fmt.Sprint(status)
	}
	if requestID, ok := event["request_id"]; ok && fmt.Sprint(requestID) != "" {
		text += "\nRequest: " + fmt.Sprint(requestID)
	}
	payload, _ := json.Marshal(map[string]any{"chat_id": infra.telegramChatID, "text": text, "disable_web_page_preview": true})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+infra.telegramToken+"/sendMessage", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (infra *infrastructure) monitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
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
	return map[string]any{"postgres": infra != nil && infra.db != nil, "redis": infra != nil && infra.redis != nil, "telegram": infra != nil && infra.telegramToken != "" && infra.telegramChatID != ""}
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
