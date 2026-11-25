package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const maxCustomCacheTTL = 24 * time.Hour

type cacheItem struct {
	body      []byte
	expiresAt time.Time
}

type responseCache struct {
	mu       sync.RWMutex
	enabled  bool
	ttl      time.Duration
	maxItems int
	cacheAll bool
	redis    *redis.Client
	items    map[string]cacheItem
	hits     atomic.Uint64
	misses   atomic.Uint64
}

func newResponseCache(enabled bool, ttl time.Duration, maxItems int, cacheAll bool) *responseCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if maxItems <= 0 {
		maxItems = 10000
	}
	return &responseCache{
		enabled:  enabled,
		ttl:      ttl,
		maxItems: maxItems,
		cacheAll: cacheAll,
		items:    make(map[string]cacheItem),
	}
}

func (c *responseCache) setRedis(client *redis.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.redis = client
}

func computeCacheKey(obj map[string]any) (string, error) {
	return computeCacheKeyScoped(obj, "")
}

func computeCacheKeyScoped(obj map[string]any, authScope string) (string, error) {
	canonical := make(map[string]any, len(obj)+1)
	for k, v := range obj {
		switch k {
		case "stream", "stream_options", "user":
			continue
		case "model":
			if s, ok := v.(string); ok {
				canonical["model"] = strings.TrimSpace(s)
			} else {
				canonical["model"] = v
			}
		default:
			canonical[k] = v
		}
	}
	if authScope != "" {
		canonical["__auth_scope"] = authScope
	}

	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func toFloat64(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func (c *responseCache) isCacheable(r *http.Request, body []byte, obj map[string]any) (string, time.Duration, bool) {
	return c.isCacheableScoped(r, body, obj, "")
}

func (c *responseCache) isCacheableScoped(r *http.Request, _ []byte, obj map[string]any, authScope string) (string, time.Duration, bool) {
	if c == nil || !c.enabled {
		return "", 0, false
	}
	if r.Header.Get("Cache-Control") == "no-cache" || strings.ToLower(r.Header.Get("X-Cache-Skip")) == "true" {
		return "", 0, false
	}
	if stream, _ := obj["stream"].(bool); stream {
		return "", 0, false
	}

	forceCache := strings.ToLower(r.Header.Get("X-Cache")) == "true" || c.cacheAll
	if !forceCache {
		temp, hasTemp := obj["temperature"]
		if !hasTemp {
			// In LLM APIs, omitted temperature defaults to 1.0 (stochastic).
			// Only cache if temperature is explicitly set to 0 (deterministic) or requested.
			return "", 0, false
		}
		tempFloat, ok := toFloat64(temp)
		if !ok || tempFloat > 0.05 {
			return "", 0, false
		}
	}

	ttl := c.ttl
	if customTTL := r.Header.Get("X-Cache-TTL"); customTTL != "" {
		if d, err := time.ParseDuration(customTTL); err == nil && d > 0 {
			ttl = d
		} else if sec, err := strconv.Atoi(customTTL); err == nil && sec > 0 {
			ttl = time.Duration(sec) * time.Second
		}
	}
	if ttl > maxCustomCacheTTL {
		ttl = maxCustomCacheTTL
	}

	key, err := computeCacheKeyScoped(obj, authScope)
	if err != nil {
		return "", 0, false
	}
	return key, ttl, true
}

func (c *responseCache) get(ctx context.Context, key string) ([]byte, bool) {
	if c == nil || !c.enabled || key == "" {
		return nil, false
	}
	c.mu.RLock()
	rClient := c.redis
	c.mu.RUnlock()

	if rClient != nil {
		raw, err := rClient.Get(ctx, "agentrouter:cache:"+key).Bytes()
		if err == nil && len(raw) > 0 {
			c.hits.Add(1)
			return raw, true
		}
	}

	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()

	if ok {
		if time.Now().After(item.expiresAt) {
			c.mu.Lock()
			delete(c.items, key)
			c.mu.Unlock()
			c.misses.Add(1)
			return nil, false
		}
		c.hits.Add(1)
		return bytes.Clone(item.body), true
	}

	c.misses.Add(1)
	return nil, false
}

func (c *responseCache) set(ctx context.Context, key string, body []byte, ttl time.Duration) {
	if c == nil || !c.enabled || key == "" || len(body) == 0 {
		return
	}
	if ttl <= 0 {
		ttl = c.ttl
	}

	c.mu.RLock()
	rClient := c.redis
	c.mu.RUnlock()

	if rClient != nil {
		_ = rClient.Set(ctx, "agentrouter:cache:"+key, body, ttl).Err()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxItems {
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expiresAt) {
				delete(c.items, k)
			}
		}
		if len(c.items) >= c.maxItems {
			toDelete := c.maxItems / 10
			if toDelete == 0 {
				toDelete = 1
			}
			count := 0
			for k := range c.items {
				delete(c.items, k)
				count++
				if count >= toDelete {
					break
				}
			}
		}
	}

	c.items[key] = cacheItem{
		body:      bytes.Clone(body),
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *responseCache) clear(ctx context.Context) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.items = make(map[string]cacheItem)
	rClient := c.redis
	c.mu.Unlock()

	if rClient != nil {
		var cursor uint64
		for {
			keys, nextCursor, err := rClient.Scan(ctx, cursor, "agentrouter:cache:*", 100).Result()
			if err != nil {
				break
			}
			if len(keys) > 0 {
				_ = rClient.Del(ctx, keys...).Err()
			}
			cursor = nextCursor
			if cursor == 0 {
				break
			}
		}
	}
}

func (c *responseCache) stats() map[string]any {
	if c == nil {
		return map[string]any{"enabled": false}
	}
	c.mu.RLock()
	backend := "memory"
	if c.redis != nil {
		backend = "redis"
	}
	itemCount := len(c.items)
	c.mu.RUnlock()

	return map[string]any{
		"enabled":     c.enabled,
		"backend":     backend,
		"items":       itemCount,
		"hits":        c.hits.Load(),
		"misses":      c.misses.Load(),
		"default_ttl": c.ttl.String(),
	}
}
