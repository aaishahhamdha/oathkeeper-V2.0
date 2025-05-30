package session_store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore implements the SessionStorer interface with Redis
type RedisStore struct {
	client        *redis.Client
	sessionPrefix string
	statePrefix   string
	ctx           context.Context
	defaultTTL    time.Duration
}

// CleanExpired implements SessionStorer.
func (r *RedisStore) CleanExpired() {
	// Redis automatically removes expired keys, so we don't need to manually clean them
	// This method is implemented to satisfy the SessionStorer interface
	// No action needed as Redis handles expiration automatically
}

// CleanExpiredStates implements SessionStorer.
func (r *RedisStore) CleanExpiredStates(maxAge time.Duration) {
	panic("unimplemented")
}

// GetSessionCount implements SessionStorer.
func (r *RedisStore) GetSessionCount() int {
	panic("unimplemented")
}

// SessionExists implements SessionStorer.
func (r *RedisStore) SessionExists(id string) bool {
	panic("unimplemented")
}

// ValidateAndRemoveState implements SessionStorer.
func (r *RedisStore) ValidateAndRemoveState(state string) bool {
	panic("unimplemented")
}

// RedisConfig holds configuration for Redis connection
type RedisConfig struct {
	Addr          string        `json:"addr"`
	Password      string        `json:"password"`
	DB            int           `json:"db"`
	SessionPrefix string        `json:"session_prefix"`
	StatePrefix   string        `json:"state_prefix"`
	TTL           string        `json:"ttl"`
	ParsedTTL     time.Duration `json:"-"` // Not serialized, used internally
}

// NewRedisStore creates a new Redis-backed session store
func NewRedisStore(config RedisConfig) (*RedisStore, error) {
	fmt.Printf("DEBUG: Creating Redis store with addr: %s, DB: %d\n", config.Addr, config.DB)

	client := redis.NewClient(&redis.Options{
		Addr:     config.Addr,
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	ctx := context.Background()
	fmt.Printf("DEBUG: Testing Redis connection...\n")
	if err := client.Ping(ctx).Err(); err != nil {
		fmt.Printf("DEBUG: Redis connection test failed: %v\n", err)
		return nil, err
	}
	fmt.Printf("DEBUG: Redis connection successful\n")

	sessionPrefix := "session:"
	if config.SessionPrefix != "" {
		sessionPrefix = config.SessionPrefix
	}
	fmt.Printf("DEBUG: Using session prefix: %s\n", sessionPrefix)

	statePrefix := "state:"
	if config.StatePrefix != "" {
		statePrefix = config.StatePrefix
	}
	fmt.Printf("DEBUG: Using state prefix: %s\n", statePrefix)

	// Default TTL if not set
	if config.ParsedTTL == 0 {
		config.ParsedTTL = 24 * time.Hour
		fmt.Printf("DEBUG: Using default TTL: 24h\n")
	} else {
		fmt.Printf("DEBUG: Using configured TTL: %v\n", config.ParsedTTL)
	}

	return &RedisStore{
		client:        client,
		sessionPrefix: sessionPrefix,
		statePrefix:   statePrefix,
		ctx:           ctx,
		defaultTTL:    config.ParsedTTL,
	}, nil
}

// AddSession adds a new session to Redis
func (r *RedisStore) AddSession(sess Session) {
	data, err := json.Marshal(sess)
	if err != nil {
		return
	}

	// Calculate TTL based on expiration time
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return // Don't store expired sessions
	}

	r.client.Set(r.ctx, r.sessionPrefix+sess.ID, data, ttl)
}

// GetSession retrieves a session by its ID
func (r *RedisStore) GetSession(id string) (Session, bool) {
	var sess Session
	data, err := r.client.Get(r.ctx, r.sessionPrefix+id).Bytes()
	if err != nil {
		return sess, false
	}

	if err := json.Unmarshal(data, &sess); err != nil {
		return sess, false
	}

	return sess, true
}

// Implement remaining methods of the SessionStorer interface
// DeleteSession removes a session from Redis
func (r *RedisStore) DeleteSession(id string) {
	r.client.Del(r.ctx, r.sessionPrefix+id)
}

// GetField retrieves a specific field from a session
func (r *RedisStore) GetField(id string, field string) (string, bool) {
	sess, ok := r.GetSession(id)
	if !ok {
		return "", false
	}

	switch field {
	case "username":
		return sess.Username, true
	case "sub":
		return sess.Sub, true
	case "access_token":
		return sess.AccessToken, true
	case "id_token":
		return sess.IDToken, true
	default:
		return "", false
	}
}

// AddStateEntry stores a state entry for CSRF protection
func (r *RedisStore) AddStateEntry(state string, ip, userAgent string) {
	stateEntry := StateEntry{
		State:     state,
		CreatedAt: time.Now(),
		IP:        ip,
		UserAgent: userAgent,
	}

	data, err := json.Marshal(stateEntry)
	if err != nil {
		return
	}

	// Store with default TTL (typically used for short-lived state tokens)
	r.client.Set(r.ctx, r.statePrefix+state, data, r.defaultTTL)
}

// Additional methods implementation...
