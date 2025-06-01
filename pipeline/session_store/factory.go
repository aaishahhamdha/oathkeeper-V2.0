package session_store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// StoreType defines the type of session store to use
type StoreType string

const (
	// InMemoryStore uses the default in-memory implementation
	InMemoryStore StoreType = "memory"
	// RedisStore uses Redis as the backend
	RedisStoreType StoreType = "redis"
)

// StoreConfig holds configuration for the session store
type StoreConfig struct {
	// Type of store to use (memory, redis)
	Type StoreType `json:"type"`

	// Redis specific configuration, only used when Type is "redis"
	Redis RedisConfig `json:"redis,omitempty"`
}

// InitializeSessionStore creates and returns a SessionStorer based on the provided configuration
// This function uses a default logger for backward compatibility
func InitializeSessionStore(config StoreConfig) (SessionStorer, error) {
	fmt.Printf("SESSION_STORE: Initializing session store with type: %s\n", config.Type)

	switch config.Type {
	case InMemoryStore, "":
		// Default to in-memory store if not specified
		fmt.Printf("SESSION_STORE: Using in-memory session store\n")
		return NewStore(), nil

	case RedisStoreType:
		fmt.Printf("SESSION_STORE: Attempting to initialize Redis session store with addr: %s\n", config.Redis.Addr)
		store, err := NewRedisStore(config.Redis)
		if err != nil {
			fmt.Printf("SESSION_STORE: Redis session store initialization failed: %v\n", err)
			return nil, err
		}
		fmt.Printf("SESSION_STORE: Successfully initialized Redis session store\n")
		return &redisStoreAdapter{store: store}, nil

	default:
		return nil, fmt.Errorf("unsupported session store type: %s", config.Type)
	}
}

// InitializeFromJSON creates a session store from JSON configuration
func InitializeFromJSON(configJSON []byte) (SessionStorer, error) {
	var config StoreConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return nil, fmt.Errorf("failed to parse session store config: %w", err)
	}

	return InitializeSessionStore(config)
}

// redisStoreAdapter adapts RedisStore to implement the SessionStorer interface
type redisStoreAdapter struct {
	store *RedisStore
}

// AddSession implements SessionStorer by forwarding to RedisStore with context
func (a *redisStoreAdapter) AddSession(sess Session) {
	_ = a.store.AddSession(context.Background(), sess)
}

// Other methods to implement the SessionStorer interface...
func (a *redisStoreAdapter) GetSession(id string) (Session, bool) {
	return a.store.GetSession(id)
}

func (a *redisStoreAdapter) DeleteSession(id string) {
	a.store.DeleteSession(id)
}

func (a *redisStoreAdapter) CleanExpired() {
	a.store.CleanExpired()
}

func (a *redisStoreAdapter) GetField(id string, field string) (string, bool) {
	return a.store.GetField(id, field)
}

func (a *redisStoreAdapter) GetSessionCount() int {
	return a.store.GetSessionCount()
}

func (a *redisStoreAdapter) SessionExists(id string) bool {
	return a.store.SessionExists(id)
}

func (a *redisStoreAdapter) AddStateEntry(state string, ip, userAgent string) {
	a.store.AddStateEntry(state, ip, userAgent)
}

func (a *redisStoreAdapter) ValidateAndRemoveState(state string) bool {
	data, _ := a.store.ValidateAndRemoveState(context.Background(), state)
	return data != ""
}

func (a *redisStoreAdapter) CleanExpiredStates(maxAge time.Duration) {
	a.store.CleanExpiredStates(maxAge)
}
