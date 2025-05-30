package session_store

import (
	"encoding/json"
	"fmt"
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
func InitializeSessionStore(config StoreConfig) (SessionStorer, error) {
	fmt.Printf("DEBUG: Initializing session store with type: %s\n", config.Type)

	switch config.Type {
	case InMemoryStore, "":
		// Default to in-memory store if not specified
		fmt.Printf("DEBUG: Using in-memory session store\n")
		return NewStore(), nil

	case RedisStoreType:
		fmt.Printf("DEBUG: Attempting to initialize Redis session store with addr: %s\n", config.Redis.Addr)
		store, err := NewRedisStore(config.Redis)
		if err != nil {
			fmt.Printf("DEBUG: Redis session store initialization failed: %v\n", err)
			return nil, err
		}
		fmt.Printf("DEBUG: Successfully initialized Redis session store\n")
		return store, nil

	default:
		fmt.Printf("DEBUG: Unsupported session store type: %s\n", config.Type)
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
