package session_store

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents the session information for a user
type Session struct {
	ID          string    // Unique session ID
	Username    string    // Username of the user
	Sub         string    // Subject (usually user ID from IdP)
	ExpiresAt   time.Time // Expiration time
	IssuedAt    time.Time // Issued time
	AccessToken string    // OAuth2 Access Token
	IDToken     string    // OIDC ID Token
	State       string    // State parameter for CSRF protection
}

// StateEntry represents a temporary state for CSRF protection
type StateEntry struct {
	State     string    // The state parameter
	CreatedAt time.Time // When this state was created
	IP        string    // Optional: IP address for additional validation
	UserAgent string    // Optional: User agent for additional validation
}

// Store manages all active sessions and state entries
type Store struct {
	mu           sync.RWMutex
	sessions     map[string]Session    // map of session ID to session
	stateEntries map[string]StateEntry // map of state to state entry
}

// NewStore initializes and returns a new session store
func NewStore() *Store {
	return &Store{
		sessions:     make(map[string]Session),
		stateEntries: make(map[string]StateEntry),
	}
}

// GlobalStore is the singleton instance of the session store
var GlobalStore = NewStore()

// GenerateSessionID creates a new cryptographically secure random session ID
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 16) // 128-bit session ID
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// AddSession adds a new session to the store
func (s *Store) AddSession(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

// GetSession retrieves a session by its ID
func (s *Store) GetSession(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// DeleteSession removes a session from the store
func (s *Store) DeleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// CleanExpired removes all expired sessions
func (s *Store) CleanExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.sessions {
		if sess.ExpiresAt.Before(now) {
			delete(s.sessions, id)
		}
	}
}

// GetField retrieves a specific string field from the session by ID.
// Supported fields: "username", "sub", "access_token", "id_token", "state"
func (s *Store) GetField(id string, field string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
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
	case "state":
		return sess.State, true
	default:
		return "", false
	}
}

// AddStateEntry stores a state entry for CSRF protection
func (s *Store) AddStateEntry(state string, ip, userAgent string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateEntries[state] = StateEntry{
		State:     state,
		CreatedAt: time.Now(),
		IP:        ip,
		UserAgent: userAgent,
	}
}

// ValidateAndRemoveState checks if a state exists and removes it if found
// Returns true if state was found and removed, false otherwise
func (s *Store) ValidateAndRemoveState(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.stateEntries[state]
	if exists {
		delete(s.stateEntries, state)
		return true
	}
	return false
}

// CleanExpiredStates removes all expired state entries
func (s *Store) CleanExpiredStates(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for state, entry := range s.stateEntries {
		if now.Sub(entry.CreatedAt) > maxAge {
			delete(s.stateEntries, state)
		}
	}
}
