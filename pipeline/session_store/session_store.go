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

// Store manages all active sessions in memory
type Store struct {
	mu       sync.RWMutex
	sessions map[string]Session // map of session ID to session
}

// NewStore initializes and returns a new session store
func NewStore() *Store {
	return &Store{
		sessions: make(map[string]Session),
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
