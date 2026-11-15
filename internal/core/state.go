package core

import (
	"sync"
	"time"
)

type TargetSession struct {
	Id         string
	ClientAddr string
	SNI        string
	Upstream   string
	Lure       string
	Status     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	payload    map[string]string
	mu         sync.RWMutex
}

func NewTargetSession(id, clientAddr, sni, upstream, lure string) *TargetSession {
	now := time.Now()
	return &TargetSession{
		Id:         id,
		ClientAddr: clientAddr,
		SNI:        sni,
		Upstream:   upstream,
		Lure:       lure,
		Status:     "active",
		CreatedAt:  now,
		UpdatedAt:  now,
		payload:    make(map[string]string),
	}
}

func (s *TargetSession) SetPayload(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payload[key] = value
	s.UpdatedAt = time.Now()
}

func (s *TargetSession) GetPayload(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.payload[key]
	return v, ok
}

func (s *TargetSession) Payload() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.payload))
	for k, v := range s.payload {
		out[k] = v
	}
	return out
}

func (s *TargetSession) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UpdatedAt = time.Now()
}

func (s *TargetSession) SetStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
	s.UpdatedAt = time.Now()
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*TargetSession
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*TargetSession),
	}
}

func (s *SessionStore) Register(sess *TargetSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.Id] = sess
}

func (s *SessionStore) Get(id string) (*TargetSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *SessionStore) List() []*TargetSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TargetSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *SessionStore) Mutate(id string, fn func(*TargetSession)) bool {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	fn(sess)
	return true
}
