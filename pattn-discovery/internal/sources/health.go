package sources

import (
	"sync"
	"time"
)

type Health struct {
	ID                  string    `json:"id"`
	LastAttempt         time.Time `json:"lastAttempt,omitempty"`
	LastSuccessfulFetch time.Time `json:"lastSuccessfulFetch,omitempty"`
	LastFailure         string    `json:"lastFailure,omitempty"`
	TargetCount         int       `json:"targetCount"`
}

type Tracker struct {
	mu sync.RWMutex
	m  map[string]Health
}

func NewTracker() *Tracker { return &Tracker{m: make(map[string]Health)} }

func (t *Tracker) Success(id string, count int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[id] = Health{ID: id, LastAttempt: now, LastSuccessfulFetch: now, TargetCount: count}
}

func (t *Tracker) Failure(id string, err error, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.m[id]
	h.ID = id
	h.LastAttempt = now
	if err != nil {
		h.LastFailure = err.Error()
	}
	t.m[id] = h
}

func (t *Tracker) Get(id string) (Health, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	h, ok := t.m[id]
	return h, ok
}
func (t *Tracker) Snapshot() []Health {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Health, 0, len(t.m))
	for _, h := range t.m {
		out = append(out, h)
	}
	return out
}
