package scheduler

import (
	"context"
	"sync"
)

// Gate centrally pauses dispatch of new scan work. Active probes are allowed to finish;
// cancellation remains the responsibility of the caller's context.
type Gate struct {
	mu     sync.Mutex
	paused bool
	resume chan struct{}
}

func NewGate() *Gate { return &Gate{} }

func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.resume = make(chan struct{})
}

func (g *Gate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		return
	}
	g.paused = false
	close(g.resume)
	g.resume = nil
}

func (g *Gate) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

func (g *Gate) Wait(ctx context.Context) error {
	for {
		g.mu.Lock()
		if !g.paused {
			g.mu.Unlock()
			return nil
		}
		resume := g.resume
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resume:
		}
	}
}
