package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGatePauseResumeAndCancellation(t *testing.T) {
	g := NewGate()
	g.Pause()
	done := make(chan error, 1)
	go func() { done <- g.Wait(context.Background()) }()
	select {
	case <-done:
		t.Fatal("wait returned while paused")
	case <-time.After(20 * time.Millisecond):
	}
	g.Resume()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not resume")
	}

	g.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
