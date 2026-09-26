package measure

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunQuorumRequiresRepeatedSuccess(t *testing.T) {
	seq := []AttemptResult{
		{Success: true, Latency: 70 * time.Millisecond},
		{Success: false, Error: errors.New("transient")},
		{Success: true, Latency: 50 * time.Millisecond},
	}
	got := RunQuorum(context.Background(), 3, 2, func(_ context.Context, i int) AttemptResult { return seq[i] })
	if !got.Meets(2) || got.Successes != 2 || got.MedianLatency != 60*time.Millisecond {
		t.Fatalf("got %+v", got)
	}
}

func TestRunQuorumStopsWhenSuccessBecomesImpossible(t *testing.T) {
	calls := 0
	got := RunQuorum(context.Background(), 5, 4, func(_ context.Context, _ int) AttemptResult { calls++; return AttemptResult{} })
	if calls != 2 || got.Successes != 0 {
		t.Fatalf("calls=%d result=%+v", calls, got)
	}
}
