package scheduler

import "testing"

func TestAdaptiveThrottleBacksOffAndRecovers(t *testing.T) {
	a := NewAdaptiveThrottle(100, 10, 200, 0.05)
	for i := 0; i < 80; i++ {
		a.RecordTimeout()
	}
	for i := 0; i < 20; i++ {
		a.RecordSuccess()
	}
	if got := a.Reevaluate(); got >= 100 {
		t.Fatalf("expected backoff, got %d", got)
	}
	low := a.Current()
	for i := 0; i < 100; i++ {
		a.RecordSuccess()
	}
	if got := a.Reevaluate(); got <= low {
		t.Fatalf("expected recovery, got %d from %d", got, low)
	}
}
