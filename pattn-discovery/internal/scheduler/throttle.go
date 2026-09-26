package scheduler

import "sync"

// AdaptiveThrottle is a deterministic extraction of WhiteDNS' concurrency feedback loop.
// Record methods only collect observations; Reevaluate performs an adjustment, which keeps
// policy testable and lets the engine decide the observation window/timing.
type AdaptiveThrottle struct {
	mu         sync.Mutex
	current    int
	min        int
	max        int
	targetRate float64
	successes  int64
	timeouts   int64
}

func NewAdaptiveThrottle(initial, min, max int, targetTimeoutRate float64) *AdaptiveThrottle {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	if initial < min {
		initial = min
	}
	if initial > max {
		initial = max
	}
	if targetTimeoutRate <= 0 {
		targetTimeoutRate = 0.05
	}
	return &AdaptiveThrottle{current: initial, min: min, max: max, targetRate: targetTimeoutRate}
}

func (a *AdaptiveThrottle) RecordSuccess() { a.mu.Lock(); a.successes++; a.mu.Unlock() }
func (a *AdaptiveThrottle) RecordTimeout() { a.mu.Lock(); a.timeouts++; a.mu.Unlock() }
func (a *AdaptiveThrottle) Current() int   { a.mu.Lock(); defer a.mu.Unlock(); return a.current }

func (a *AdaptiveThrottle) Reevaluate() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	total := a.successes + a.timeouts
	if total == 0 {
		return a.current
	}
	rate := float64(a.timeouts) / float64(total)
	if rate > a.targetRate*2 {
		next := int(float64(a.current) * 0.88)
		if next < a.min {
			next = a.min
		}
		a.current = next
	} else if rate < a.targetRate*0.5 && a.current < a.max {
		next := int(float64(a.current) * 1.15)
		if next <= a.current {
			next = a.current + 1
		}
		if next > a.max {
			next = a.max
		}
		a.current = next
	}
	a.successes, a.timeouts = 0, 0
	return a.current
}
