package measure

import (
	"context"
	"sort"
	"time"
)

type AttemptResult struct {
	Success bool
	Latency time.Duration
	Error   error
}

type QuorumResult struct {
	Attempts             int
	Successes            int
	ConsecutiveSuccesses int
	MedianLatency        time.Duration
	Errors               []string
}

func (r QuorumResult) Meets(minSuccesses int) bool {
	return minSuccesses > 0 && r.Successes >= minSuccesses
}

// RunQuorum repeats a deeper validation and aggregates stability evidence rather than accepting
// a one-off success. It exits early once quorum is reached or becomes impossible.
func RunQuorum(ctx context.Context, attempts, minSuccesses int, fn func(context.Context, int) AttemptResult) QuorumResult {
	if attempts < 1 {
		attempts = 1
	}
	if minSuccesses < 1 {
		minSuccesses = 1
	}
	if minSuccesses > attempts {
		minSuccesses = attempts
	}
	result := QuorumResult{}
	var latencies []time.Duration
	consecutive := 0
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			break
		}
		observation := fn(ctx, i)
		result.Attempts++
		if observation.Success {
			result.Successes++
			consecutive++
			if consecutive > result.ConsecutiveSuccesses {
				result.ConsecutiveSuccesses = consecutive
			}
			if observation.Latency > 0 {
				latencies = append(latencies, observation.Latency)
			}
		} else {
			consecutive = 0
			if observation.Error != nil {
				result.Errors = append(result.Errors, observation.Error.Error())
			}
		}
		remaining := attempts - (i + 1)
		if result.Successes >= minSuccesses || result.Successes+remaining < minSuccesses {
			break
		}
	}
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		mid := len(latencies) / 2
		if len(latencies)%2 == 1 {
			result.MedianLatency = latencies[mid]
		} else {
			result.MedianLatency = (latencies[mid-1] + latencies[mid]) / 2
		}
	}
	return result
}
