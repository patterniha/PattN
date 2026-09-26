package sources

import (
	"errors"
	"testing"
	"time"
)

func TestFailurePreservesLastSuccessfulFetch(t *testing.T) {
	tr := NewTracker()
	okAt := time.Unix(10, 0)
	failAt := time.Unix(20, 0)
	tr.Success("source", 12, okAt)
	tr.Failure("source", errors.New("offline"), failAt)
	h, _ := tr.Get("source")
	if !h.LastSuccessfulFetch.Equal(okAt) || h.LastFailure != "offline" || h.TargetCount != 12 {
		t.Fatalf("%+v", h)
	}
}
