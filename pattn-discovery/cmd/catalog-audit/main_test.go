package main

import (
	"bytes"
	"testing"
	"time"
)

func TestRunPassesFreshCatalogAndFailsStaleCatalog(t *testing.T) {
	var stdout, stderr bytes.Buffer
	fresh := run(
		[]string{"-max-age-days", "120"},
		time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
		&stdout,
		&stderr,
	)
	if fresh != 0 {
		t.Fatalf("fresh exit=%d stderr=%s stdout=%s", fresh, stderr.String(), stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	stale := run(
		[]string{"-max-age-days", "30"},
		time.Date(2027, 1, 23, 12, 0, 0, 0, time.UTC),
		&stdout,
		&stderr,
	)
	if stale != 1 {
		t.Fatalf("stale exit=%d stderr=%s stdout=%s", stale, stderr.String(), stdout.String())
	}
}

func TestRunRejectsInvalidWindow(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-max-age-days", "0"}, time.Now(), &stdout, &stderr); code != 2 {
		t.Fatalf("exit=%d", code)
	}
}
