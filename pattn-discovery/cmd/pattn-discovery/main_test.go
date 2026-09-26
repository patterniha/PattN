package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestNDJSONContract(t *testing.T) {
	in := strings.NewReader("{\"v\":1,\"id\":\"a\",\"method\":\"engine.version\"}\n{bad}\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"id":"a"`) || !strings.Contains(lines[0], `"pattn-discovery"`) {
		t.Fatalf("unexpected response: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"invalid_json"`) {
		t.Fatalf("unexpected error response: %s", lines[1])
	}
}


func FuzzNDJSONFraming(f *testing.F) {
	f.Add([]byte("{\"v\":1,\"id\":\"a\",\"method\":\"engine.version\"}\n"))
	f.Add([]byte("{bad}\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 256*1024 {
			t.Skip()
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var out bytes.Buffer
		err := run(ctx, bytes.NewReader(input), &out)
		if err != nil && ctx.Err() == nil {
			// Scanner token-too-long and output failures are ordinary bounded
			// framing errors; panics or hangs are the properties under test.
			if !strings.Contains(err.Error(), "token too long") {
				t.Logf("run returned bounded framing error: %v", err)
			}
		}
	})
}
