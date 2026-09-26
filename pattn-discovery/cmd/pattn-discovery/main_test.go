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
	var sawVersion, sawInvalid bool
	for _, line := range lines {
		sawVersion = sawVersion || (strings.Contains(line, `"id":"a"`) && strings.Contains(line, `"pattn-discovery"`))
		sawInvalid = sawInvalid || strings.Contains(line, `"invalid_json"`)
	}
	if !sawVersion || !sawInvalid {
		t.Fatalf("unexpected responses: %q", out.String())
	}
}


func TestRequestCancelForUnknownRequestReturnsBoundedError(t *testing.T) {
	in := strings.NewReader("{\"v\":1,\"id\":\"cancel\",\"method\":\"request.cancel\",\"params\":{\"requestId\":\"missing\"}}\n")
	var out bytes.Buffer
	if err := run(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"id":"cancel"`) || !strings.Contains(out.String(), `"request_not_found"`) {
		t.Fatalf("unexpected response: %s", out.String())
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
