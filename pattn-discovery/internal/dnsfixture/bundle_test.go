package dnsfixture

import (
	"context"
	"strings"
	"testing"

	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

func TestExchangeBundleCanDriveDnsTraceOffline(t *testing.T) {
	runtime, err := LoadExchangeBundle("testdata/trace-one-hop.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := runtime.TraceOptions()
	if err != nil {
		t.Fatal(err)
	}

	result, err := dnstrace.Trace(context.Background(), "example.com", dnswire.TypeA, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Hops) != 1 || len(result.FinalAnswers) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if result.FinalAnswers[0].Address != "93.184.216.34" {
		t.Fatalf("answers=%+v", result.FinalAnswers)
	}
}

func TestExchangeBundleRejectsUnsafeFixturePath(t *testing.T) {
	bundle := ExchangeBundle{
		Version: ExchangeBundleVersion,
		RootServers: []string{"192.0.2.53"},
		Exchanges: []ExchangeBundleStep{
			{
				Address: "192.0.2.53",
				Domain: "example.com",
				QueryType: dnswire.TypeA,
				Transport: "udp",
				Fixture: "../outside.json",
			},
		},
	}
	if err := bundle.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("err=%v", err)
	}
}

func TestExchangeBundleMissingTupleFailsClosed(t *testing.T) {
	runtime, err := LoadExchangeBundle("testdata/trace-one-hop.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := runtime.TraceOptions()
	// dnstrace converts exchange failures into an explicit incomplete trace instead of contacting the network.
	result, err := dnstrace.Trace(context.Background(), "missing.example", dnswire.TypeA, opts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.ErrorCode != "nameserver_unreachable" {
		t.Fatalf("result=%+v", result)
	}
}
