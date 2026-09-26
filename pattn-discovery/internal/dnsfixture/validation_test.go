package dnsfixture

import (
	"context"
	"testing"

	"pattn-discovery/internal/dnsvalidate"
	"pattn-discovery/internal/dnswire"
)

func TestValidateDNSSECBundleRunsExistingValidatorOffline(t *testing.T) {
	result, err := ValidateDNSSECBundle(
		context.Background(),
		"testdata/trace-one-hop.bundle.json",
		"example.com",
		dnswire.TypeA,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Trace.Complete || len(result.Trace.Hops) != 1 {
		t.Fatalf("trace=%+v", result.Trace)
	}
	if result.Status != dnsvalidate.StatusIndeterminate || result.TrustScope != "unanchored" {
		t.Fatalf("status=%q trust=%q", result.Status, result.TrustScope)
	}
	if len(result.Trace.FinalAnswers) != 1 || result.Trace.FinalAnswers[0].Address != "93.184.216.34" {
		t.Fatalf("answers=%+v", result.Trace.FinalAnswers)
	}
}
