package dnsrepair

import (
	"context"
	"errors"
	"testing"

	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnsvalidate"
	"pattn-discovery/internal/dnswire"
	"pattn-discovery/internal/resolvercatalog"
)

func TestInspectCombinesDnssecFamilyEvidenceFallbackAndCatalog(t *testing.T) {
	validate := func(_ context.Context, domain string, qtype uint16, _ dnstrace.Options) (dnsvalidate.Result, error) {
		if qtype == dnswire.TypeAAAA {
			return dnsvalidate.Result{}, errors.New("dnssec unavailable")
		}
		return dnsvalidate.Result{
			Domain: domain,
			QueryType: qtype,
			AnswerAuthenticated: true,
			Status: dnsvalidate.StatusAuthenticatedAnswer,
			Trace: dnstrace.Result{
				Domain: domain,
				QueryType: qtype,
				Complete: true,
				FinalAnswers: []dnstrace.Record{{Name: domain, Type: dnswire.TypeA, Address: "203.0.113.7"}},
			},
		}, nil
	}
	trace := func(_ context.Context, domain string, qtype uint16, _ dnstrace.Options) (dnstrace.Result, error) {
		return dnstrace.Result{
			Domain: domain,
			QueryType: qtype,
			Complete: true,
			FinalAnswers: []dnstrace.Record{{Name: domain, Type: dnswire.TypeAAAA, Address: "2001:db8::7"}},
		}, nil
	}

	result, err := Inspect(context.Background(), "proxy.example.", Options{
		Validate: validate,
		Trace: trace,
		Catalog: resolvercatalog.Builtin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Domain != "proxy.example" || !result.IPv4.DNSSECAuthenticated || result.IPv4.FallbackUsed {
		t.Fatalf("ipv4=%+v", result.IPv4)
	}
	if !result.IPv6.FallbackUsed || result.IPv6.DNSSECStatus != "validation-unavailable" ||
		len(result.IPv6.Trace.FinalAnswers) != 1 {
		t.Fatalf("ipv6=%+v", result.IPv6)
	}
	if result.ResolverCatalogVersion != resolvercatalog.Version || len(result.ResolverRecommendations) != 3 {
		t.Fatalf("catalog version=%q recommendations=%d", result.ResolverCatalogVersion, len(result.ResolverRecommendations))
	}
}

func TestInspectRejectsEmptyDomain(t *testing.T) {
	if _, err := Inspect(context.Background(), " ", Options{}); err == nil {
		t.Fatal("expected empty-domain error")
	}
}
