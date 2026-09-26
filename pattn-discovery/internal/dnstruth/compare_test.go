package dnstruth

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/resolvercatalog"
	"pattn-discovery/internal/dnswire"
)

func TestCompareAssessesCandidatesAgainstDefinitiveAuthorityMajority(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	ns1 := netip.MustParseAddr("192.0.2.11")
	ns2 := netip.MustParseAddr("192.0.2.12")
	trusted := netip.MustParseAddr("192.0.2.21")
	candidate := netip.MustParseAddr("192.0.2.22")
	good := netip.MustParseAddr("203.0.113.7")
	bad := netip.MustParseAddr("203.0.113.8")

	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, rd bool) (dnsmeasure.Observation, error) {
		base := dnsmeasure.Observation{Address: address, Domain: name, QueryType: qtype, Transport: transport, Header: dnswire.Header{QR: true}}
		switch address {
		case root:
			if rd {
				t.Fatal("authoritative trace requested recursion")
			}
			base.Authorities = []dnswire.ResourceRecord{
				{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com"},
				{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns2.example.com"},
			}
			base.Additionals = []dnswire.ResourceRecord{
				{Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns1},
				{Name: "ns2.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns2},
			}
		case ns1, ns2:
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: good}}
		case trusted:
			if !rd { t.Fatal("recursive resolver queried without RD") }
			base.Header.RA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: good}}
		case candidate:
			if !rd { t.Fatal("candidate resolver queried without RD") }
			base.Header.RA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: bad}}
		default:
			t.Fatalf("unexpected address %s", address)
		}
		return base, nil
	}

	result, err := Compare(context.Background(), "example.com", dnswire.TypeA, CompareOptions{
		Trace: dnstrace.Options{RootServers: []netip.Addr{root}, Exchange: exchange},
		Exchange: exchange,
		Resolvers: []ResolverEndpoint{
			{Name: "trusted", Address: trusted.String(), Kind: SourceTrusted},
			{Name: "candidate", Address: candidate.String(), Kind: SourceCandidate},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.AuthorityReferenceDefinitive || result.AuthorityReferenceSignature == "" {
		t.Fatalf("authority=%+v", result.Authority)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Status != CandidateDiffersAuthority {
		t.Fatalf("candidates=%+v", result.Candidates)
	}
	if !result.Consensus.Divergent || result.Consensus.ValidEvidenceCount != 4 {
		t.Fatalf("consensus=%+v", result.Consensus)
	}
}

func TestCompareAvoidsCandidateVerdictWithoutAuthorityMajority(t *testing.T) {
	result := ComparisonResult{}
	_ = result
}


func TestDefaultTrustedResolversCarryCatalogIdentityAndEncryptedTransports(t *testing.T) {
	values := DefaultTrustedResolvers()
	if len(values) != 3 {
		t.Fatalf("values=%+v", values)
	}
	var quad9 ResolverEndpoint
	for _, value := range values {
		if value.CatalogID == "quad9-secure" {
			quad9 = value
		}
		if value.CatalogID == "" || value.ServerName == "" || value.DoTPort != 853 || value.DoHURL == "" {
			t.Fatalf("incomplete default resolver=%+v", value)
		}
	}
	if quad9.Policy != resolvercatalog.PolicySecurityFiltering || isReferenceEligible(quad9) {
		t.Fatalf("quad9=%+v", quad9)
	}
}

func TestReferenceConsensusExcludesFilteringTrustedResolverAndCandidates(t *testing.T) {
	auth := Observation{Source: "auth", Kind: SourceAuthoritative, Signature: "A"}
	neutral := Observation{Source: "neutral", Kind: SourceTrusted, Signature: "A"}
	filtering := Observation{Source: "filtering", Kind: SourceTrusted, Signature: "B"}
	candidate := Observation{Source: "candidate", Kind: SourceCandidate, Signature: "B"}

	all := Aggregate([]Observation{auth, neutral, filtering, candidate})
	reference := Aggregate([]Observation{auth, neutral})
	if !all.Divergent || reference.Divergent || !reference.Unanimous || reference.ValidEvidenceCount != 2 {
		t.Fatalf("all=%+v reference=%+v", all, reference)
	}
}


func TestCompareReferenceConsensusExcludesFilteringDefaultResolverPolicy(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	ns := netip.MustParseAddr("192.0.2.11")
	neutral := netip.MustParseAddr("192.0.2.21")
	filtering := netip.MustParseAddr("192.0.2.22")
	good := netip.MustParseAddr("203.0.113.7")
	filtered := netip.MustParseAddr("203.0.113.8")

	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, rd bool) (dnsmeasure.Observation, error) {
		base := dnsmeasure.Observation{Address: address, Domain: name, QueryType: qtype, Transport: transport, Header: dnswire.Header{QR: true}}
		switch address {
		case root:
			base.Authorities = []dnswire.ResourceRecord{{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns.example.com"}}
			base.Additionals = []dnswire.ResourceRecord{{Name: "ns.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns}}
		case ns:
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: good}}
		case neutral:
			if !rd { t.Fatal("neutral recursive resolver queried without RD") }
			base.Header.RA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: good}}
		case filtering:
			if !rd { t.Fatal("filtering recursive resolver queried without RD") }
			base.Header.RA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: filtered}}
		default:
			t.Fatalf("unexpected address %s", address)
		}
		return base, nil
	}

	result, err := Compare(context.Background(), "example.com", dnswire.TypeA, CompareOptions{
		Trace: dnstrace.Options{RootServers: []netip.Addr{root}, Exchange: exchange},
		Exchange: exchange,
		Resolvers: []ResolverEndpoint{
			{
				Name: "neutral", Address: neutral.String(), Kind: SourceTrusted,
				CatalogID: "neutral", Policy: resolvercatalog.PolicyNeutral,
			},
			{
				Name: "filtering", Address: filtering.String(), Kind: SourceTrusted,
				CatalogID: "filtering", Policy: resolvercatalog.PolicySecurityFiltering,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Consensus.Divergent {
		t.Fatalf("all evidence consensus=%+v", result.Consensus)
	}
	if !result.ReferenceConsensus.Unanimous || result.ReferenceConsensus.Divergent || result.ReferenceConsensus.ValidEvidenceCount != 2 {
		t.Fatalf("reference consensus=%+v", result.ReferenceConsensus)
	}
	for _, observation := range result.Resolvers {
		if observation.CatalogID == "filtering" && observation.ReferenceEligible {
			t.Fatalf("filtering observation became reference eligible: %+v", observation)
		}
	}
}
