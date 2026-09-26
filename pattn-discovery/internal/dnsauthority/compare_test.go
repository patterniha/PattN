package dnsauthority

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

func TestCompareGroupsEquivalentAnswersAndFindsDivergence(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	ns1 := netip.MustParseAddr("192.0.2.11")
	ns2 := netip.MustParseAddr("192.0.2.12")
	ns3 := netip.MustParseAddr("192.0.2.13")

	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		switch address {
		case root:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true},
				Authorities: []dnswire.ResourceRecord{
					{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com"},
					{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns2.example.com"},
					{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns3.example.com"},
				},
				Additionals: []dnswire.ResourceRecord{
					{Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns1},
					{Name: "ns2.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns2},
					{Name: "ns3.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns3},
				},
			}, nil
		case ns1, ns2:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true, AA: true},
				Answers: []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 60, Address: netip.MustParseAddr("203.0.113.7")}},
			}, nil
		case ns3:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true, AA: true},
				Answers: []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 90, Address: netip.MustParseAddr("203.0.113.8")}},
			}, nil
		default:
			t.Fatalf("unexpected address %s", address)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Compare(context.Background(), "example.com", dnswire.TypeA, Options{
		Trace: dnstrace.Options{RootServers: []netip.Addr{root}, Exchange: exchange},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Divergent || result.Unanimous || result.Responding != 3 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Groups) != 2 || result.Groups[0].Count != 2 || result.MajorityCount != 2 {
		t.Fatalf("groups=%+v", result.Groups)
	}
}

func TestCompareExcludesNonAuthoritativeAndTransientResponsesFromBaseline(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	ns1 := netip.MustParseAddr("192.0.2.11")
	ns2 := netip.MustParseAddr("192.0.2.12")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		switch address {
		case root:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true},
				Authorities: []dnswire.ResourceRecord{
					{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com"},
					{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns2.example.com"},
				},
				Additionals: []dnswire.ResourceRecord{
					{Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns1},
					{Name: "ns2.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: ns2},
				},
			}, nil
		case ns1:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true},
				Answers: []dnswire.ResourceRecord{{
					Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
					Address: netip.MustParseAddr("203.0.113.31"),
				}},
			}, nil
		case ns2:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true, AA: true, RCode: 2},
			}, nil
		default:
			t.Fatalf("unexpected address %s", address)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Compare(context.Background(), "example.com", dnswire.TypeA, Options{
		Trace: dnstrace.Options{RootServers: []netip.Addr{root}, Exchange: exchange},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Responding != 0 || len(result.Groups) != 0 || result.MajoritySignature != "" || result.Unanimous || result.Divergent {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Observations) != 2 || result.Observations[0].Error == "" || result.Observations[1].Error == "" {
		t.Fatalf("observations=%+v", result.Observations)
	}
}
