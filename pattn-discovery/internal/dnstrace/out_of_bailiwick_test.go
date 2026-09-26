package dnstrace

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnswire"
)

func TestTraceResolvesOutOfBailiwickNameserverWithoutGlue(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	tld := netip.MustParseAddr("192.0.2.2")
	auth := netip.MustParseAddr("192.0.2.53")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, recursionDesired bool) (dnsmeasure.Observation, error) {
		if recursionDesired {
			t.Fatal("iterative trace requested recursion")
		}
		base := dnsmeasure.Observation{Address: address, Domain: name, QueryType: qtype, Transport: transport, Header: dnswire.Header{QR: true}}
		switch {
		case address == root && name == "www.example.com":
			base.Authorities = []dnswire.ResourceRecord{{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns.external.net"}}
			// Out-of-bailiwick additional data must not be trusted as glue.
			base.Additionals = []dnswire.ResourceRecord{{Name: "ns.external.net", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: netip.MustParseAddr("198.51.100.66")}}
			return base, nil
		case address == root && name == "ns.external.net":
			base.Authorities = []dnswire.ResourceRecord{{Name: "net", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "a.gtld.net"}}
			base.Additionals = []dnswire.ResourceRecord{{Name: "a.gtld.net", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: tld}}
			return base, nil
		case address == tld && name == "ns.external.net" && qtype == dnswire.TypeA:
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: auth}}
			return base, nil
		case address == tld && name == "ns.external.net" && qtype == dnswire.TypeAAAA:
			base.Header.AA = true
			return base, nil
		case address == auth && name == "www.example.com":
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: netip.MustParseAddr("203.0.113.9")}}
			return base, nil
		default:
			t.Fatalf("unexpected exchange address=%s name=%s qtype=%d", address, name, qtype)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ErrorCode != "" {
		t.Fatalf("result=%+v", result)
	}
	if len(result.Delegation) != 1 || len(result.Delegation[0].Addresses) != 1 || result.Delegation[0].Addresses[0] != auth.String() {
		t.Fatalf("delegation=%+v", result.Delegation)
	}
	if len(result.FinalAnswers) != 1 || result.FinalAnswers[0].Address != "203.0.113.9" {
		t.Fatalf("answers=%+v", result.FinalAnswers)
	}
}
