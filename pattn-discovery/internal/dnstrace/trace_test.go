package dnstrace

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnswire"
)

func TestTraceFollowsReferralGlueToAuthoritativeAnswer(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	auth := netip.MustParseAddr("192.0.2.53")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, recursionDesired bool) (dnsmeasure.Observation, error) {
		if recursionDesired {
			t.Fatal("iterative trace requested recursion")
		}
		if transport != dnsmeasure.UDP {
			t.Fatalf("unexpected transport %q", transport)
		}
		switch address {
		case root:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true},
				Authorities: []dnswire.ResourceRecord{{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com"}},
				Additionals: []dnswire.ResourceRecord{{Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: auth}},
			}, nil
		case auth:
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true, AA: true},
				Answers: []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: netip.MustParseAddr("203.0.113.9")}},
			}, nil
		default:
			t.Fatalf("unexpected nameserver %s", address)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{RootServers: []netip.Addr{root}, Exchange: exchange})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ErrorCode != "" || len(result.Hops) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.FinalAnswers) != 1 || result.FinalAnswers[0].Address != "203.0.113.9" {
		t.Fatalf("answers=%+v", result.FinalAnswers)
	}
	if result.TerminalZone != "example.com" {
		t.Fatalf("terminalZone=%q", result.TerminalZone)
	}
}

func TestTraceFallsBackToTCPWhenUDPIsTruncated(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	calls := 0
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		calls++
		if transport == dnsmeasure.UDP {
			return dnsmeasure.Observation{
				Address: address, Domain: name, QueryType: qtype, Transport: transport,
				Header: dnswire.Header{QR: true, TC: true},
			}, nil
		}
		return dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true, AA: true},
			Answers: []dnswire.ResourceRecord{{Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: netip.MustParseAddr("203.0.113.10")}},
		}, nil
	}
	result, err := Trace(context.Background(), "example.com", dnswire.TypeA, Options{RootServers: []netip.Addr{root}, Exchange: exchange})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.Hops) != 1 || result.Hops[0].Transport != dnsmeasure.TCP || !result.Complete {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
}


func TestTraceIgnoresUnrelatedAddressInAnswerSection(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	auth := netip.MustParseAddr("192.0.2.53")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		base := dnsmeasure.Observation{Address: address, Domain: name, QueryType: qtype, Transport: transport, Header: dnswire.Header{QR: true}}
		switch address {
		case root:
			base.Answers = []dnswire.ResourceRecord{{
				Name: "unrelated.example", Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("198.51.100.66"),
			}}
			base.Authorities = []dnswire.ResourceRecord{{
				Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com",
			}}
			base.Additionals = []dnswire.ResourceRecord{{
				Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: auth,
			}}
			return base, nil
		case auth:
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("203.0.113.9"),
			}}
			return base, nil
		default:
			t.Fatalf("unexpected nameserver %s", address)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root}, Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Hops) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.FinalAnswers) != 1 || result.FinalAnswers[0].Address != "203.0.113.9" {
		t.Fatalf("answers=%+v", result.FinalAnswers)
	}
}

func TestTraceIgnoresUnrelatedCNAMEInAnswerSection(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	auth := netip.MustParseAddr("192.0.2.53")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		base := dnsmeasure.Observation{Address: address, Domain: name, QueryType: qtype, Transport: transport, Header: dnswire.Header{QR: true}}
		switch address {
		case root:
			if name != "www.example.com" {
				t.Fatalf("unrelated CNAME redirected trace to %q", name)
			}
			base.Answers = []dnswire.ResourceRecord{{
				Name: "other.example", Type: dnswire.TypeCNAME, Class: dnswire.ClassIN, Target: "attacker.example",
			}}
			base.Authorities = []dnswire.ResourceRecord{{
				Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com",
			}}
			base.Additionals = []dnswire.ResourceRecord{{
				Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: auth,
			}}
			return base, nil
		case auth:
			base.Header.AA = true
			base.Answers = []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("203.0.113.10"),
			}}
			return base, nil
		default:
			t.Fatalf("unexpected nameserver %s", address)
			return dnsmeasure.Observation{}, nil
		}
	}

	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root}, Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Hops) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if len(result.FinalAnswers) != 1 || result.FinalAnswers[0].Address != "203.0.113.10" {
		t.Fatalf("answers=%+v", result.FinalAnswers)
	}
}

func TestAnswerChainAcceptsOnlyRecordsReachableFromQuestion(t *testing.T) {
	values := []dnswire.ResourceRecord{
		{Name: "www.example.com", Type: dnswire.TypeCNAME, Target: "edge.example.net"},
		{Name: "edge.example.net", Type: dnswire.TypeA, Address: netip.MustParseAddr("203.0.113.20")},
		{Name: "unrelated.example", Type: dnswire.TypeA, Address: netip.MustParseAddr("198.51.100.20")},
	}
	answers, cname, conflict, loop := answerChain(values, "www.example.com", dnswire.TypeA)
	if conflict || loop || cname != "" || len(answers) != 1 || answers[0].Name != "edge.example.net" {
		t.Fatalf("answers=%+v cname=%q conflict=%v loop=%v", answers, cname, conflict, loop)
	}
}


func TestAnswerChainDetailedFollowsDnameAndMatchingSynthesizedCname(t *testing.T) {
	values := []dnswire.ResourceRecord{
		{Name: "example.com", Type: dnswire.TypeDNAME, Target: "example.net"},
		{Name: "www.sub.example.com", Type: dnswire.TypeCNAME, Target: "www.sub.example.net"},
	}
	answers, aliases, next, conflict, loop, err := answerChainDetailed(
		values,
		"www.sub.example.com",
		dnswire.TypeA,
	)
	if err != nil || conflict || loop || len(answers) != 0 {
		t.Fatalf("answers=%+v aliases=%+v next=%q conflict=%v loop=%v err=%v", answers, aliases, next, conflict, loop, err)
	}
	if next != "www.sub.example.net" || len(aliases) != 1 {
		t.Fatalf("aliases=%+v next=%q", aliases, next)
	}
	step := aliases[0]
	if step.Type != dnswire.TypeDNAME || step.Owner != "example.com" ||
		step.Target != "example.net" || step.ResultName != "www.sub.example.net" || !step.Synthesized {
		t.Fatalf("step=%+v", step)
	}
}

func TestAnswerChainDetailedRejectsContradictoryDnameAndSynthesizedCname(t *testing.T) {
	values := []dnswire.ResourceRecord{
		{Name: "example.com", Type: dnswire.TypeDNAME, Target: "example.net"},
		{Name: "www.example.com", Type: dnswire.TypeCNAME, Target: "attacker.example"},
	}
	_, _, _, conflict, loop, err := answerChainDetailed(values, "www.example.com", dnswire.TypeA)
	if err != nil || !conflict || loop {
		t.Fatalf("conflict=%v loop=%v err=%v", conflict, loop, err)
	}
}

func TestSynthesizeDnameRejectsOversizedResult(t *testing.T) {
	label := strings.Repeat("a", 63)
	query := strings.Join([]string{label, label, label, label, "example", "com"}, ".")
	_, err := synthesizeDNAME(query, "example.com", "target.example")
	if err == nil {
		t.Fatal("expected synthesized DNS name length failure")
	}
}

func TestTracePreservesAuthoritativeAliasEvidenceAcrossRootRestart(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		observation := dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true, AA: true},
		}
		switch name {
		case "alias.example":
			observation.Answers = []dnswire.ResourceRecord{
				{Name: name, Type: dnswire.TypeCNAME, Class: dnswire.ClassIN, Target: "target.example"},
				{Name: name, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN},
			}
		case "target.example":
			observation.Answers = []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("203.0.113.77"),
			}}
		default:
			t.Fatalf("unexpected query name %q", name)
		}
		return observation, nil
	}
	result, err := Trace(context.Background(), "alias.example", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.AliasChain) != 1 || len(result.WireAnswers) != 3 {
		t.Fatalf("result=%+v wireAnswers=%+v", result, result.WireAnswers)
	}
	if result.AliasChain[0].Type != dnswire.TypeCNAME ||
		result.AliasChain[0].ResultName != "target.example" {
		t.Fatalf("alias=%+v", result.AliasChain[0])
	}
}

func TestTraceDoesNotAcceptTerminalAnswerFromNonAuthoritativeReferral(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	auth := netip.MustParseAddr("192.0.2.53")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		observation := dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true},
		}
		if address == root {
			observation.Answers = []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("198.51.100.66"),
			}}
			observation.Authorities = []dnswire.ResourceRecord{{
				Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com",
			}}
			observation.Additionals = []dnswire.ResourceRecord{{
				Name: "ns1.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, Address: auth,
			}}
			return observation, nil
		}
		if address == auth {
			observation.Header.AA = true
			observation.Answers = []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("203.0.113.88"),
			}}
			return observation, nil
		}
		t.Fatalf("unexpected nameserver %s", address)
		return dnsmeasure.Observation{}, nil
	}
	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.FinalAnswers) != 1 ||
		result.FinalAnswers[0].Address != "203.0.113.88" {
		t.Fatalf("result=%+v", result)
	}
}

func TestTraceRetriesAlternateServerAfterRetryableRCode(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	var queried []netip.Addr
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		queried = append(queried, address)
		observation := dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true},
		}
		if address == first {
			observation.Header.RCode = 2 // SERVFAIL: try another authority.
			return observation, nil
		}
		observation.Header.AA = true
		observation.Answers = []dnswire.ResourceRecord{{
			Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
			Address: netip.MustParseAddr("203.0.113.44"),
		}}
		return observation, nil
	}

	result, err := Trace(context.Background(), "example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{first, second},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.TerminalRCode != 0 || len(result.FinalAnswers) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if len(queried) != 2 || queried[0] != first || queried[1] != second {
		t.Fatalf("queried=%v", queried)
	}
}

func TestTraceReportsUnusableRCodeWhenAllServersFail(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		return dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true, RCode: 5},
		}, nil
	}

	result, err := Trace(context.Background(), "example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{first, second},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.TerminalRCode != 5 || result.ErrorCode != "unusable_rcode" {
		t.Fatalf("result=%+v", result)
	}
}

func TestTraceRetriesAlternateServerAfterNonAuthoritativeTerminalAnswer(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	var queried []netip.Addr
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		queried = append(queried, address)
		observation := dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true},
			Answers: []dnswire.ResourceRecord{{
				Name: name, Type: dnswire.TypeA, Class: dnswire.ClassIN,
				Address: netip.MustParseAddr("203.0.113.50"),
			}},
		}
		if address == second {
			observation.Header.AA = true
			observation.Answers[0].Address = netip.MustParseAddr("203.0.113.51")
		}
		return observation, nil
	}

	result, err := Trace(context.Background(), "example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{first, second},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ErrorCode != "" || len(result.FinalAnswers) != 1 ||
		result.FinalAnswers[0].Address != "203.0.113.51" {
		t.Fatalf("result=%+v", result)
	}
	if len(queried) != 2 || queried[0] != first || queried[1] != second {
		t.Fatalf("queried=%v", queried)
	}
}

func TestAnswerChainRejectsConflictingCnameTargets(t *testing.T) {
	values := []dnswire.ResourceRecord{
		{Name: "www.example.com", Type: dnswire.TypeCNAME, Target: "edge-a.example.net"},
		{Name: "www.example.com", Type: dnswire.TypeCNAME, Target: "edge-b.example.net"},
	}
	answers, cname, conflict, loop := answerChain(values, "www.example.com", dnswire.TypeA)
	if len(answers) != 0 || cname != "" || !conflict || loop {
		t.Fatalf("answers=%+v cname=%q conflict=%v loop=%v", answers, cname, conflict, loop)
	}
}

func TestAnswerChainRejectsCnameMixedWithTerminalData(t *testing.T) {
	values := []dnswire.ResourceRecord{
		{Name: "www.example.com", Type: dnswire.TypeCNAME, Target: "edge.example.net"},
		{Name: "www.example.com", Type: dnswire.TypeA, Address: netip.MustParseAddr("203.0.113.45")},
	}
	answers, cname, conflict, loop := answerChain(values, "www.example.com", dnswire.TypeA)
	if len(answers) != 0 || cname != "" || !conflict || loop {
		t.Fatalf("answers=%+v cname=%q conflict=%v loop=%v", answers, cname, conflict, loop)
	}
}

func TestTraceRejectsAmbiguousReferralOwners(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		if address != root {
			t.Fatalf("unexpected nameserver %s", address)
		}
		return dnsmeasure.Observation{
			Address: address,
			Domain: name,
			QueryType: qtype,
			Transport: transport,
			Header: dnswire.Header{QR: true},
			Authorities: []dnswire.ResourceRecord{
				{Name: "com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "a.gtld.example"},
				{Name: "example.com", Type: dnswire.TypeNS, Class: dnswire.ClassIN, Target: "ns1.example.com"},
			},
		}, nil
	}

	result, err := Trace(context.Background(), "www.example.com", dnswire.TypeA, Options{
		RootServers: []netip.Addr{root},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.ErrorCode != "invalid_referral" {
		t.Fatalf("result=%+v", result)
	}
}
