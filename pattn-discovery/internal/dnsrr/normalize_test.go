package dnsrr

import (
	"net/netip"
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestAnswerSignatureIgnoresTTLAndOrder(t *testing.T) {
	left := []dnswire.ResourceRecord{
		{Name: "Example.COM.", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 10, Address: netip.MustParseAddr("203.0.113.2")},
		{Name: "example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 20, Address: netip.MustParseAddr("203.0.113.1")},
	}
	right := []dnswire.ResourceRecord{
		{Name: "example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 999, Address: netip.MustParseAddr("203.0.113.1")},
		{Name: "EXAMPLE.COM", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 1, Address: netip.MustParseAddr("203.0.113.2")},
	}
	if !EquivalentAnswers(0, left, 0, right, dnswire.TypeA) {
		t.Fatalf("left=%q right=%q", AnswerSignature(0, left, dnswire.TypeA), AnswerSignature(0, right, dnswire.TypeA))
	}
}

func TestAnswerSignatureIncludesRCode(t *testing.T) {
	if EquivalentAnswers(0, nil, 3, nil, dnswire.TypeA) {
		t.Fatal("different rcodes considered equivalent")
	}
}
