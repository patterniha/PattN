package dnsvalidate

import (
	"context"
	"strings"
	"testing"
	"time"

	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

func TestFindSignerPrefersRelevantSignature(t *testing.T) {
	rdata := make([]byte, 18)
	rdata[1] = byte(dnswire.TypeA)
	rdata[2] = 15
	rdata[3] = 2
	rdata = append(rdata, 0x07)
	rdata = append(rdata, []byte("example")...)
	rdata = append(rdata, 0x03)
	rdata = append(rdata, []byte("com")...)
	rdata = append(rdata, 0)
	rdata = append(rdata, make([]byte, 64)...)
	record := dnswire.ResourceRecord{Name: "www.example.com", Type: dnswire.TypeRRSIG, RawData: rdata}
	if _, err := dnssec.ParseRRSIG(record); err != nil {
		t.Fatal(err)
	}
	if got := findSigner([]dnswire.ResourceRecord{record}, nil, "www.example.com", dnswire.TypeA); got != "example.com" {
		t.Fatalf("signer=%q", got)
	}
}

func TestHasRRTypeForOwner(t *testing.T) {
	records := []dnswire.ResourceRecord{
		{Name: "target.example", Type: dnswire.TypeAAAA},
		{Name: "unrelated.example", Type: dnswire.TypeA},
	}
	if !hasRRTypeForOwner(records, "target.example", dnswire.TypeAAAA) ||
		hasRRTypeForOwner(records, "target.example", dnswire.TypeA) {
		t.Fatalf("records=%+v", records)
	}
}

func TestTerminalQueryNameUsesFinalAnswerOwnerAfterCNAMETraversal(t *testing.T) {
	trace := dnstrace.Result{
		Domain: "alias.example",
		Hops: []dnstrace.Hop{{QueryName: "target.example"}},
		FinalAnswers: []dnstrace.Record{{Name: "target.example", Type: dnswire.TypeA, Address: "203.0.113.8"}},
	}
	if got := terminalQueryName(trace, "alias.example"); got != "target.example" {
		t.Fatalf("terminal=%q", got)
	}
}

func TestFindSignerSupportsDnameAliasSignatures(t *testing.T) {
	rdata := make([]byte, 18)
	rdata[1] = byte(dnswire.TypeDNAME)
	rdata[2] = 15
	rdata[3] = 2
	rdata = append(rdata, 0x07)
	rdata = append(rdata, []byte("example")...)
	rdata = append(rdata, 0)
	rdata = append(rdata, make([]byte, 64)...)
	record := dnswire.ResourceRecord{
		Name: "alias.example",
		Type: dnswire.TypeRRSIG,
		RawData: rdata,
	}
	if _, err := dnssec.ParseRRSIG(record); err != nil {
		t.Fatal(err)
	}
	if got := findSigner(
		[]dnswire.ResourceRecord{record},
		nil,
		"alias.example",
		dnswire.TypeDNAME,
	); got != "example" {
		t.Fatalf("signer=%q", got)
	}
}

func TestEmptyAliasChainIsVacuouslyAuthenticated(t *testing.T) {
	values, authenticated, bogus, err := validateAliasChain(
		context.Background(),
		dnstrace.Result{},
		dnstrace.Options{},
		time.Unix(0, 0).UTC(),
	)
	if err != nil || len(values) != 0 || !authenticated || bogus {
		t.Fatalf("values=%+v authenticated=%v bogus=%v err=%v", values, authenticated, bogus, err)
	}
}

func TestFindSignerFailsClosedOnAmbiguousRelevantSigners(t *testing.T) {
	makeSig := func(signer string) dnswire.ResourceRecord {
		rdata := make([]byte, 18)
		rdata[1] = byte(dnswire.TypeA)
		rdata[2] = 15
		rdata[3] = 2
		for _, label := range strings.Split(signer, ".") {
			rdata = append(rdata, byte(len(label)))
			rdata = append(rdata, []byte(label)...)
		}
		rdata = append(rdata, 0)
		rdata = append(rdata, make([]byte, 64)...)
		return dnswire.ResourceRecord{Name: "www.example.com", Type: dnswire.TypeRRSIG, RawData: rdata}
	}
	records := []dnswire.ResourceRecord{makeSig("example.com"), makeSig("other.example")}
	if got := findSigner(records, nil, "www.example.com", dnswire.TypeA); got != "" {
		t.Fatalf("ambiguous signer=%q", got)
	}
}

func TestSignerMustMatchAuthenticatedAuthoritativeZone(t *testing.T) {
	if !signerMatchesAuthoritativeZone("example.com.", "EXAMPLE.COM") {
		t.Fatal("equivalent authoritative zone names should match")
	}
	if signerMatchesAuthoritativeZone("attacker.example", "victim.example") {
		t.Fatal("cross-zone signer must not authenticate a victim zone RRset")
	}
	if signerMatchesAuthoritativeZone("", "victim.example") ||
		signerMatchesAuthoritativeZone("victim.example", "") {
		t.Fatal("missing signer or authoritative zone must fail closed")
	}
}
