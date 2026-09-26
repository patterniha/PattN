package dnssec

import (
	"encoding/base32"
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestParseAndEvaluateNSECNoData(t *testing.T) {
	next, _ := canonicalNameWire("z.example.com")
	bitmap := []byte{0, 6, 0x40, 0, 0, 0, 0, 0x02}
	rdata := append(next, bitmap...)
	record := dnswire.ResourceRecord{
		Name: "a.example.com", Type: dnswire.TypeNSEC, Class: dnswire.ClassIN,
		RawData: rdata, CanonicalRData: rdata,
	}
	value, err := ParseNSEC(record)
	if err != nil {
		t.Fatal(err)
	}
	evidence := EvaluateNSEC("a.example.com", dnswire.TypeAAAA, value)
	if evidence.Status != DenialNODATA || !evidence.ExactName || !evidence.TypeAbsent {
		t.Fatalf("evidence=%+v value=%+v", evidence, value)
	}
}

func TestNSECIntervalCoverageWraps(t *testing.T) {
	if !canonicalNameIntervalContains("z.example", "b.example", "zz.example") {
		t.Fatal("expected wrapped interval to contain query")
	}
}

func TestNSEC3HashKnownShapeAndCoverage(t *testing.T) {
	hash, err := NSEC3Hash("example.com", 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(hash)
	if err != nil || len(decoded) != 20 {
		t.Fatalf("hash=%q len=%d err=%v", hash, len(decoded), err)
	}
	value := NSEC3{
		OwnerHash: hash,
		Zone: "example.com",
		HashAlgorithm: 1,
		Iterations: 0,
		Salt: "",
		NextHash: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		Types: []uint16{dnswire.TypeA},
	}
	evidence := EvaluateNSEC3("example.com", dnswire.TypeAAAA, value)
	if evidence.Status != DenialNODATA || !evidence.ExactName {
		t.Fatalf("evidence=%+v", evidence)
	}
}
