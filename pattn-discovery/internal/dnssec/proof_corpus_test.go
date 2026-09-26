package dnssec

import (
	"strings"
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestDenialProofCorpus_NSECIncompleteWithoutWildcardCoverage(t *testing.T) {
	values := []NSEC{
		{Owner: "example.com", NextDomain: "*.example.com", Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS}},
		{Owner: "m.example.com", NextDomain: "z.example.com", Types: []uint16{dnswire.TypeA}},
	}
	proof := ComposeNSECProof("x.y.example.com", dnswire.TypeA, 3, values)
	if proof.Complete || proof.Status != ProofIncomplete || !proof.ClosestEncloserOK || !proof.NextCloserOK {
		t.Fatalf("proof=%+v", proof)
	}
	if proof.WildcardOK {
		t.Fatalf("wildcard proof unexpectedly complete: %+v", proof)
	}
}

func TestDenialProofCorpus_NSECExactNameWithCnameDoesNotProveNoData(t *testing.T) {
	proof := ComposeNSECProof("alias.example.com", dnswire.TypeAAAA, 0, []NSEC{{
		Owner: "alias.example.com", NextDomain: "b.example.com",
		Types: []uint16{dnswire.TypeA, dnswire.TypeCNAME},
	}})
	if proof.Complete || proof.Status != ProofIncomplete || proof.CNAMEAbsent {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3NoData(t *testing.T) {
	const zone = "example.com"
	const query = "host.example.com"
	hash, err := NSEC3Hash(query, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	proof := ComposeNSEC3Proof(query, dnswire.TypeAAAA, 0, []NSEC3{{
		OwnerHash: hash,
		Zone: zone,
		HashAlgorithm: 1,
		Iterations: 0,
		Salt: "",
		NextHash: strings.Repeat("V", len(hash)),
		Types: []uint16{dnswire.TypeA},
	}})
	if !proof.Complete || proof.Status != ProofNODATA || !proof.ExactNameOK || !proof.TypeAbsent || !proof.CNAMEAbsent {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3CompleteNxDomain(t *testing.T) {
	const zone = "example.com"
	const query = "missing.example.com"
	closestHash, err := NSEC3Hash(zone, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	width := len(closestHash)
	values := []NSEC3{
		{
			OwnerHash: closestHash,
			Zone: zone,
			HashAlgorithm: 1,
			Iterations: 0,
			Salt: "",
			NextHash: strings.Repeat("V", width),
			Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS},
		},
		{
			OwnerHash: strings.Repeat("0", width),
			Zone: zone,
			HashAlgorithm: 1,
			Iterations: 0,
			Salt: "",
			NextHash: strings.Repeat("V", width),
			Types: []uint16{dnswire.TypeA},
		},
	}
	proof := ComposeNSEC3Proof(query, dnswire.TypeA, 3, values)
	if !proof.Complete || proof.Status != ProofNXDOMAIN ||
		!proof.ClosestEncloserOK || !proof.NextCloserOK || !proof.WildcardOK {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3OptOutCanRepresentInsecureDsDelegation(t *testing.T) {
	const zone = "example.com"
	const query = "child.example.com"
	closestHash, err := NSEC3Hash(zone, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	width := len(closestHash)
	values := []NSEC3{
		{
			OwnerHash: closestHash,
			Zone: zone,
			HashAlgorithm: 1,
			Iterations: 0,
			Salt: "",
			NextHash: strings.Repeat("V", width),
			Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS},
		},
		{
			OwnerHash: strings.Repeat("0", width),
			Zone: zone,
			HashAlgorithm: 1,
			Flags: 1,
			Iterations: 0,
			Salt: "",
			NextHash: strings.Repeat("V", width),
			Types: []uint16{dnswire.TypeNS},
		},
	}
	proof := ComposeNSEC3Proof(query, dnswire.TypeDS, 0, values)
	if !proof.Complete || proof.Status != ProofInsecureDelegation ||
		!proof.InsecureDelegation || !proof.OptOut || !proof.NextCloserOK {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSECExactDelegationProvesInsecureDSAbsence(t *testing.T) {
	proof := ComposeNSECProof("child.example.com", dnswire.TypeDS, 0, []NSEC{{
		Owner: "child.example.com",
		NextDomain: "z.example.com",
		Types: []uint16{dnswire.TypeNS, dnswire.TypeRRSIG, dnswire.TypeNSEC},
	}})
	if !proof.Complete || proof.Status != ProofInsecureDelegation ||
		!proof.InsecureDelegation || !proof.ExactNameOK || !proof.TypeAbsent {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSECApexNoDataDoesNotClaimDelegation(t *testing.T) {
	proof := ComposeNSECProof("example.com", dnswire.TypeDS, 0, []NSEC{{
		Owner: "example.com",
		NextDomain: "z.example.com",
		Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS, dnswire.TypeRRSIG, dnswire.TypeNSEC},
	}})
	if !proof.Complete || proof.Status != ProofNODATA || proof.InsecureDelegation {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSECNoDataWithoutDelegationDoesNotClaimInsecureBoundary(t *testing.T) {
	proof := ComposeNSECProof("host.example.com", dnswire.TypeDS, 0, []NSEC{{
		Owner: "host.example.com",
		NextDomain: "z.example.com",
		Types: []uint16{dnswire.TypeA, dnswire.TypeRRSIG, dnswire.TypeNSEC},
	}})
	if !proof.Complete || proof.Status != ProofNODATA || proof.InsecureDelegation {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3ExactDelegationProvesInsecureDSAbsence(t *testing.T) {
	const zone = "example.com"
	const query = "child.example.com"
	hash, err := NSEC3Hash(query, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	proof := ComposeNSEC3Proof(query, dnswire.TypeDS, 0, []NSEC3{{
		OwnerHash: hash,
		Zone: zone,
		HashAlgorithm: 1,
		Iterations: 0,
		Salt: "",
		NextHash: strings.Repeat("V", len(hash)),
		Types: []uint16{dnswire.TypeNS, dnswire.TypeRRSIG},
	}})
	if !proof.Complete || proof.Status != ProofInsecureDelegation ||
		!proof.InsecureDelegation || !proof.ExactNameOK || !proof.TypeAbsent {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3ExactApexNoDataDoesNotClaimDelegation(t *testing.T) {
	const zone = "example.com"
	hash, err := NSEC3Hash(zone, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	proof := ComposeNSEC3Proof(zone, dnswire.TypeDS, 0, []NSEC3{{
		OwnerHash: hash,
		Zone: zone,
		HashAlgorithm: 1,
		Iterations: 0,
		Salt: "",
		NextHash: strings.Repeat("V", len(hash)),
		Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS, dnswire.TypeRRSIG},
	}})
	if !proof.Complete || proof.Status != ProofNODATA || proof.InsecureDelegation {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestDenialProofCorpus_NSEC3ParameterMismatchIsUnsupported(t *testing.T) {
	const zone = "example.com"
	hash, err := NSEC3Hash(zone, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	values := []NSEC3{
		{OwnerHash: hash, Zone: zone, HashAlgorithm: 1, Iterations: 0, Salt: "", NextHash: "F"},
		{OwnerHash: "0", Zone: zone, HashAlgorithm: 1, Iterations: 1, Salt: "", NextHash: "F"},
	}
	proof := ComposeNSEC3Proof("missing.example.com", dnswire.TypeA, 3, values)
	if proof.Status != ProofUnsupported || proof.Complete {
		t.Fatalf("proof=%+v", proof)
	}
}
