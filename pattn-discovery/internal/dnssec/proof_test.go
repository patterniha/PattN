package dnssec

import (
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestComposeNSECProofRequiresClosestNextAndWildcard(t *testing.T) {
	values := []NSEC{
		{Owner: "example.com", NextDomain: "m.example.com", Types: []uint16{dnswire.TypeSOA, dnswire.TypeNS}},
		{Owner: "m.example.com", NextDomain: "z.example.com", Types: []uint16{dnswire.TypeA}},
		{Owner: "z.example.com", NextDomain: "example.com", Types: []uint16{dnswire.TypeA}},
	}
	proof := ComposeNSECProof("x.y.example.com", dnswire.TypeA, 3, values)
	if proof.ClosestEncloser != "example.com" || proof.NextCloser != "y.example.com" || proof.WildcardName != "*.example.com" {
		t.Fatalf("proof=%+v", proof)
	}
	if !proof.ClosestEncloserOK || !proof.NextCloserOK || !proof.WildcardOK || !proof.Complete || proof.Status != ProofNXDOMAIN {
		t.Fatalf("proof=%+v", proof)
	}
}

func TestComposeNSECProofNoData(t *testing.T) {
	proof := ComposeNSECProof("a.example.com", dnswire.TypeAAAA, 0, []NSEC{{
		Owner: "a.example.com", NextDomain: "b.example.com", Types: []uint16{dnswire.TypeA},
	}})
	if !proof.Complete || proof.Status != ProofNODATA || !proof.TypeAbsent || !proof.CNAMEAbsent {
		t.Fatalf("proof=%+v", proof)
	}
}
