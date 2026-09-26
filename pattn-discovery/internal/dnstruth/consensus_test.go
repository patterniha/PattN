package dnstruth

import "testing"

func TestAggregateKeepsEvidenceSeparateFromVerdict(t *testing.T) {
	result := Aggregate([]Observation{
		{Source: "authoritative", Kind: SourceAuthoritative, Signature: "A"},
		{Source: "cloudflare", Kind: SourceTrusted, Signature: "A"},
		{Source: "google", Kind: SourceTrusted, Signature: "A"},
		{Source: "quad9", Kind: SourceTrusted, Signature: "B"},
		{Source: "candidate", Kind: SourceCandidate, Signature: "A"},
		{Source: "failed", Kind: SourceTrusted, Error: "timeout"},
	})
	if result.EvidenceCount != 6 || result.ValidEvidenceCount != 5 {
		t.Fatalf("counts=%+v", result)
	}
	if !result.Divergent || result.Unanimous {
		t.Fatalf("agreement=%+v", result)
	}
	if result.DominantSignature != "A" || result.DominantCount != 4 {
		t.Fatalf("dominant=%+v", result)
	}
	if len(result.Groups) != 2 || result.Groups[0].AuthoritativeCount != 1 {
		t.Fatalf("groups=%+v", result.Groups)
	}
}

func TestAggregateDoesNotTreatFailuresAsDisagreement(t *testing.T) {
	result := Aggregate([]Observation{
		{Source: "one", Kind: SourceTrusted, Signature: "A"},
		{Source: "two", Kind: SourceTrusted, Error: "timeout"},
	})
	if !result.Unanimous || result.Divergent || result.ValidEvidenceCount != 1 {
		t.Fatalf("result=%+v", result)
	}
}
