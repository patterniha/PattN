package dnssec

import (
	"testing"
	"time"
)

func TestIANARootTrustAnchorsIncludeCurrentAndSuccessorKSKs(t *testing.T) {
	values := IANARootTrustAnchors()
	if len(values) != 2 {
		t.Fatalf("anchors=%+v", values)
	}
	if values[0].KeyTag != 20326 || values[1].KeyTag != 38696 {
		t.Fatalf("anchors=%+v", values)
	}
	records := TrustAnchorRecords(values)
	if len(records) != 2 || len(records[0].RawData) != 36 || len(records[1].RawData) != 36 {
		t.Fatalf("records=%+v", records)
	}
}


func TestIANARootTrustAnchorAuditIsCurrentBeforeScheduledRollover(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	audit := AuditIANARootTrustAnchors(now, 90*24*time.Hour)
	if !audit.Valid || audit.Stale || audit.ReviewRequired || audit.RolloverReviewRequired {
		t.Fatalf("audit=%+v", audit)
	}
	if audit.Status != "current" || audit.VerifiedDate != "2026-09-24" ||
		audit.RolloverDate != "2026-10-11" {
		t.Fatalf("audit=%+v", audit)
	}
	if len(audit.KeyTags) != 2 || audit.KeyTags[0] != 20326 || audit.KeyTags[1] != 38696 {
		t.Fatalf("keyTags=%v", audit.KeyTags)
	}
}

func TestIANARootTrustAnchorAuditRequiresExplicitPostRolloverReview(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	audit := AuditIANARootTrustAnchors(now, 90*24*time.Hour)
	if !audit.Valid || audit.Stale || !audit.RolloverReviewRequired ||
		!audit.ReviewRequired || audit.Status != "rollover-review-required" {
		t.Fatalf("audit=%+v", audit)
	}
}

func TestIANARootTrustAnchorAuditMarksOldVerificationStale(t *testing.T) {
	now := time.Date(2026, 12, 24, 0, 0, 0, 0, time.UTC)
	audit := AuditIANARootTrustAnchors(now, 30*24*time.Hour)
	if !audit.Stale || !audit.ReviewRequired {
		t.Fatalf("audit=%+v", audit)
	}
}


func TestCompareIANARootTrustAnchorXMLMatchesEmbeddedSnapshot(t *testing.T) {
	xml := []byte(`
<TrustAnchor>
  <Zone>.</Zone>
  <KeyDigest>
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
  <KeyDigest>
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
</TrustAnchor>`)

	comparison, err := CompareIANARootTrustAnchorXML(xml, time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.MatchesEmbedded || len(comparison.MissingFromEmbedded) != 0 || len(comparison.ExtraInEmbedded) != 0 {
		t.Fatalf("comparison=%+v", comparison)
	}
}

func TestCompareIANARootTrustAnchorXMLDetectsPublishedChange(t *testing.T) {
	xml := []byte(`
<TrustAnchor>
  <Zone>.</Zone>
  <KeyDigest>
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
</TrustAnchor>`)

	comparison, err := CompareIANARootTrustAnchorXML(xml, time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if comparison.MatchesEmbedded || len(comparison.ExtraInEmbedded) != 1 {
		t.Fatalf("comparison=%+v", comparison)
	}
}


func TestCompareIANARootTrustAnchorXMLRejectsDuplicateActiveDigest(t *testing.T) {
	xml := []byte(`
<TrustAnchor>
  <Zone>.</Zone>
  <KeyDigest>
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
  <KeyDigest>
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
</TrustAnchor>`)
	if _, err := CompareIANARootTrustAnchorXML(
		xml,
		time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected duplicate active KeyDigest to be rejected")
	}
}

func TestCompareIANARootTrustAnchorXMLRejectsUnexpectedRootElement(t *testing.T) {
	xml := []byte(`<RootAnchors><Zone>.</Zone></RootAnchors>`)
	if _, err := CompareIANARootTrustAnchorXML(
		xml,
		time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected unexpected XML root element to be rejected")
	}
}

func TestCompareIANARootTrustAnchorXMLIgnoresExpiredKeyDigest(t *testing.T) {
	xml := []byte(`
<TrustAnchor>
  <Zone>.</Zone>
  <KeyDigest validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
    <KeyTag>19036</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
  </KeyDigest>
  <KeyDigest validFrom="2017-02-02T00:00:00+00:00">
    <KeyTag>20326</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
  </KeyDigest>
  <KeyDigest validFrom="2024-07-18T00:00:00+00:00">
    <KeyTag>38696</KeyTag>
    <Algorithm>8</Algorithm>
    <DigestType>2</DigestType>
    <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
  </KeyDigest>
</TrustAnchor>`)

	comparison, err := CompareIANARootTrustAnchorXML(
		xml,
		time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !comparison.MatchesEmbedded {
		t.Fatalf("comparison=%+v", comparison)
	}
	if len(comparison.PublishedKeyTags) != 2 ||
		comparison.PublishedKeyTags[0] != 20326 ||
		comparison.PublishedKeyTags[1] != 38696 {
		t.Fatalf("publishedKeyTags=%v", comparison.PublishedKeyTags)
	}
}
