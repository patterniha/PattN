package dnsfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReplayManifestValidatesParserAndDenialSemantics(t *testing.T) {
	results, err := ReplayManifest("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results=%d", len(results))
	}
	for _, result := range results {
		if result.AuthenticationScope != "not-evaluated-single-packet" {
			t.Fatalf("authenticationScope=%q", result.AuthenticationScope)
		}
	}
	var foundNODATA bool
	for _, result := range results {
		for _, denial := range result.DenialEvidence {
			if denial.Mechanism == "nsec" && denial.Status == "nodata-evidence" {
				foundNODATA = true
			}
		}
	}
	if !foundNODATA {
		t.Fatalf("missing NSEC NODATA result: %+v", results)
	}
}

func TestManifestRejectsTraversal(t *testing.T) {
	manifest := Manifest{
		Version: ManifestVersion,
		Entries: []ManifestEntry{{Path: "../secret.json"}},
	}
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("err=%v", err)
	}
}

func TestManifestRejectsBackslashTraversalAlias(t *testing.T) {
	manifest := Manifest{
		Version: ManifestVersion,
		Entries: []ManifestEntry{{Path: "..\\secret.json"}},
	}
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("err=%v", err)
	}
}

func TestCapturedFixtureRequiresMatchingHumanReviewMetadata(t *testing.T) {
	root := t.TempDir()
	fixture, err := NewCaptured(
		"reviewed A",
		"udp://192.0.2.53:53",
		time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC),
		"example.com",
		1,
		0x1234,
		[]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(root, "captured.json")
	if err := fixture.Save(fixturePath); err != nil {
		t.Fatal(err)
	}

	manifest := Manifest{
		Version: ManifestVersion,
		Entries: []ManifestEntry{{
			Path: "captured.json",
			Expected: ManifestExpected{},
		}},
	}
	raw, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayManifest(manifestPath); err == nil || !strings.Contains(err.Error(), "human review") {
		t.Fatalf("err=%v", err)
	}

	manifest.Entries[0].Review = &ManifestReview{
		Reviewer: "reviewer@example",
		ReviewedAt: "2026-09-25T10:30:00Z",
		Case: "a",
		FixtureSHA256: fixture.SHA256,
		ReplayExpectation: "REVIEW_AND_CONFIRM: packet parses as an A-query response fixture",
	}
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayManifest(manifestPath); err == nil || !strings.Contains(err.Error(), "template placeholder") {
		t.Fatalf("err=%v", err)
	}

	manifest.Entries[0].Review.ReplayExpectation = "packet parses as an A-query response fixture"
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayManifest(manifestPath); err != nil {
		t.Fatal(err)
	}
}

func TestManifestExpectedRejectsSemanticMismatch(t *testing.T) {
	fixture, err := Load("testdata/example-a.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ReplaySemantics(fixture)
	if err != nil {
		t.Fatal(err)
	}
	want := uint8(3)
	if err := (ManifestExpected{RCode: &want}).Validate(result); err == nil {
		t.Fatal("expected semantic mismatch")
	}
}
