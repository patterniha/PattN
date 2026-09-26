package dnsfixture

import (
	"encoding/json"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnswire"
)

const ManifestVersion = 1

type Manifest struct {
	Version int             `json:"version"`
	Entries []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Path     string           `json:"path"`
	Tags     []string         `json:"tags,omitempty"`
	Review   *ManifestReview  `json:"review,omitempty"`
	Expected ManifestExpected `json:"expected"`
}

type ManifestReview struct {
	Reviewer          string `json:"reviewer"`
	ReviewedAt        string `json:"reviewedAt"`
	Case              string `json:"case"`
	FixtureSHA256     string `json:"fixtureSha256"`
	ReplayExpectation string `json:"replayExpectation"`
}

func (r ManifestReview) Validate(fixture Fixture) error {
	reviewer := strings.TrimSpace(r.Reviewer)
	if reviewer == "" {
		return fmt.Errorf("captured fixture review requires reviewer")
	}
	upperReviewer := strings.ToUpper(reviewer)
	if strings.HasPrefix(upperReviewer, "REPLACE_") || upperReviewer == "TBD" || len(reviewer) > 256 {
		return fmt.Errorf("captured fixture review has placeholder/invalid reviewer")
	}

	reviewedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(r.ReviewedAt))
	if err != nil {
		return fmt.Errorf("captured fixture review has invalid reviewedAt: %w", err)
	}
	capturedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(fixture.CapturedAt))
	if err != nil {
		return fmt.Errorf("captured fixture review cannot validate fixture capturedAt: %w", err)
	}
	if reviewedAt.Before(capturedAt) {
		return fmt.Errorf("captured fixture review predates the capture")
	}
	if reviewedAt.After(time.Now().UTC().Add(5 * time.Minute)) {
		return fmt.Errorf("captured fixture review time is implausibly in the future")
	}

	allowedCases := map[string]bool{
		"a": true, "aaaa": true, "cname": true, "dname": true,
		"nxdomain": true, "nodata": true, "nsec": true, "nsec3": true,
		"ds": true, "dnskey": true, "rrsig": true,
	}
	caseName := strings.ToLower(strings.TrimSpace(r.Case))
	if !allowedCases[caseName] {
		return fmt.Errorf("captured fixture review has unsupported case %q", r.Case)
	}
	if !strings.EqualFold(strings.TrimSpace(r.FixtureSHA256), fixture.SHA256) {
		return fmt.Errorf("captured fixture review sha256 does not match fixture")
	}
	expectation := strings.TrimSpace(r.ReplayExpectation)
	upperExpectation := strings.ToUpper(expectation)
	if expectation == "" ||
		strings.HasPrefix(upperExpectation, "REPLACE_") ||
		strings.HasPrefix(upperExpectation, "REVIEW_AND_CONFIRM:") ||
		upperExpectation == "TBD" ||
		len(expectation) > 2048 {
		return fmt.Errorf("captured fixture review requires a confirmed replayExpectation, not a template placeholder")
	}
	if err := ValidateReviewCase(caseName, fixture); err != nil {
		return fmt.Errorf("captured fixture review case mismatch: %w", err)
	}
	return nil
}

type ManifestExpected struct {
	RCode           *uint8   `json:"rcode,omitempty"`
	AnswerCount     *int     `json:"answerCount,omitempty"`
	AnswerTypes     []uint16 `json:"answerTypes,omitempty"`
	DenialMechanism string   `json:"denialMechanism,omitempty"`
	DenialStatus    string   `json:"denialStatus,omitempty"`
}

type SemanticReplay struct {
	Fixture              Fixture                  `json:"fixture"`
	RCode                uint8                    `json:"rcode"`
	AnswerCount          int                      `json:"answerCount"`
	AnswerTypes          []uint16                 `json:"answerTypes,omitempty"`
	DenialEvidence       []dnssec.DenialEvidence  `json:"denialEvidence,omitempty"`
	AuthenticationScope  string                   `json:"authenticationScope"`
}

func LoadManifest(path string) (Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode dns fixture manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("unsupported dns fixture manifest version %d", m.Version)
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("dns fixture manifest must contain at least one entry")
	}
	seen := map[string]bool{}
	for i, entry := range m.Entries {
		rawPath := strings.TrimSpace(entry.Path)
		if rawPath == "" || strings.Contains(rawPath, "\\") {
			return fmt.Errorf("manifest entry %d has unsafe/non-portable fixture path %q", i, entry.Path)
		}
		clean := pathpkg.Clean(rawPath)
		if clean == "." || clean == ".." ||
			strings.HasPrefix(clean, "../") ||
			strings.HasPrefix(clean, "/") ||
			clean != rawPath {
			return fmt.Errorf("manifest entry %d has unsafe/non-canonical fixture path %q", i, entry.Path)
		}
		if seen[clean] {
			return fmt.Errorf("duplicate dns fixture manifest path %q", clean)
		}
		seen[clean] = true
	}
	return nil
}

func ReplayManifest(path string) ([]SemanticReplay, error) {
	manifest, err := LoadManifest(path)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	results := make([]SemanticReplay, 0, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		fixturePath, err := resolveManifestPath(base, entry.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Path, err)
		}
		fixture, err := Load(fixturePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Path, err)
		}
		if fixture.CaptureKind == CaptureKindCaptured {
			if entry.Review == nil {
				return nil, fmt.Errorf("%s: captured fixture requires explicit human review metadata", entry.Path)
			}
			if err := entry.Review.Validate(fixture); err != nil {
				return nil, fmt.Errorf("%s: %w", entry.Path, err)
			}
		}
		result, err := ReplaySemantics(fixture)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Path, err)
		}
		if err := entry.Expected.Validate(result); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Path, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func resolveManifestPath(base, manifestPath string) (string, error) {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(baseAbs, filepath.FromSlash(manifestPath))
	candidateReal, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	baseReal, err := filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseReal, candidateReal)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("fixture path escapes manifest directory")
	}
	return candidateReal, nil
}

func ReplaySemantics(f Fixture) (SemanticReplay, error) {
	message, err := f.Replay()
	if err != nil {
		return SemanticReplay{}, err
	}

	answerTypes := make([]uint16, 0, len(message.Answers))
	for _, record := range message.Answers {
		answerTypes = append(answerTypes, record.Type)
	}
	sort.Slice(answerTypes, func(i, j int) bool { return answerTypes[i] < answerTypes[j] })

	var denial []dnssec.DenialEvidence
	for _, record := range message.Authorities {
		switch record.Type {
		case dnswire.TypeNSEC:
			value, err := dnssec.ParseNSEC(record)
			if err != nil {
				return SemanticReplay{}, fmt.Errorf("parse NSEC: %w", err)
			}
			denial = append(denial, dnssec.EvaluateNSEC(f.QueryName, f.QueryType, value))
		case dnswire.TypeNSEC3:
			value, err := dnssec.ParseNSEC3(record)
			if err != nil {
				return SemanticReplay{}, fmt.Errorf("parse NSEC3: %w", err)
			}
			denial = append(denial, dnssec.EvaluateNSEC3(f.QueryName, f.QueryType, value))
		}
	}

	return SemanticReplay{
		Fixture: f,
		RCode: message.Header.RCode,
		AnswerCount: len(message.Answers),
		AnswerTypes: answerTypes,
		DenialEvidence: denial,
		AuthenticationScope: "not-evaluated-single-packet",
	}, nil
}

func (e ManifestExpected) Validate(result SemanticReplay) error {
	if e.RCode != nil && result.RCode != *e.RCode {
		return fmt.Errorf("rcode=%d want %d", result.RCode, *e.RCode)
	}
	if e.AnswerCount != nil && result.AnswerCount != *e.AnswerCount {
		return fmt.Errorf("answerCount=%d want %d", result.AnswerCount, *e.AnswerCount)
	}
	if len(e.AnswerTypes) > 0 {
		expected := append([]uint16(nil), e.AnswerTypes...)
		sort.Slice(expected, func(i, j int) bool { return expected[i] < expected[j] })
		if !equalUint16s(result.AnswerTypes, expected) {
			return fmt.Errorf("answerTypes=%v want %v", result.AnswerTypes, expected)
		}
	}
	if e.DenialMechanism != "" || e.DenialStatus != "" {
		for _, value := range result.DenialEvidence {
			if (e.DenialMechanism == "" || value.Mechanism == e.DenialMechanism) &&
				(e.DenialStatus == "" || value.Status == e.DenialStatus) {
				return nil
			}
		}
		return fmt.Errorf("expected denial evidence mechanism=%q status=%q, got %+v",
			e.DenialMechanism, e.DenialStatus, result.DenialEvidence)
	}
	return nil
}

func equalUint16s(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
