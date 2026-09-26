package dnssec

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnswire"
)

type TrustAnchor struct {
	Zone       string `json:"zone"`
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
	Digest     string `json:"digest"`
	Source     string `json:"source,omitempty"`
}

const (
	IANARootTrustAnchorSourceURL         = "https://data.iana.org/root-anchors/root-anchors.xml"
	IANARootTrustAnchorSourceUpdatedDate    = "2024-11-05"
	IANARootTrustAnchorSignatureUpdatedDate = "2025-08-04"
	IANARootTrustAnchorCABundleUpdatedDate  = "2026-05-28"
	IANARootTrustAnchorVerifiedDate         = "2026-09-24"
	IANARootKSKRolloverDate                 = "2026-10-11"
	DefaultTrustAnchorMaxAgeDays         = 90
)

type TrustAnchorSnapshot struct {
	Version           string        `json:"version"`
	SourceURL         string        `json:"sourceUrl"`
	SourceUpdatedDate    string        `json:"sourceUpdatedDate"`
	SignatureUpdatedDate string        `json:"signatureUpdatedDate"`
	CABundleUpdatedDate  string        `json:"caBundleUpdatedDate"`
	VerifiedDate         string        `json:"verifiedDate"`
	RolloverDate      string        `json:"rolloverDate"`
	Anchors           []TrustAnchor `json:"anchors"`
}

type TrustAnchorAudit struct {
	Version                  string   `json:"version"`
	SourceURL                string   `json:"sourceUrl"`
	SourceUpdatedDate        string   `json:"sourceUpdatedDate"`
	SignatureUpdatedDate     string   `json:"signatureUpdatedDate"`
	CABundleUpdatedDate      string   `json:"caBundleUpdatedDate"`
	VerifiedDate             string   `json:"verifiedDate"`
	RolloverDate             string   `json:"rolloverDate"`
	AgeDays                  int      `json:"ageDays"`
	MaxAgeDays               int      `json:"maxAgeDays"`
	DaysUntilRollover        int      `json:"daysUntilRollover"`
	RolloverReviewRequired   bool     `json:"rolloverReviewRequired"`
	Stale                    bool     `json:"stale"`
	Valid                    bool     `json:"valid"`
	ReviewRequired           bool     `json:"reviewRequired"`
	Status                   string   `json:"status"`
	KeyTags                  []uint16 `json:"keyTags"`
	Errors                   []string `json:"errors,omitempty"`
}

func IANARootTrustAnchorSnapshot() TrustAnchorSnapshot {
	const source = "IANA root-anchors.xml verified 2026-09-24"
	return TrustAnchorSnapshot{
		Version:           "iana-root-anchors-2024-11-05/verified-2026-09-24",
		SourceURL:         IANARootTrustAnchorSourceURL,
		SourceUpdatedDate:    IANARootTrustAnchorSourceUpdatedDate,
		SignatureUpdatedDate: IANARootTrustAnchorSignatureUpdatedDate,
		CABundleUpdatedDate:  IANARootTrustAnchorCABundleUpdatedDate,
		VerifiedDate:         IANARootTrustAnchorVerifiedDate,
		RolloverDate:      IANARootKSKRolloverDate,
		Anchors: []TrustAnchor{
			{
				Zone: ".", KeyTag: 20326, Algorithm: 8, DigestType: 2,
				Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
				Source: source,
			},
			{
				Zone: ".", KeyTag: 38696, Algorithm: 8, DigestType: 2,
				Digest: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
				Source: source,
			},
		},
	}
}

func IANARootTrustAnchors() []TrustAnchor {
	snapshot := IANARootTrustAnchorSnapshot()
	return append([]TrustAnchor(nil), snapshot.Anchors...)
}

func AuditIANARootTrustAnchors(now time.Time, maxAge time.Duration) TrustAnchorAudit {
	snapshot := IANARootTrustAnchorSnapshot()
	if maxAge <= 0 {
		maxAge = DefaultTrustAnchorMaxAgeDays * 24 * time.Hour
	}
	maxAgeDays := int(maxAge / (24 * time.Hour))
	if maxAgeDays < 1 {
		maxAgeDays = 1
	}

	audit := TrustAnchorAudit{
		Version:           snapshot.Version,
		SourceURL:         snapshot.SourceURL,
		SourceUpdatedDate:    snapshot.SourceUpdatedDate,
		SignatureUpdatedDate: snapshot.SignatureUpdatedDate,
		CABundleUpdatedDate:  snapshot.CABundleUpdatedDate,
		VerifiedDate:         snapshot.VerifiedDate,
		RolloverDate:      snapshot.RolloverDate,
		MaxAgeDays:        maxAgeDays,
		Valid:             true,
		Status:            "current",
	}

	verifiedAt, err := time.Parse("2006-01-02", snapshot.VerifiedDate)
	if err != nil {
		audit.Valid = false
		audit.Errors = append(audit.Errors, "invalid verifiedDate: "+err.Error())
	}
	rolloverAt, err := time.Parse("2006-01-02", snapshot.RolloverDate)
	if err != nil {
		audit.Valid = false
		audit.Errors = append(audit.Errors, "invalid rolloverDate: "+err.Error())
	}

	now = now.UTC()
	if audit.Valid {
		if now.Before(verifiedAt) {
			audit.Valid = false
			audit.Errors = append(audit.Errors, "trust-anchor verification date is in the future")
		} else {
			audit.AgeDays = int(now.Sub(verifiedAt) / (24 * time.Hour))
			audit.Stale = now.Sub(verifiedAt) > maxAge
		}
		audit.DaysUntilRollover = int(rolloverAt.Sub(now) / (24 * time.Hour))
		// A pre-rollover verification cannot attest to the post-rollover root
		// signing state. Force an explicit IANA re-check once the scheduled
		// transition date is reached even if the ordinary freshness window has
		// not yet expired.
		audit.RolloverReviewRequired = !verifiedAt.Equal(rolloverAt) &&
			verifiedAt.Before(rolloverAt) && !now.Before(rolloverAt)
	}

	seen := make(map[uint16]struct{}, len(snapshot.Anchors))
	for _, anchor := range snapshot.Anchors {
		if strings.TrimSpace(anchor.Zone) != "." {
			audit.Valid = false
			audit.Errors = append(audit.Errors, fmt.Sprintf("trust anchor %d is not rooted at '.'", anchor.KeyTag))
		}
		if _, exists := seen[anchor.KeyTag]; exists {
			audit.Valid = false
			audit.Errors = append(audit.Errors, fmt.Sprintf("duplicate trust-anchor key tag %d", anchor.KeyTag))
			continue
		}
		seen[anchor.KeyTag] = struct{}{}
		digest, err := hex.DecodeString(anchor.Digest)
		if err != nil || len(digest) != 32 || anchor.DigestType != 2 {
			audit.Valid = false
			audit.Errors = append(audit.Errors, fmt.Sprintf("trust anchor %d has invalid SHA-256 DS material", anchor.KeyTag))
		}
		audit.KeyTags = append(audit.KeyTags, anchor.KeyTag)
	}
	sort.Slice(audit.KeyTags, func(i, j int) bool { return audit.KeyTags[i] < audit.KeyTags[j] })
	if len(TrustAnchorRecords(snapshot.Anchors)) != len(snapshot.Anchors) {
		audit.Valid = false
		audit.Errors = append(audit.Errors, "one or more trust anchors could not be converted to DS records")
	}

	audit.ReviewRequired = !audit.Valid || audit.Stale || audit.RolloverReviewRequired
	switch {
	case !audit.Valid:
		audit.Status = "invalid"
	case audit.RolloverReviewRequired:
		audit.Status = "rollover-review-required"
	case audit.Stale:
		audit.Status = "stale"
	default:
		audit.Status = "current"
	}
	return audit
}

func TrustAnchorRecords(values []TrustAnchor) []dnswire.ResourceRecord {
	out := make([]dnswire.ResourceRecord, 0, len(values))
	for _, value := range values {
		digest, err := hex.DecodeString(value.Digest)
		if err != nil || len(digest) == 0 {
			continue
		}
		raw := []byte{byte(value.KeyTag >> 8), byte(value.KeyTag), value.Algorithm, value.DigestType}
		raw = append(raw, digest...)
		out = append(out, dnswire.ResourceRecord{
			Name: normalizeName(value.Zone),
			Type: dnswire.TypeDS,
			Class: dnswire.ClassIN,
			RawData: raw,
			CanonicalRData: append([]byte(nil), raw...),
		})
	}
	return out
}

func AuthenticatedDNSKEYRecords(records []dnswire.ResourceRecord) []dnswire.ResourceRecord {
	out := make([]dnswire.ResourceRecord, 0, len(records))
	for _, record := range records {
		if record.Type == dnswire.TypeDNSKEY {
			out = append(out, record)
		}
	}
	return out
}
