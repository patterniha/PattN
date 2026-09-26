package dnssec

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"
)

type TrustAnchorSourceComparison struct {
	Zone                string   `json:"zone"`
	MatchesEmbedded     bool     `json:"matchesEmbedded"`
	PublishedKeyTags    []uint16 `json:"publishedKeyTags"`
	EmbeddedKeyTags     []uint16 `json:"embeddedKeyTags"`
	MissingFromEmbedded []string `json:"missingFromEmbedded,omitempty"`
	ExtraInEmbedded     []string `json:"extraInEmbedded,omitempty"`
}

type ianaTrustAnchorXML struct {
	XMLName    xml.Name           `xml:"TrustAnchor"`
	Zone       string             `xml:"Zone"`
	KeyDigests []ianaKeyDigestXML `xml:"KeyDigest"`
}

type ianaKeyDigestXML struct {
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// CompareIANARootTrustAnchorXML compares the checked-in reviewed snapshot with
// IANA's published XML representation. It deliberately performs no network I/O;
// scheduled/manual tooling fetches the source and feeds the exact bytes here.
func CompareIANARootTrustAnchorXML(
	data []byte,
	at time.Time,
) (TrustAnchorSourceComparison, error) {
	var published ianaTrustAnchorXML
	if err := xml.Unmarshal(data, &published); err != nil {
		return TrustAnchorSourceComparison{}, fmt.Errorf("parse IANA root trust-anchor XML: %w", err)
	}
	if strings.TrimSpace(published.Zone) != "." {
		return TrustAnchorSourceComparison{}, fmt.Errorf(
			"IANA trust-anchor XML zone is %q, expected '.'",
			published.Zone)
	}
	if len(published.KeyDigests) == 0 {
		return TrustAnchorSourceComparison{}, fmt.Errorf("IANA trust-anchor XML contains no KeyDigest entries")
	}

	at = at.UTC()
	if len(published.KeyDigests) > 16 {
		return TrustAnchorSourceComparison{}, fmt.Errorf(
			"IANA trust-anchor XML contains an implausible number of KeyDigest entries: %d",
			len(published.KeyDigests))
	}

	publishedSet := make(map[string]struct{}, len(published.KeyDigests))
	publishedByTag := make(map[uint16]string, len(published.KeyDigests))
	publishedTags := make([]uint16, 0, len(published.KeyDigests))
	for _, item := range published.KeyDigests {
		active, err := ianaKeyDigestActiveAt(item, at)
		if err != nil {
			return TrustAnchorSourceComparison{}, err
		}
		if !active {
			continue
		}

		digest := canonicalTrustAnchorDigest(item.Digest)
		if item.KeyTag == 0 || item.Algorithm == 0 || item.DigestType != 2 || len(digest) != 64 {
			return TrustAnchorSourceComparison{}, fmt.Errorf(
				"IANA trust-anchor key tag %d has unsupported or malformed DS material",
				item.KeyTag)
		}
		for _, ch := range digest {
			if !strings.ContainsRune("0123456789ABCDEF", ch) {
				return TrustAnchorSourceComparison{}, fmt.Errorf(
					"IANA trust-anchor key tag %d has a non-hex digest",
					item.KeyTag)
			}
		}
		key := trustAnchorIdentity(item.KeyTag, item.Algorithm, item.DigestType, digest)
		if _, exists := publishedSet[key]; exists {
			return TrustAnchorSourceComparison{}, fmt.Errorf(
				"IANA trust-anchor XML contains duplicate active KeyDigest %s",
				key)
		}
		if previous, exists := publishedByTag[item.KeyTag]; exists && previous != key {
			return TrustAnchorSourceComparison{}, fmt.Errorf(
				"IANA trust-anchor XML contains conflicting active material for key tag %d",
				item.KeyTag)
		}
		publishedSet[key] = struct{}{}
		publishedByTag[item.KeyTag] = key
		publishedTags = append(publishedTags, item.KeyTag)
	}

	embedded := IANARootTrustAnchors()
	embeddedSet := make(map[string]struct{}, len(embedded))
	embeddedTags := make([]uint16, 0, len(embedded))
	for _, item := range embedded {
		key := trustAnchorIdentity(
			item.KeyTag,
			item.Algorithm,
			item.DigestType,
			canonicalTrustAnchorDigest(item.Digest))
		embeddedSet[key] = struct{}{}
		embeddedTags = append(embeddedTags, item.KeyTag)
	}

	var missing []string
	for key := range publishedSet {
		if _, ok := embeddedSet[key]; !ok {
			missing = append(missing, key)
		}
	}
	var extra []string
	for key := range embeddedSet {
		if _, ok := publishedSet[key]; !ok {
			extra = append(extra, key)
		}
	}

	sort.Strings(missing)
	sort.Strings(extra)
	sort.Slice(publishedTags, func(i, j int) bool { return publishedTags[i] < publishedTags[j] })
	sort.Slice(embeddedTags, func(i, j int) bool { return embeddedTags[i] < embeddedTags[j] })

	return TrustAnchorSourceComparison{
		Zone:                ".",
		MatchesEmbedded:     len(missing) == 0 && len(extra) == 0,
		PublishedKeyTags:    dedupeUint16(publishedTags),
		EmbeddedKeyTags:     dedupeUint16(embeddedTags),
		MissingFromEmbedded: missing,
		ExtraInEmbedded:     extra,
	}, nil
}


func ianaKeyDigestActiveAt(item ianaKeyDigestXML, at time.Time) (bool, error) {
	if strings.TrimSpace(item.ValidFrom) != "" {
		validFrom, err := time.Parse(time.RFC3339, strings.TrimSpace(item.ValidFrom))
		if err != nil {
			return false, fmt.Errorf(
				"IANA trust-anchor key tag %d has invalid validFrom: %w",
				item.KeyTag,
				err)
		}
		if at.Before(validFrom) {
			return false, nil
		}
	}
	if strings.TrimSpace(item.ValidUntil) != "" {
		validUntil, err := time.Parse(time.RFC3339, strings.TrimSpace(item.ValidUntil))
		if err != nil {
			return false, fmt.Errorf(
				"IANA trust-anchor key tag %d has invalid validUntil: %w",
				item.KeyTag,
				err)
		}
		if !at.Before(validUntil) {
			return false, nil
		}
	}
	return true, nil
}

func trustAnchorIdentity(keyTag uint16, algorithm, digestType uint8, digest string) string {
	return fmt.Sprintf("%d/%d/%d/%s", keyTag, algorithm, digestType, digest)
}

func canonicalTrustAnchorDigest(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(value), ""))
}

func dedupeUint16(values []uint16) []uint16 {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	var previous uint16
	for i, value := range values {
		if i == 0 || value != previous {
			out = append(out, value)
			previous = value
		}
	}
	return out
}
