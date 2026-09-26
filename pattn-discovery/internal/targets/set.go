package targets

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// SourceKind describes what a target collection means, independently of how it was obtained.
type SourceKind string

const (
	SourceCIDR         SourceKind = "cidr"
	SourceASN          SourceKind = "asn"
	SourceCountry      SourceKind = "country"
	SourceDomain       SourceKind = "domain"
	SourceEndpoint     SourceKind = "endpoint-list"
	SourceProvider     SourceKind = "provider"
	SourceHistorical   SourceKind = "historical"
	SourceEndpointPool SourceKind = "endpoint-pool"
	SourceUser         SourceKind = "user"
	SourceCurated      SourceKind = "curated"
)

// ScopeType is deliberately semantic: a country-geolocation set is not the same thing as
// networks announced by an organization associated with that country.
type ScopeType string

const (
	ScopeUnspecified  ScopeType = "unspecified"
	ScopeCountryGeo   ScopeType = "country-geolocation"
	ScopeASN          ScopeType = "asn"
	ScopeOrganization ScopeType = "organization"
	ScopeEdgeProvider ScopeType = "edge-provider"
	ScopeCurated      ScopeType = "curated"
	ScopeUserDefined  ScopeType = "user-defined"
)

type SourceMetadata struct {
	ID         string            `json:"id"`
	Kind       SourceKind        `json:"kind"`
	Scope      ScopeType         `json:"scope,omitempty"`
	ScopeValue string            `json:"scopeValue,omitempty"`
	Version    string            `json:"version,omitempty"`
	UpdatedAt  time.Time         `json:"updatedAt,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Set struct {
	Source SourceMetadata `json:"source"`
	Ranges []Range        `json:"ranges"`
}

func (s Set) Count() *big.Int {
	total := new(big.Int)
	for _, r := range s.Ranges {
		total.Add(total, r.Count())
	}
	return total
}

// NormalizeSet validates, sorts, removes duplicates, and merges overlapping/adjacent ranges.
// It never enumerates individual addresses, so normalization remains safe for /0 and IPv6 ranges.
func NormalizeSet(source SourceMetadata, values []string) (Set, []string) {
	valid, invalid := ParseMany(values)
	return Set{Source: normalizeSource(source), Ranges: NormalizeRanges(valid)}, invalid
}

func NormalizeRanges(input []Range) []Range {
	ranges := make([]Range, 0, len(input))
	for _, r := range input {
		r.Start = r.Start.Unmap()
		r.End = r.End.Unmap()
		if !r.Start.IsValid() || !r.End.IsValid() || r.Start.BitLen() != r.End.BitLen() || r.Start.Compare(r.End) > 0 {
			continue
		}
		ranges = append(ranges, r)
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start.BitLen() != ranges[j].Start.BitLen() {
			return ranges[i].Start.BitLen() < ranges[j].Start.BitLen() // IPv4 then IPv6
		}
		if c := ranges[i].Start.Compare(ranges[j].Start); c != 0 {
			return c < 0
		}
		return ranges[i].End.Compare(ranges[j].End) < 0
	})

	merged := make([]Range, 0, len(ranges))
	for _, current := range ranges {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if last.Start.BitLen() != current.Start.BitLen() || !touchesOrOverlaps(*last, current) {
			merged = append(merged, current)
			continue
		}
		if current.End.Compare(last.End) > 0 {
			last.End = current.End
		}
	}
	return merged
}

func FilterFamily(ranges []Range, ipv4, ipv6 bool) []Range {
	out := make([]Range, 0, len(ranges))
	for _, r := range ranges {
		if r.Start.Is4() && ipv4 {
			out = append(out, r)
		}
		if r.Start.Is6() && ipv6 {
			out = append(out, r)
		}
	}
	return out
}

func (s Set) Strings() []string {
	out := make([]string, 0, len(s.Ranges))
	for _, r := range s.Ranges {
		out = append(out, r.String())
	}
	return out
}

func ValidateSource(source SourceMetadata) error {
	if strings.TrimSpace(source.ID) == "" {
		return fmt.Errorf("source id is required")
	}
	switch source.Kind {
	case SourceCIDR, SourceASN, SourceCountry, SourceDomain, SourceEndpoint, SourceProvider,
		SourceHistorical, SourceEndpointPool, SourceUser, SourceCurated:
	default:
		return fmt.Errorf("unknown source kind %q", source.Kind)
	}
	return nil
}

func normalizeSource(source SourceMetadata) SourceMetadata {
	source.ID = strings.TrimSpace(source.ID)
	source.ScopeValue = strings.TrimSpace(source.ScopeValue)
	source.Version = strings.TrimSpace(source.Version)
	return source
}

func touchesOrOverlaps(left, right Range) bool {
	if left.End.Compare(right.Start) >= 0 {
		return true
	}
	next := left.End.Next()
	return next.IsValid() && next == right.Start
}

// Ensure the compiler continues to enforce netip use in this package when Set evolves.
var _ = netip.Addr{}
