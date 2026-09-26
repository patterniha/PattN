package resolvercatalog

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const Version = "2026-09-23"

type PolicyClass string

const (
	PolicyNeutral          PolicyClass = "neutral"
	PolicySecurityFiltering PolicyClass = "security-filtering"
)

type Identity struct {
	ID                string      `json:"id"`
	Provider          string      `json:"provider"`
	Name              string      `json:"name"`
	IPv4              []string    `json:"ipv4,omitempty"`
	IPv6              []string    `json:"ipv6,omitempty"`
	Port              uint16      `json:"port"`
	DoTServerName     string      `json:"dotServerName,omitempty"`
	DoTPort           uint16      `json:"dotPort,omitempty"`
	DoHURL            string      `json:"dohUrl,omitempty"`
	DNSSECValidating  bool        `json:"dnssecValidating"`
	Policy            PolicyClass `json:"policy"`
	ReferenceEligible bool        `json:"referenceEligible"`
	SourceURLs        []string    `json:"sourceUrls,omitempty"`
	VerifiedDate      string      `json:"verifiedDate"`
}

var builtin = []Identity{
	{
		ID: "cloudflare-standard", Provider: "Cloudflare", Name: "Cloudflare 1.1.1.1",
		IPv4: []string{"1.1.1.1", "1.0.0.1"},
		IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
		Port: 53, DoTServerName: "one.one.one.one", DoTPort: 853,
		DoHURL: "https://cloudflare-dns.com/dns-query",
		DNSSECValidating: true, Policy: PolicyNeutral, ReferenceEligible: true,
		SourceURLs: []string{
			"https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/",
			"https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
		},
		VerifiedDate: "2026-09-23",
	},
	{
		ID: "google-standard", Provider: "Google", Name: "Google Public DNS",
		IPv4: []string{"8.8.8.8", "8.8.4.4"},
		IPv6: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		Port: 53, DoTServerName: "dns.google", DoTPort: 853,
		DoHURL: "https://dns.google/dns-query",
		DNSSECValidating: true, Policy: PolicyNeutral, ReferenceEligible: true,
		SourceURLs: []string{
			"https://developers.google.com/speed/public-dns/docs/using",
			"https://developers.google.com/speed/public-dns/faq",
		},
		VerifiedDate: "2026-09-23",
	},
	{
		ID: "quad9-secure", Provider: "Quad9", Name: "Quad9 Secure",
		IPv4: []string{"9.9.9.9", "149.112.112.112"},
		IPv6: []string{"2620:fe::fe", "2620:fe::9"},
		Port: 53, DoTServerName: "dns.quad9.net", DoTPort: 853,
		DoHURL: "https://dns.quad9.net/dns-query",
		DNSSECValidating: true, Policy: PolicySecurityFiltering, ReferenceEligible: false,
		SourceURLs: []string{
			"https://docs.quad9.net/services/",
			"https://quad9.net/service/service-addresses-and-features/",
		},
		VerifiedDate: "2026-09-23",
	},
}

func Builtin() []Identity {
	out := make([]Identity, len(builtin))
	for i, value := range builtin {
		out[i] = clone(value)
	}
	return out
}

func ReferenceEligible() []Identity {
	var out []Identity
	for _, value := range builtin {
		if value.ReferenceEligible {
			out = append(out, clone(value))
		}
	}
	return out
}

func Find(id string) (Identity, bool) {
	for _, value := range builtin {
		if value.ID == id {
			return clone(value), true
		}
	}
	return Identity{}, false
}

func clone(value Identity) Identity {
	value.IPv4 = append([]string(nil), value.IPv4...)
	value.IPv6 = append([]string(nil), value.IPv6...)
	value.SourceURLs = append([]string(nil), value.SourceURLs...)
	return value
}


func Validate(values []Identity) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value.ID) == "" {
			return fmt.Errorf("resolver catalog entry has empty id")
		}
		if _, exists := seen[value.ID]; exists {
			return fmt.Errorf("duplicate resolver catalog id %q", value.ID)
		}
		seen[value.ID] = struct{}{}
		if strings.TrimSpace(value.Provider) == "" || strings.TrimSpace(value.Name) == "" {
			return fmt.Errorf("resolver %q has incomplete identity", value.ID)
		}
		if value.Port == 0 || value.DoTPort == 0 {
			return fmt.Errorf("resolver %q has invalid DNS/DoT port", value.ID)
		}
		if len(value.IPv4)+len(value.IPv6) == 0 {
			return fmt.Errorf("resolver %q has no addresses", value.ID)
		}
		for _, raw := range append(append([]string(nil), value.IPv4...), value.IPv6...) {
			if _, err := netip.ParseAddr(raw); err != nil {
				return fmt.Errorf("resolver %q has invalid address %q: %w", value.ID, raw, err)
			}
		}
		if strings.TrimSpace(value.DoTServerName) == "" {
			return fmt.Errorf("resolver %q has no DoT server identity", value.ID)
		}
		parsed, err := url.Parse(value.DoHURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return fmt.Errorf("resolver %q has invalid HTTPS DoH URL %q", value.ID, value.DoHURL)
		}
		if value.ReferenceEligible && value.Policy != PolicyNeutral {
			return fmt.Errorf("resolver %q is reference-eligible but policy is %q", value.ID, value.Policy)
		}
		if len(value.SourceURLs) == 0 {
			return fmt.Errorf("resolver %q has no source URLs", value.ID)
		}
		for _, raw := range value.SourceURLs {
			source, err := url.Parse(raw)
			if err != nil || source.Scheme != "https" || source.Hostname() == "" {
				return fmt.Errorf("resolver %q has invalid source URL %q", value.ID, raw)
			}
		}
		if _, err := time.Parse("2006-01-02", value.VerifiedDate); err != nil {
			return fmt.Errorf("resolver %q has invalid verified date %q", value.ID, value.VerifiedDate)
		}
	}
	return nil
}


type AuditEntry struct {
	ID           string `json:"id"`
	VerifiedDate string `json:"verifiedDate"`
	AgeDays      int    `json:"ageDays"`
	Stale        bool   `json:"stale"`
}

type AuditResult struct {
	Version    string       `json:"version"`
	Valid      bool         `json:"valid"`
	Error      string       `json:"error,omitempty"`
	MaxAgeDays int          `json:"maxAgeDays"`
	StaleCount int          `json:"staleCount"`
	Entries    []AuditEntry `json:"entries"`
}

func Audit(now time.Time, maxAge time.Duration) AuditResult {
	if maxAge <= 0 {
		maxAge = 90 * 24 * time.Hour
	}
	result := AuditResult{
		Version: Version,
		Valid: true,
		MaxAgeDays: int(maxAge / (24 * time.Hour)),
	}
	values := Builtin()
	if err := Validate(values); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	now = now.UTC()
	for _, value := range values {
		verified, err := time.Parse("2006-01-02", value.VerifiedDate)
		if err != nil {
			result.Valid = false
			result.Error = err.Error()
			return result
		}
		age := now.Sub(verified.UTC())
		ageDays := int(age / (24 * time.Hour))
		if ageDays < 0 {
			ageDays = 0
		}
		stale := age > maxAge
		if stale {
			result.StaleCount++
		}
		result.Entries = append(result.Entries, AuditEntry{
			ID: value.ID,
			VerifiedDate: value.VerifiedDate,
			AgeDays: ageDays,
			Stale: stale,
		})
	}
	return result
}
