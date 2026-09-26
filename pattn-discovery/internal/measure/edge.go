package measure

import (
	"net/http"
	"regexp"
	"strings"
)

type EdgeObservation struct {
	Provider string `json:"provider,omitempty"`
	PoP      string `json:"pop,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

var iataSuffix = regexp.MustCompile(`(?i)(?:^|[-_])([a-z]{3})(?:\d+)?$`)

// DetectEdge normalizes common CDN/edge response metadata into one provider/PoP observation.
func DetectEdge(h http.Header) EdgeObservation {
	if v := h.Get("cf-ray"); v != "" {
		return EdgeObservation{Provider: "cloudflare", PoP: lastIATA(v), Evidence: "cf-ray=" + v}
	}
	if v := h.Get("x-amz-cf-pop"); v != "" {
		return EdgeObservation{Provider: "cloudfront", PoP: firstToken(v), Evidence: "x-amz-cf-pop=" + v}
	}
	if v := h.Get("x-served-by"); v != "" {
		return EdgeObservation{Provider: "fastly", PoP: lastIATA(v), Evidence: "x-served-by=" + v}
	}
	if v := h.Get("x-77-pop"); v != "" {
		return EdgeObservation{Provider: "cdn77", PoP: firstToken(v), Evidence: "x-77-pop=" + v}
	}
	if v := h.Get("server"); strings.HasPrefix(strings.ToLower(v), "bunnycdn-") {
		pop := strings.TrimSpace(v[len("BunnyCDN-"):])
		return EdgeObservation{Provider: "bunny", PoP: strings.ToUpper(pop), Evidence: "server=" + v}
	}
	if v := h.Get("x-id-fe"); v != "" {
		return EdgeObservation{Provider: "gcore", PoP: firstToken(v), Evidence: "x-id-fe=" + v}
	}
	return EdgeObservation{}
}

func lastIATA(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	for i := len(parts) - 1; i >= 0; i-- {
		if m := iataSuffix.FindStringSubmatch(parts[i]); len(m) == 2 {
			return strings.ToUpper(m[1])
		}
	}
	return ""
}

func firstToken(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexAny(value, " ,;"); i >= 0 {
		value = value[:i]
	}
	return strings.ToUpper(value)
}
