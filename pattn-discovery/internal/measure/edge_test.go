package measure

import (
	"net/http"
	"testing"
)

func TestDetectEdgeProviders(t *testing.T) {
	cases := []struct {
		header        http.Header
		provider, pop string
	}{
		{http.Header{"Cf-Ray": {"abc-SJC"}}, "cloudflare", "SJC"},
		{http.Header{"X-Amz-Cf-Pop": {"FRA56-P1"}}, "cloudfront", "FRA56-P1"},
		{http.Header{"X-Served-By": {"cache-fra-eddf8230100-FRA"}}, "fastly", "FRA"},
		{http.Header{"X-77-Pop": {"US-NYC"}}, "cdn77", "US-NYC"},
		{http.Header{"Server": {"BunnyCDN-DE"}}, "bunny", "DE"},
	}
	for _, tc := range cases {
		got := DetectEdge(tc.header)
		if got.Provider != tc.provider || got.PoP != tc.pop {
			t.Fatalf("%v => %+v", tc.header, got)
		}
	}
}
