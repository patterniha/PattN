package measure

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestProbePinnedHTTPDialsCandidateButPreservesLogicalHost(t *testing.T) {
	var seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.Header().Set("cf-ray", "abc123-SJC")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	obs, err := ProbePinnedHTTP(context.Background(), DialTarget{
		Address: netip.MustParseAddr(host), Port: uint16(port), ServerName: "logical.example", HTTPHost: "origin.example",
	}, HTTPProbeOptions{Scheme: "http", Path: "/probe", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if seenHost != "origin.example" {
		t.Fatalf("Host=%q", seenHost)
	}
	if obs.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", obs.StatusCode)
	}
	if obs.Edge.Provider != "cloudflare" || obs.Edge.PoP != "SJC" {
		t.Fatalf("edge=%+v", obs.Edge)
	}
}
