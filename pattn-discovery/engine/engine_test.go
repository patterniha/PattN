package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"pattn-discovery/internal/resolvercatalog"
	"pattn-discovery/protocol"
)

func TestTargetsInspectDoesNotExpandLargeRanges(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"targets": []string{"10.0.0.0/8", "2001:db8::/64", "bad"}})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "1", Method: "targets.inspect", Params: params})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	data := res.Data.(map[string]any)
	if data["addressCount"] != "18446744073726328832" {
		t.Fatalf("count=%v", data["addressCount"])
	}
}

func TestEndpointProbePreservesLogicalHostAndReturnsQuorumEvidence(t *testing.T) {
	var hosts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		w.Header().Set("cf-ray", "abc123-FRA")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(map[string]any{
		"addresses":    []string{host, "not-an-ip"},
		"port":         port,
		"serverName":   "logical.example",
		"httpHost":     "logical.example",
		"scheme":       "http",
		"attempts":     3,
		"minSuccesses": 2,
		"timeoutMs":    1000,
	})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "p", Method: "endpoint.probe", Params: params})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	payload := res.Data.(endpointProbeResponse)
	if len(payload.Results) != 1 || len(payload.Invalid) != 1 {
		t.Fatalf("result=%+v", payload)
	}
	got := payload.Results[0]
	if !got.Qualified || got.Successes != 2 || got.Attempts != 2 {
		t.Fatalf("quorum=%+v", got)
	}
	if got.Edge.Provider != "cloudflare" || got.Edge.PoP != "FRA" {
		t.Fatalf("edge=%+v", got.Edge)
	}
	if len(hosts) != 2 {
		t.Fatalf("requests=%d", len(hosts))
	}
	for _, gotHost := range hosts {
		if gotHost != "logical.example" {
			t.Fatalf("host=%q", gotHost)
		}
	}
}

func TestEndpointProbeRejectsImpossibleQuorum(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"addresses":    []string{"127.0.0.1"},
		"port":         443,
		"serverName":   "example.com",
		"attempts":     2,
		"minSuccesses": 3,
	})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "p", Method: "endpoint.probe", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}

func TestTCPScanStreamsStartedResultProgressAndCompleted(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	params, _ := json.Marshal(map[string]any{
		"targets":     []string{"127.0.0.1"},
		"ports":       []int{port},
		"timeoutMs":   250,
		"concurrency": 2,
		"maxTargets":  1,
	})
	var events []string
	var resultAddress string
	eng := New()
	err = eng.HandleStream(context.Background(), protocol.Request{Version: protocol.Version, ID: "scan-1", Method: "scan.tcp", Params: params}, func(response protocol.Response) error {
		events = append(events, response.Event)
		if response.Event == "result" {
			data := response.Data.(map[string]any)
			resultAddress = data["address"].(string)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 4 || events[0] != "started" || events[len(events)-1] != "completed" {
		t.Fatalf("events=%v", events)
	}
	if resultAddress != "127.0.0.1" {
		t.Fatalf("resultAddress=%q", resultAddress)
	}
}

func TestTCPScanCanBeCancelledThroughControlRequest(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"targets":     []string{"127.0.0.1-127.0.0.100"},
		"ports":       []int{1},
		"timeoutMs":   50,
		"concurrency": 1,
		"maxTargets":  100,
	})
	eng := New()
	var finalEvent string
	err := eng.HandleStream(context.Background(), protocol.Request{Version: protocol.Version, ID: "scan-cancel", Method: "scan.tcp", Params: params}, func(response protocol.Response) error {
		if response.Event == "started" {
			controlParams, _ := json.Marshal(map[string]any{"scanId": "scan-cancel"})
			control := eng.Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "ctl", Method: "scan.cancel", Params: controlParams})
			if control.Error != nil {
				t.Fatalf("control error=%+v", control.Error)
			}
		}
		if response.Event == "cancelled" || response.Event == "completed" {
			finalEvent = response.Event
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalEvent != "cancelled" {
		t.Fatalf("finalEvent=%q", finalEvent)
	}
}

func TestTargetsNormalizePreservesSourceSemanticsAndMergesRanges(t *testing.T) {
	eng := New()
	params := json.RawMessage(`{
		"source":{"id":"iran-geo","kind":"country","scope":"country-geolocation","scopeValue":"IR","version":"2026-09"},
		"targets":["192.0.2.0/25","192.0.2.128/25","2001:db8::/126","bad"],
		"ipv4":true,"ipv6":false
	}`)
	response := eng.Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "normalize", Method: "targets.normalize", Params: params})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	payload, err := json.Marshal(response.Data)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Source struct {
			ID         string `json:"id"`
			Kind       string `json:"kind"`
			Scope      string `json:"scope"`
			ScopeValue string `json:"scopeValue"`
			Version    string `json:"version"`
		} `json:"source"`
		Ranges       []string `json:"ranges"`
		Invalid      []string `json:"invalid"`
		AddressCount string   `json:"addressCount"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Source.ID != "iran-geo" || got.Source.Kind != "country" || got.Source.Scope != "country-geolocation" || got.Source.ScopeValue != "IR" || got.Source.Version != "2026-09" {
		t.Fatalf("source=%+v", got.Source)
	}
	if len(got.Ranges) != 1 || got.Ranges[0] != "192.0.2.0-192.0.2.255" || got.AddressCount != "256" {
		t.Fatalf("ranges=%v count=%s", got.Ranges, got.AddressCount)
	}
	if len(got.Invalid) != 1 || got.Invalid[0] != "bad" {
		t.Fatalf("invalid=%v", got.Invalid)
	}
}


func TestCapabilitiesAdvertiseDeepDnsMethods(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps, ok := res.Data.(protocol.Capabilities)
	if !ok {
		t.Fatalf("unexpected capabilities type %T", res.Data)
	}
	methods := make(map[string]bool, len(caps.Methods))
	for _, method := range caps.Methods {
		methods[method] = true
	}
	for _, required := range []string{"dns.trace", "dns.authority.compare", "request.cancel"} {
		if !methods[required] {
			t.Fatalf("missing capability %q in %v", required, caps.Methods)
		}
	}
}

func TestAuthorityCompareRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": "", "queryType": 1})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "authority", Method: "dns.authority.compare", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseDnssecAndConsensus(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-next", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	methods := make(map[string]bool, len(caps.Methods))
	for _, method := range caps.Methods {
		methods[method] = true
	}
	for _, required := range []string{"dns.dnssec.inspect", "dns.consensus.compare"} {
		if !methods[required] {
			t.Fatalf("missing capability %q in %v", required, caps.Methods)
		}
	}
}

func TestDnssecInspectRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": ""})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "dnssec", Method: "dns.dnssec.inspect", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}

func TestDnsConsensusRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": ""})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "consensus", Method: "dns.consensus.compare", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseDomainDnssecValidation(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-dnssec-domain", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.dnssec.validate" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.dnssec.validate missing from %v", caps.Methods)
	}
}

func TestDnssecValidateRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": "", "queryType": 1})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "dnssec-domain", Method: "dns.dnssec.validate", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseDnssecChain(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-chain", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.dnssec.chain" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.dnssec.chain missing from %v", caps.Methods)
	}
}

func TestDnssecChainRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": ""})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "dnssec-chain", Method: "dns.dnssec.chain", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseResolverProfile(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-resolver-profile", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.resolver.profile" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.resolver.profile missing from %v", caps.Methods)
	}
}

func TestResolverProfileRejectsInvalidAddress(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"address": "not-an-ip", "domain": "example.com"})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "resolver-profile", Method: "dns.resolver.profile", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestResolverProfileRejectsInvalidQuorum(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"address": "192.0.2.53",
		"domain": "example.com",
		"attempts": 2,
		"minSuccesses": 3,
	})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "profile-quorum", Method: "dns.resolver.profile", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}

func TestResolverQualifyRejectsInvalidDepthQuorum(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"address": "192.0.2.53",
		"domain": "example.com",
		"checkDepth": true,
		"depthAttempts": 2,
		"depthMinSuccesses": 3,
	})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "qualify-quorum", Method: "dns.resolver.qualify", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}

func TestDnsConsensusRejectsInvalidDepthQuorum(t *testing.T) {
	params, _ := json.Marshal(map[string]any{
		"domain": "example.com",
		"checkDepth": true,
		"depthAttempts": 2,
		"depthMinSuccesses": 3,
	})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "consensus-quorum", Method: "dns.consensus.compare", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseResolverCatalog(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-resolver-catalog", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.resolver.catalog" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.resolver.catalog missing from %v", caps.Methods)
	}
}

func TestResolverCatalogSeparatesReferenceEligibleResolvers(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "resolver-catalog", Method: "dns.resolver.catalog"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	data := res.Data.(map[string]any)
	if data["version"] != resolvercatalog.Version {
		t.Fatalf("version=%v", data["version"])
	}
	resolvers := data["resolvers"].([]resolvercatalog.Identity)
	references := data["referenceEligible"].([]resolvercatalog.Identity)
	if len(resolvers) != 3 || len(references) != 2 {
		t.Fatalf("resolvers=%+v references=%+v", resolvers, references)
	}
}


func TestCapabilitiesAdvertiseDnsRepairInspect(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-dns-repair", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.repair.inspect" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.repair.inspect missing from %v", caps.Methods)
	}
}

func TestDnsRepairInspectRejectsEmptyDomain(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"domain": ""})
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "dns-repair", Method: "dns.repair.inspect", Params: params})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}


func TestCapabilitiesAdvertiseResolverCatalogAudit(t *testing.T) {
	res := New().Handle(context.Background(), protocol.Request{Version: protocol.Version, ID: "caps-resolver-catalog-audit", Method: "engine.capabilities"})
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	caps := res.Data.(protocol.Capabilities)
	found := false
	for _, method := range caps.Methods {
		if method == "dns.resolver.catalog.audit" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dns.resolver.catalog.audit missing from %v", caps.Methods)
	}
}

func TestResolverCatalogAuditRejectsAbsurdAgeWindow(t *testing.T) {
	params, _ := json.Marshal(map[string]any{"maxAgeDays": 5000})
	res := New().Handle(context.Background(), protocol.Request{
		Version: protocol.Version,
		ID: "resolver-catalog-audit",
		Method: "dns.resolver.catalog.audit",
		Params: params,
	})
	if res.Error == nil || res.Error.Code != "invalid_params" {
		t.Fatalf("error=%+v", res.Error)
	}
}
