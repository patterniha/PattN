package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pattn-discovery/internal/dnsauthority"
	"pattn-discovery/internal/dnsrepair"
	"pattn-discovery/internal/dnschain"
	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnssecdiag"
	"pattn-discovery/internal/dnsvalidate"
	"pattn-discovery/internal/dnswire"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnstruth"
	"pattn-discovery/internal/measure"
	"pattn-discovery/internal/resolvercatalog"
	"pattn-discovery/internal/resolverdepth"
	"pattn-discovery/internal/resolverdiscovery"
	"pattn-discovery/internal/resolverqual"
	"pattn-discovery/internal/scan"
	"pattn-discovery/internal/scheduler"
	"pattn-discovery/internal/targets"
	"pattn-discovery/protocol"
)

const EngineVersion = "0.1.0-dev"

type scanSession struct {
	cancel    context.CancelFunc
	gate      *scheduler.Gate
	cancelled atomic.Bool
}

type Engine struct {
	mu    sync.Mutex
	scans map[string]*scanSession
}

func New() *Engine { return &Engine{scans: make(map[string]*scanSession)} }

func IsStreamingMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case "scan.tcp", "dns.resolver.discover":
		return true
	default:
		return false
	}
}

func (e *Engine) Handle(ctx context.Context, req protocol.Request) protocol.Response {
	base := protocol.Response{Version: protocol.Version, ID: req.ID}
	if req.Version != protocol.Version {
		base.Error = &protocol.Error{Code: "protocol_version_mismatch", Message: fmt.Sprintf("supported=%d requested=%d", protocol.Version, req.Version)}
		return base
	}
	switch req.Method {
	case "engine.version":
		base.Data = map[string]any{"engine": "pattn-discovery", "version": EngineVersion}
	case "engine.capabilities":
		base.Data = protocol.Capabilities{ProtocolVersion: protocol.Version, NativeScanner: true, Methods: []string{"engine.version", "engine.capabilities", "targets.inspect", "targets.normalize", "endpoint.probe", "dns.trace", "dns.authority.compare", "dns.trust-anchor.audit", "dns.dnssec.inspect", "dns.dnssec.chain", "dns.dnssec.validate", "dns.consensus.compare", "dns.repair.inspect", "dns.resolver.catalog", "dns.resolver.catalog.audit", "dns.resolver.profile", "dns.resolver.qualify", "scan.tcp", "dns.resolver.discover", "scan.pause", "scan.resume", "scan.cancel", "request.cancel"}}
	case "targets.inspect":
		var p struct {
			Targets []string `json:"targets"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		valid, invalid := targets.ParseMany(p.Targets)
		total := new(big.Int)
		for _, r := range valid {
			total.Add(total, r.Count())
		}
		normalized := make([]string, 0, len(valid))
		for _, r := range valid {
			normalized = append(normalized, r.String())
		}
		base.Data = map[string]any{"ranges": normalized, "invalid": invalid, "addressCount": total.String()}
	case "targets.normalize":
		var p struct {
			Source  targets.SourceMetadata `json:"source"`
			Targets []string               `json:"targets"`
			IPv4    *bool                  `json:"ipv4,omitempty"`
			IPv6    *bool                  `json:"ipv6,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if err := targets.ValidateSource(p.Source); err != nil {
			base.Error = &protocol.Error{Code: "invalid_source", Message: err.Error()}
			break
		}
		set, invalid := targets.NormalizeSet(p.Source, p.Targets)
		ipv4, ipv6 := true, true
		if p.IPv4 != nil {
			ipv4 = *p.IPv4
		}
		if p.IPv6 != nil {
			ipv6 = *p.IPv6
		}
		set.Ranges = targets.FilterFamily(set.Ranges, ipv4, ipv6)
		base.Data = map[string]any{
			"source":       set.Source,
			"ranges":       set.Strings(),
			"invalid":      invalid,
			"addressCount": set.Count().String(),
		}
	case "scan.pause", "scan.resume", "scan.cancel":
		var p struct {
			ScanID string `json:"scanId"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || strings.TrimSpace(p.ScanID) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "scanId is required"}
			break
		}
		session := e.getScan(p.ScanID)
		if session == nil {
			base.Error = &protocol.Error{Code: "scan_not_found", Message: "active scan not found: " + p.ScanID}
			break
		}
		switch req.Method {
		case "scan.pause":
			session.gate.Pause()
			base.Data = map[string]any{"scanId": p.ScanID, "state": "paused"}
		case "scan.resume":
			session.gate.Resume()
			base.Data = map[string]any{"scanId": p.ScanID, "state": "running"}
		case "scan.cancel":
			session.cancelled.Store(true)
			session.cancel()
			base.Data = map[string]any{"scanId": p.ScanID, "state": "cancelling"}
		}
	case "scan.tcp", "dns.resolver.discover":
		base.Error = &protocol.Error{Code: "streaming_required", Message: req.Method + " must be invoked through the streaming dispatcher"}
	case "endpoint.probe":
		var p endpointProbeParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		result, err := probeEndpoints(ctx, p)
		if err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.trace":
		var p struct {
			Domain      string   `json:"domain"`
			QueryType   uint16   `json:"queryType"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		roots := make([]netip.Addr, 0, len(p.RootServers))
		for _, raw := range p.RootServers {
			root, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(raw, "[]")))
			if err != nil {
				base.Error = &protocol.Error{Code: "invalid_params", Message: "invalid root server address: " + raw}
				break
			}
			roots = append(roots, root.Unmap())
		}
		if base.Error != nil {
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnstrace.Trace(ctx, p.Domain, p.QueryType, dnstrace.Options{
			RootServers: roots,
			Timeout:     timeout,
			MaxHops:     p.MaxHops,
			MaxNSDepth:  p.MaxNSDepth,
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "trace_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.authority.compare":
		var p struct {
			Domain      string   `json:"domain"`
			QueryType   uint16   `json:"queryType"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		roots := make([]netip.Addr, 0, len(p.RootServers))
		for _, raw := range p.RootServers {
			root, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(raw, "[]")))
			if err != nil {
				base.Error = &protocol.Error{Code: "invalid_params", Message: "invalid root server address: " + raw}
				break
			}
			roots = append(roots, root.Unmap())
		}
		if base.Error != nil {
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnsauthority.Compare(ctx, p.Domain, p.QueryType, dnsauthority.Options{
			Trace: dnstrace.Options{
				RootServers: roots,
				Timeout:     timeout,
				MaxHops:     p.MaxHops,
				MaxNSDepth:  p.MaxNSDepth,
			},
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "authority_compare_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.trust-anchor.audit":
		var p struct {
			MaxAgeDays int `json:"maxAgeDays"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
				break
			}
		}
		if p.MaxAgeDays < 0 || p.MaxAgeDays > 3650 {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "maxAgeDays must be between 0 and 3650"}
			break
		}
		maxAge := time.Duration(p.MaxAgeDays) * 24 * time.Hour
		base.Data = dnssec.AuditIANARootTrustAnchors(time.Now(), maxAge)
	case "dns.dnssec.inspect":
		var p struct {
			Domain      string   `json:"domain"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		roots, parseErr := parseAddressList(p.RootServers)
		if parseErr != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: parseErr.Error()}
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnssecdiag.Inspect(ctx, p.Domain, dnstrace.Options{
			RootServers: roots,
			Timeout: timeout,
			MaxHops: p.MaxHops,
			MaxNSDepth: p.MaxNSDepth,
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "dnssec_inspect_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.dnssec.chain":
		var p struct {
			Domain      string   `json:"domain"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		roots, parseErr := parseAddressList(p.RootServers)
		if parseErr != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: parseErr.Error()}
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnschain.Validate(ctx, p.Domain, dnschain.Options{
			Trace: dnstrace.Options{
				RootServers: roots,
				Timeout: timeout,
				MaxHops: p.MaxHops,
				MaxNSDepth: p.MaxNSDepth,
			},
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "dnssec_chain_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.dnssec.validate":
		var p struct {
			Domain      string   `json:"domain"`
			QueryType   uint16   `json:"queryType"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		roots, parseErr := parseAddressList(p.RootServers)
		if parseErr != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: parseErr.Error()}
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnsvalidate.Validate(ctx, p.Domain, p.QueryType, dnstrace.Options{
			RootServers: roots,
			Timeout: timeout,
			MaxHops: p.MaxHops,
			MaxNSDepth: p.MaxNSDepth,
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "dnssec_validate_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.consensus.compare":
		var p struct {
			Domain       string   `json:"domain"`
			QueryType    uint16   `json:"queryType"`
			TimeoutMs    int      `json:"timeoutMs"`
			DepthAttempts int     `json:"depthAttempts"`
			DepthMinSuccesses int `json:"depthMinSuccesses"`
			MaxHops      int      `json:"maxHops"`
			MaxNSDepth   int      `json:"maxNsDepth"`
			RootServers  []string `json:"rootServers,omitempty"`
			UseDefaults  *bool    `json:"useDefaultTrustedResolvers,omitempty"`
			CheckDNSSEC  *bool    `json:"checkDnssec,omitempty"`
			CheckDepth   *bool    `json:"checkDepth,omitempty"`
			Trusted      []struct {
				Name string `json:"name"`
				Address string `json:"address"`
				Port uint16 `json:"port"`
				CatalogID string `json:"catalogId,omitempty"`
				Policy resolvercatalog.PolicyClass `json:"policy,omitempty"`
				ServerName string `json:"serverName,omitempty"`
				DoTPort uint16 `json:"dotPort,omitempty"`
				DoHURL string `json:"dohUrl,omitempty"`
			} `json:"trustedResolvers,omitempty"`
			Candidates []struct {
				Name string `json:"name"`
				Address string `json:"address"`
				Port uint16 `json:"port"`
				CatalogID string `json:"catalogId,omitempty"`
				Policy resolvercatalog.PolicyClass `json:"policy,omitempty"`
				ServerName string `json:"serverName,omitempty"`
				DoTPort uint16 `json:"dotPort,omitempty"`
				DoHURL string `json:"dohUrl,omitempty"`
			} `json:"candidateResolvers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		if p.DepthAttempts < 0 || p.DepthAttempts > 7 || p.DepthMinSuccesses < 0 ||
			(p.DepthAttempts > 0 && p.DepthMinSuccesses > p.DepthAttempts) {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "depth quorum must satisfy 0 <= depthMinSuccesses <= depthAttempts <= 7"}
			break
		}
		roots, parseErr := parseAddressList(p.RootServers)
		if parseErr != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: parseErr.Error()}
			break
		}
		resolvers := make([]dnstruth.ResolverEndpoint, 0, len(p.Trusted)+len(p.Candidates)+3)
		useDefaults := true
		if p.UseDefaults != nil {
			useDefaults = *p.UseDefaults
		}
		if useDefaults {
			resolvers = append(resolvers, dnstruth.DefaultTrustedResolvers()...)
		}
		for _, resolver := range p.Trusted {
			resolvers = append(resolvers, dnstruth.ResolverEndpoint{Name: resolver.Name, Address: resolver.Address, Port: resolver.Port, Kind: dnstruth.SourceTrusted, CatalogID: resolver.CatalogID, Policy: resolver.Policy, ServerName: resolver.ServerName, DoTPort: resolver.DoTPort, DoHURL: resolver.DoHURL})
		}
		for _, resolver := range p.Candidates {
			resolvers = append(resolvers, dnstruth.ResolverEndpoint{Name: resolver.Name, Address: resolver.Address, Port: resolver.Port, Kind: dnstruth.SourceCandidate, CatalogID: resolver.CatalogID, Policy: resolver.Policy, ServerName: resolver.ServerName, DoTPort: resolver.DoTPort, DoHURL: resolver.DoHURL})
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		checkDNSSEC := p.CheckDNSSEC != nil && *p.CheckDNSSEC
		result, err := dnstruth.Compare(ctx, p.Domain, p.QueryType, dnstruth.CompareOptions{
			Trace: dnstrace.Options{RootServers: roots, Timeout: timeout, MaxHops: p.MaxHops, MaxNSDepth: p.MaxNSDepth},
			Resolvers: resolvers,
			Timeout: timeout,
			CheckDNSSEC: checkDNSSEC,
			CheckDepth: p.CheckDepth != nil && *p.CheckDepth,
			DepthAttempts: p.DepthAttempts,
			DepthMinimumSuccesses: p.DepthMinSuccesses,
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "dns_consensus_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.repair.inspect":
		var p struct {
			Domain      string   `json:"domain"`
			TimeoutMs   int      `json:"timeoutMs"`
			MaxHops     int      `json:"maxHops"`
			MaxNSDepth  int      `json:"maxNsDepth"`
			RootServers []string `json:"rootServers,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		if strings.TrimSpace(p.Domain) == "" {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "domain is required"}
			break
		}
		roots, parseErr := parseAddressList(p.RootServers)
		if parseErr != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: parseErr.Error()}
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		result, err := dnsrepair.Inspect(ctx, p.Domain, dnsrepair.Options{
			TraceOptions: dnstrace.Options{
				RootServers: roots,
				Timeout: timeout,
				MaxHops: p.MaxHops,
				MaxNSDepth: p.MaxNSDepth,
			},
		})
		if err != nil {
			base.Error = &protocol.Error{Code: "dns_repair_inspect_failed", Message: err.Error()}
			break
		}
		base.Data = result
	case "dns.resolver.catalog.audit":
		var p struct {
			MaxAgeDays int `json:"maxAgeDays"`
		}
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
				break
			}
		}
		if p.MaxAgeDays < 0 || p.MaxAgeDays > 3650 {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "maxAgeDays must be between 0 and 3650"}
			break
		}
		maxAge := time.Duration(p.MaxAgeDays) * 24 * time.Hour
		base.Data = resolvercatalog.Audit(time.Now(), maxAge)
	case "dns.resolver.catalog":
		catalog := resolvercatalog.Builtin()
		if err := resolvercatalog.Validate(catalog); err != nil {
			base.Error = &protocol.Error{Code: "resolver_catalog_invalid", Message: err.Error()}
			break
		}
		base.Data = map[string]any{
			"version": resolvercatalog.Version,
			"resolvers": catalog,
			"referenceEligible": resolvercatalog.ReferenceEligible(),
		}
	case "dns.resolver.profile":
		var p struct {
			Address    string `json:"address"`
			Port       uint16 `json:"port"`
			Domain     string `json:"domain"`
			TimeoutMs  int    `json:"timeoutMs"`
			Attempts   int    `json:"attempts"`
			MinSuccesses int  `json:"minSuccesses"`
			ServerName string `json:"serverName,omitempty"`
			DoTPort    uint16 `json:"dotPort,omitempty"`
			DoHURL     string `json:"dohUrl,omitempty"`
			CheckUDP   *bool  `json:"checkUdp,omitempty"`
			CheckTCP   *bool  `json:"checkTcp,omitempty"`
			CheckEDNS  *bool  `json:"checkEdns,omitempty"`
			CheckTXT   *bool  `json:"checkTxt,omitempty"`
			CheckDoT   *bool  `json:"checkDot,omitempty"`
			CheckDoH   *bool  `json:"checkDoh,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		address, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(p.Address, "[]")))
		if err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "invalid resolver address"}
			break
		}
		if p.Attempts < 0 || p.Attempts > 7 || p.MinSuccesses < 0 ||
			(p.Attempts > 0 && p.MinSuccesses > p.Attempts) {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "resolver profile quorum must satisfy 0 <= minSuccesses <= attempts <= 7"}
			break
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		check := func(value *bool, fallback bool) bool {
			if value == nil {
				return fallback
			}
			return *value
		}
		base.Data = resolverdepth.Profile(ctx, resolverdepth.Options{
			Address: address.Unmap(), Port: p.Port, Domain: p.Domain, Timeout: timeout,
			ServerName: p.ServerName, DoTPort: p.DoTPort, DoHURL: p.DoHURL,
			Attempts: p.Attempts, MinimumSuccesses: p.MinSuccesses,
			CheckUDP: check(p.CheckUDP, true),
			CheckTCP: check(p.CheckTCP, true),
			CheckEDNS: check(p.CheckEDNS, true),
			CheckTXT: check(p.CheckTXT, true),
			CheckDoT: check(p.CheckDoT, p.ServerName != ""),
			CheckDoH: check(p.CheckDoH, p.DoHURL != ""),
		})
	case "dns.resolver.qualify":
		var p struct {
			Address          string   `json:"address"`
			Port             uint16   `json:"port"`
			Domain           string   `json:"domain"`
			TimeoutMs        int      `json:"timeoutMs"`
			DepthAttempts    int      `json:"depthAttempts"`
			DepthMinSuccesses int     `json:"depthMinSuccesses"`
			ReferenceAnswers []string `json:"referenceAnswers"`
			CheckUDP         *bool    `json:"checkUdp,omitempty"`
			CheckTCP         *bool    `json:"checkTcp,omitempty"`
			CheckHijack      *bool    `json:"checkHijack,omitempty"`
			CheckDNSSEC      *bool    `json:"checkDnssec,omitempty"`
			CheckDepth       *bool    `json:"checkDepth,omitempty"`
			ServerName       string   `json:"serverName,omitempty"`
			DoTPort          uint16   `json:"dotPort,omitempty"`
			DoHURL           string   `json:"dohUrl,omitempty"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: err.Error()}
			break
		}
		address, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(p.Address, "[]")))
		if err != nil {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "invalid resolver address"}
			break
		}
		refs := make([]netip.Addr, 0, len(p.ReferenceAnswers))
		invalidRef := false
		for _, raw := range p.ReferenceAnswers {
			ref, parseErr := netip.ParseAddr(strings.TrimSpace(strings.Trim(raw, "[]")))
			if parseErr != nil {
				invalidRef = true
				break
			}
			refs = append(refs, ref.Unmap())
		}
		if invalidRef {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "invalid reference answer"}
			break
		}
		if p.DepthAttempts < 0 || p.DepthAttempts > 7 || p.DepthMinSuccesses < 0 ||
			(p.DepthAttempts > 0 && p.DepthMinSuccesses > p.DepthAttempts) {
			base.Error = &protocol.Error{Code: "invalid_params", Message: "depth quorum must satisfy 0 <= depthMinSuccesses <= depthAttempts <= 7"}
			break
		}
		checkUDP, checkTCP, checkHijack := true, true, true
		if p.CheckUDP != nil {
			checkUDP = *p.CheckUDP
		}
		if p.CheckTCP != nil {
			checkTCP = *p.CheckTCP
		}
		if p.CheckHijack != nil {
			checkHijack = *p.CheckHijack
		}
		timeout := time.Duration(p.TimeoutMs) * time.Millisecond
		if p.TimeoutMs <= 0 {
			timeout = 2 * time.Second
		}
		var dnssecRefs []netip.Addr
		var dnssecStatus string
		checkDNSSEC := p.CheckDNSSEC != nil && *p.CheckDNSSEC
		if checkDNSSEC {
			validation, validateErr := dnsvalidate.Validate(ctx, p.Domain, dnswire.TypeA, dnstrace.Options{Timeout: timeout})
			if validateErr != nil {
				dnssecStatus = "validation-error"
			} else {
				dnssecStatus = validation.Status
				if validation.AnswerAuthenticated && validation.TrustScope == "root-anchored" {
					for _, answer := range validation.Trace.FinalAnswers {
						if strings.TrimSpace(answer.Address) == "" {
							continue
						}
						parsed, parseErr := netip.ParseAddr(answer.Address)
						if parseErr == nil {
							dnssecRefs = append(dnssecRefs, parsed.Unmap())
						}
					}
				}
			}
		}
		qualification := resolverqual.Qualify(ctx, resolverqual.Options{
			Address: address.Unmap(), Port: p.Port, Domain: p.Domain, Timeout: timeout,
			ReferenceAnswers: refs,
			AuthenticatedReferenceAnswers: dnssecRefs,
			AuthenticatedReferenceStatus: dnssecStatus,
			CheckUDP: checkUDP, CheckTCP: checkTCP, CheckHijack: checkHijack,
		})
		if p.CheckDepth != nil && *p.CheckDepth {
			depth := resolverdepth.Profile(ctx, resolverdepth.Options{
				Address: address.Unmap(), Port: p.Port, Domain: p.Domain, Timeout: timeout,
				ServerName: p.ServerName, DoTPort: p.DoTPort, DoHURL: p.DoHURL,
				Attempts: p.DepthAttempts, MinimumSuccesses: p.DepthMinSuccesses,
				CheckUDP: true, CheckTCP: true, CheckEDNS: true, CheckTXT: true,
				CheckDoT: p.ServerName != "", CheckDoH: p.DoHURL != "",
			})
			qualification.Depth = &depth
		}
		base.Data = qualification
	default:
		base.Error = &protocol.Error{Code: "unknown_method", Message: "unknown method: " + strings.TrimSpace(req.Method)}
	}
	return base
}

// HandleStream emits one or more responses for streaming methods while preserving the
// same protocol envelope as unary requests.
func (e *Engine) HandleStream(ctx context.Context, req protocol.Request, emit func(protocol.Response) error) error {
	if !IsStreamingMethod(req.Method) {
		return emit(e.Handle(ctx, req))
	}
	base := protocol.Response{Version: protocol.Version, ID: req.ID}
	if req.Version != protocol.Version {
		base.Error = &protocol.Error{Code: "protocol_version_mismatch", Message: fmt.Sprintf("supported=%d requested=%d", protocol.Version, req.Version)}
		return emit(base)
	}
	if strings.TrimSpace(req.ID) == "" {
		base.Error = &protocol.Error{Code: "invalid_request", Message: "streaming request id is required"}
		return emit(base)
	}
	switch req.Method {
	case "scan.tcp":
		return e.runTCPScan(ctx, req, emit)
	case "dns.resolver.discover":
		return e.runResolverDiscovery(ctx, req, emit)
	default:
		return emit(e.Handle(ctx, req))
	}
}

type resolverDiscoveryParams struct {
	Targets     []string `json:"targets"`
	Port        uint16   `json:"port"`
	Domain      string   `json:"domain"`
	TimeoutMs   int      `json:"timeoutMs"`
	Concurrency int      `json:"concurrency"`
	MaxTargets  int64    `json:"maxTargets"`
}

func (e *Engine) runResolverDiscovery(parent context.Context, req protocol.Request, emit func(protocol.Response) error) error {
	var p resolverDiscoveryParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "invalid_params", Message: err.Error()}})
	}
	ranges, invalid := targets.ParseMany(p.Targets)
	if len(ranges) == 0 {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "invalid_params", Message: "no valid target ranges"}})
	}
	if p.Port == 0 {
		p.Port = 53
	}
	if strings.TrimSpace(p.Domain) == "" {
		p.Domain = "example.com"
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 1200
	}
	if p.Concurrency <= 0 {
		p.Concurrency = 128
	}
	if p.MaxTargets <= 0 {
		p.MaxTargets = 100_000
	}

	scanCtx, cancel := context.WithCancel(parent)
	session := &scanSession{cancel: cancel, gate: scheduler.NewGate()}
	if !e.addScan(req.ID, session) {
		cancel()
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "scan_already_active", Message: "scan id is already active"}})
	}
	defer func() {
		cancel()
		e.removeScan(req.ID)
	}()

	total := new(big.Int)
	for _, r := range ranges {
		total.Add(total, r.Count())
	}
	if big.NewInt(p.MaxTargets).Cmp(total) < 0 {
		total.SetInt64(p.MaxTargets)
	}
	if err := emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "started", Data: map[string]any{
		"scanId": req.ID, "addressCount": total.String(), "invalid": invalid, "port": p.Port, "domain": p.Domain,
	}}); err != nil {
		return err
	}

	summary, err := resolverdiscovery.Run(scanCtx, resolverdiscovery.Options{
		Ranges: ranges, Port: p.Port, Domain: p.Domain, Timeout: time.Duration(p.TimeoutMs) * time.Millisecond,
		Concurrency: p.Concurrency, MaxTargets: p.MaxTargets, Gate: session.gate,
	}, resolverdiscovery.Callbacks{
		Result: func(result resolverdiscovery.Result) error {
			answers := make([]string, 0, len(result.AnswerIPs))
			for _, answer := range result.AnswerIPs {
				answers = append(answers, answer.String())
			}
			return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "result", Data: map[string]any{
				"address": result.Address.String(), "port": result.Port,
				"latencyMs": float64(result.Latency) / float64(time.Millisecond),
				"rcode":     result.RCode, "recursionAvailable": result.RecursionAvailable,
				"truncated": result.Truncated, "answerIps": answers,
			}})
		},
		Progress: func(progress resolverdiscovery.Progress) error {
			return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "progress", Data: map[string]any{
				"addressesDispatched": progress.AddressesDispatched,
				"addressesProcessed":  progress.AddressesProcessed,
				"candidates":          progress.Candidates,
			}})
		},
	})
	if err != nil && !session.cancelled.Load() {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "scan_failed", Message: err.Error()}})
	}
	event := "completed"
	if session.cancelled.Load() {
		event = "cancelled"
	}
	return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: event, Data: map[string]any{
		"scanId":              req.ID,
		"addressesDispatched": summary.AddressesDispatched,
		"addressesProcessed":  summary.AddressesProcessed,
		"candidates":          summary.Candidates,
	}})
}

type tcpScanParams struct {
	Targets     []string `json:"targets"`
	Ports       []uint16 `json:"ports"`
	TimeoutMs   int      `json:"timeoutMs"`
	Concurrency int      `json:"concurrency"`
	MaxTargets  int64    `json:"maxTargets"`
}

func (e *Engine) runTCPScan(parent context.Context, req protocol.Request, emit func(protocol.Response) error) error {
	var p tcpScanParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "invalid_params", Message: err.Error()}})
	}
	ranges, invalid := targets.ParseMany(p.Targets)
	if len(ranges) == 0 {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "invalid_params", Message: "no valid target ranges"}})
	}
	ports := make([]uint16, 0, len(p.Ports))
	seenPorts := make(map[uint16]struct{}, len(p.Ports))
	for _, port := range p.Ports {
		if port == 0 {
			continue
		}
		if _, exists := seenPorts[port]; exists {
			continue
		}
		seenPorts[port] = struct{}{}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "invalid_params", Message: "at least one non-zero port is required"}})
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 1500
	}
	if p.Concurrency <= 0 {
		p.Concurrency = 256
	}
	if p.MaxTargets <= 0 {
		p.MaxTargets = 100_000
	}

	scanCtx, cancel := context.WithCancel(parent)
	session := &scanSession{cancel: cancel, gate: scheduler.NewGate()}
	if !e.addScan(req.ID, session) {
		cancel()
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "scan_already_active", Message: "scan id is already active"}})
	}
	defer func() {
		cancel()
		e.removeScan(req.ID)
	}()

	total := new(big.Int)
	for _, r := range ranges {
		total.Add(total, r.Count())
	}
	if big.NewInt(p.MaxTargets).Cmp(total) < 0 {
		total.SetInt64(p.MaxTargets)
	}
	endpointTotal := new(big.Int).Mul(new(big.Int).Set(total), big.NewInt(int64(len(ports))))
	if err := emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "started", Data: map[string]any{
		"scanId": req.ID, "addressCount": total.String(), "endpointCount": endpointTotal.String(), "invalid": invalid,
	}}); err != nil {
		return err
	}

	summary, err := scan.RunTCP(scanCtx, scan.TCPOptions{
		Ranges: ranges, Ports: ports, Timeout: time.Duration(p.TimeoutMs) * time.Millisecond,
		Concurrency: p.Concurrency, MaxTargets: p.MaxTargets, Gate: session.gate,
	}, scan.TCPCallbacks{
		Result: func(result scan.TCPResult) error {
			return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "result", Data: map[string]any{
				"address": result.Address.String(), "port": result.Port,
				"latencyMs": float64(result.Latency) / float64(time.Millisecond),
			}})
		},
		Progress: func(progress scan.TCPProgress) error {
			return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: "progress", Data: map[string]any{
				"addressesDispatched": progress.AddressesDispatched,
				"endpointsProcessed":  progress.EndpointsProcessed,
				"openEndpoints":       progress.OpenEndpoints,
			}})
		},
	})
	if err != nil && !session.cancelled.Load() {
		return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Error: &protocol.Error{Code: "scan_failed", Message: err.Error()}})
	}
	event := "completed"
	if session.cancelled.Load() {
		event = "cancelled"
	}
	return emit(protocol.Response{Version: protocol.Version, ID: req.ID, Event: event, Data: map[string]any{
		"scanId":              req.ID,
		"addressesDispatched": summary.AddressesDispatched,
		"endpointsProcessed":  summary.EndpointsProcessed,
		"openEndpoints":       summary.OpenEndpoints,
	}})
}

func (e *Engine) addScan(id string, session *scanSession) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.scans[id]; exists {
		return false
	}
	e.scans[id] = session
	return true
}

func (e *Engine) getScan(id string) *scanSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scans[id]
}

func (e *Engine) removeScan(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.scans, id)
}

type endpointProbeParams struct {
	Addresses          []string `json:"addresses"`
	Port               uint16   `json:"port"`
	ServerName         string   `json:"serverName"`
	HTTPHost           string   `json:"httpHost"`
	Scheme             string   `json:"scheme"`
	Path               string   `json:"path"`
	Method             string   `json:"method"`
	TimeoutMs          int      `json:"timeoutMs"`
	Attempts           int      `json:"attempts"`
	MinSuccesses       int      `json:"minSuccesses"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type endpointProbeResult struct {
	Address              string                  `json:"address"`
	Port                 uint16                  `json:"port"`
	StatusCode           int                     `json:"statusCode,omitempty"`
	Attempts             int                     `json:"attempts"`
	Successes            int                     `json:"successes"`
	ConsecutiveSuccesses int                     `json:"consecutiveSuccesses"`
	Reliability          float64                 `json:"reliability"`
	MedianLatencyMs      float64                 `json:"medianLatencyMs,omitempty"`
	Qualified            bool                    `json:"qualified"`
	Edge                 measure.EdgeObservation `json:"edge,omitempty"`
	Errors               []string                `json:"errors,omitempty"`
}

type endpointProbeResponse struct {
	Results []endpointProbeResult `json:"results"`
	Invalid []string              `json:"invalid,omitempty"`
}

func parseAddressList(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	for _, raw := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(raw, "[]")))
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", raw)
		}
		out = append(out, address.Unmap())
	}
	return out, nil
}

func probeEndpoints(ctx context.Context, p endpointProbeParams) (endpointProbeResponse, error) {
	if p.Port == 0 {
		return endpointProbeResponse{}, fmt.Errorf("port is required")
	}
	if strings.TrimSpace(p.HTTPHost) == "" && strings.TrimSpace(p.ServerName) == "" {
		return endpointProbeResponse{}, fmt.Errorf("serverName or httpHost is required")
	}
	if p.Attempts <= 0 {
		p.Attempts = 3
	}
	if p.MinSuccesses <= 0 {
		p.MinSuccesses = 2
	}
	if p.MinSuccesses > p.Attempts {
		return endpointProbeResponse{}, fmt.Errorf("minSuccesses cannot exceed attempts")
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 5000
	}
	if p.Scheme == "" {
		p.Scheme = "https"
	}
	if p.Method == "" {
		p.Method = http.MethodHead
	}

	out := endpointProbeResponse{Results: make([]endpointProbeResult, 0, len(p.Addresses))}
	for _, raw := range p.Addresses {
		if err := ctx.Err(); err != nil {
			break
		}
		text := strings.TrimSpace(strings.Trim(raw, "[]"))
		address, err := netip.ParseAddr(text)
		if err != nil {
			out.Invalid = append(out.Invalid, raw)
			continue
		}
		target := measure.DialTarget{
			Address:    address,
			Port:       p.Port,
			ServerName: strings.TrimSpace(p.ServerName),
			HTTPHost:   strings.TrimSpace(p.HTTPHost),
		}
		var statusCode int
		var edge measure.EdgeObservation
		quorum := measure.RunQuorum(ctx, p.Attempts, p.MinSuccesses, func(attemptCtx context.Context, _ int) measure.AttemptResult {
			observation, probeErr := measure.ProbePinnedHTTP(attemptCtx, target, measure.HTTPProbeOptions{
				Scheme:             p.Scheme,
				Path:               p.Path,
				Method:             p.Method,
				Timeout:            time.Duration(p.TimeoutMs) * time.Millisecond,
				InsecureSkipVerify: p.InsecureSkipVerify,
			})
			if probeErr != nil {
				return measure.AttemptResult{Error: probeErr}
			}
			statusCode = observation.StatusCode
			if edge.Provider == "" && observation.Edge.Provider != "" {
				edge = observation.Edge
			}
			return measure.AttemptResult{Success: true, Latency: observation.Latency}
		})
		reliability := 0.0
		if quorum.Attempts > 0 {
			reliability = float64(quorum.Successes) / float64(quorum.Attempts)
		}
		out.Results = append(out.Results, endpointProbeResult{
			Address:              address.String(),
			Port:                 p.Port,
			StatusCode:           statusCode,
			Attempts:             quorum.Attempts,
			Successes:            quorum.Successes,
			ConsecutiveSuccesses: quorum.ConsecutiveSuccesses,
			Reliability:          reliability,
			MedianLatencyMs:      float64(quorum.MedianLatency) / float64(time.Millisecond),
			Qualified:            quorum.Meets(p.MinSuccesses),
			Edge:                 edge,
			Errors:               quorum.Errors,
		})
	}
	return out, nil
}
