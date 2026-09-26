package dnstrace

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnswire"
)

type ExchangeFunc func(context.Context, netip.Addr, uint16, string, uint16, dnsmeasure.Transport, time.Duration, bool) (dnsmeasure.Observation, error)

type Options struct {
	RootServers []netip.Addr
	Port        uint16
	Timeout     time.Duration
	MaxHops     int
	MaxNSDepth  int
	Exchange    ExchangeFunc
}

type Record struct {
	Name    string `json:"name"`
	Type    uint16 `json:"type"`
	TTL     uint32 `json:"ttl"`
	Address string `json:"address,omitempty"`
	Target  string `json:"target,omitempty"`
}

type AuthorityEndpoint struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// AliasStep records the semantic alias transformation that resolution followed.
// CNAME steps authenticate the CNAME RRset at Owner. DNAME steps authenticate the
// DNAME RRset at Owner; ResultName is the RFC 6672 synthesized descendant name.
type AliasStep struct {
	QueryName         string `json:"queryName"`
	Owner             string `json:"owner"`
	Target            string `json:"target"`
	ResultName        string `json:"resultName"`
	Type              uint16 `json:"type"`
	Synthesized       bool   `json:"synthesized,omitempty"`
	AuthoritativeZone string `json:"authoritativeZone,omitempty"`
}

type Hop struct {
	NameServer    string               `json:"nameServer"`
	QueryName     string               `json:"queryName"`
	QueryType     uint16               `json:"queryType"`
	Transport     dnsmeasure.Transport `json:"transport"`
	LatencyMs     float64              `json:"latencyMs"`
	RCode         uint8                `json:"rcode"`
	Authoritative bool                 `json:"authoritative"`
	Truncated     bool                 `json:"truncated"`
	Answers       []Record             `json:"answers,omitempty"`
	Authorities   []Record             `json:"authorities,omitempty"`
	Additionals   []Record             `json:"additionals,omitempty"`
}

type Result struct {
	Domain        string              `json:"domain"`
	QueryType     uint16              `json:"queryType"`
	Hops          []Hop               `json:"hops"`
	Delegation    []AuthorityEndpoint `json:"delegation,omitempty"`
	AliasChain    []AliasStep         `json:"aliasChain,omitempty"`
	FinalAnswers  []Record            `json:"finalAnswers,omitempty"`
	Complete      bool                `json:"complete"`
	TerminalRCode uint8               `json:"terminalRcode,omitempty"`
	TerminalZone  string              `json:"terminalZone,omitempty"`
	ErrorCode     string              `json:"errorCode,omitempty"`
	Error         string              `json:"error,omitempty"`
	WireAnswers     []dnswire.ResourceRecord `json:"-"`
	WireAuthorities []dnswire.ResourceRecord `json:"-"`
	WireAdditionals []dnswire.ResourceRecord `json:"-"`
}

var defaultRoots = []netip.Addr{
	netip.MustParseAddr("198.41.0.4"),
	netip.MustParseAddr("199.9.14.201"),
	netip.MustParseAddr("192.33.4.12"),
	netip.MustParseAddr("199.7.91.13"),
	netip.MustParseAddr("192.203.230.10"),
	netip.MustParseAddr("192.5.5.241"),
}

func Trace(ctx context.Context, domain string, qtype uint16, opts Options) (Result, error) {
	normalizeOptions(&opts)
	return trace(ctx, domain, qtype, opts, 0)
}

func trace(ctx context.Context, domain string, qtype uint16, opts Options, nsDepth int) (Result, error) {
	domain = normalizeTraceName(domain)
	if domain == "" {
		return Result{}, fmt.Errorf("domain is required")
	}
	if qtype == 0 {
		qtype = dnswire.TypeA
	}
	roots := uniqueValid(opts.RootServers)
	if len(roots) == 0 {
		roots = append([]netip.Addr(nil), defaultRoots...)
	}

	result := Result{Domain: domain, QueryType: qtype, Hops: make([]Hop, 0, 8)}
	currentName := domain
	currentZone := "."
	servers := roots
	seenNames := map[string]struct{}{strings.ToLower(currentName): {}}

	for len(result.Hops) < opts.MaxHops {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		observation, err := queryAny(ctx, opts, servers, currentName, qtype)
		if err != nil {
			result.ErrorCode = "nameserver_unreachable"
			result.Error = err.Error()
			return result, nil
		}
		result.Hops = append(result.Hops, makeHop(observation))
		result.TerminalRCode = observation.Header.RCode
		result.WireAuthorities = append([]dnswire.ResourceRecord(nil), observation.Authorities...)
		result.WireAdditionals = append([]dnswire.ResourceRecord(nil), observation.Additionals...)

		if observation.Header.RCode != 0 {
			if observation.Header.RCode == 3 && observation.Header.AA {
				result.TerminalZone = normalizeTraceName(currentZone)
				result.Complete = true
				return result, nil
			}
			result.ErrorCode = "unusable_rcode"
			result.Error = fmt.Sprintf(
				"all reachable nameservers failed to produce a usable authoritative response; last rcode=%d",
				observation.Header.RCode)
			return result, nil
		}
		// A referral may legally carry answer-section data, but it is not
		// authoritative terminal/alias evidence. Only consume answer chains from
		// authoritative responses; otherwise continue with delegation processing.
		if observation.Header.AA {
			result.WireAnswers = append(result.WireAnswers, observation.Answers...)
			answers, aliases, nextName, aliasConflict, aliasLoop, aliasErr :=
				answerChainDetailed(observation.Answers, currentName, qtype)
			if aliasErr != nil {
				result.ErrorCode = "invalid_alias"
				result.Error = aliasErr.Error()
				return result, nil
			}
			if aliasConflict {
				// Keep the established v1 error code for compatibility; the structured
				// alias chain distinguishes CNAME and DNAME evidence.
				result.ErrorCode = "cname_conflict"
				result.Error = "conflicting alias and terminal-answer evidence while resolving " + currentName
				return result, nil
			}
			if aliasLoop {
				result.ErrorCode = "cname_loop"
				result.Error = "alias loop detected while resolving " + currentName
				return result, nil
			}

			for _, alias := range aliases {
				alias.AuthoritativeZone = normalizeTraceName(currentZone)
				key := strings.ToLower(normalizeTraceName(alias.ResultName))
				if _, exists := seenNames[key]; exists {
					result.ErrorCode = "cname_loop"
					result.Error = "alias loop detected at " + alias.ResultName
					return result, nil
				}
				seenNames[key] = struct{}{}
				result.AliasChain = append(result.AliasChain, alias)
			}

			if len(answers) > 0 {
				result.FinalAnswers = mapRecords(answers)
				result.TerminalZone = normalizeTraceName(currentZone)
				result.Complete = true
				return result, nil
			}
			if nextName != "" {
				currentName = nextName
				currentZone = "."
				servers = roots
				continue
			}
		}

		delegationZone, nsNames, referralErr := referralAuthority(observation.Authorities, currentName)
		if referralErr != nil {
			result.ErrorCode = "invalid_referral"
			result.Error = referralErr.Error()
			return result, nil
		}
		if len(nsNames) == 0 {
			if observation.Header.AA {
				result.TerminalZone = normalizeTraceName(currentZone)
				result.Complete = true
				return result, nil
			}
			result.ErrorCode = "no_referral"
			result.Error = "response contained neither a terminal answer nor a valid NS referral"
			return result, nil
		}

		currentZone = normalizeTraceName(delegationZone)
		delegation := delegationFromGlue(observation.Additionals, nsNames, delegationZone)
		if nsDepth < opts.MaxNSDepth {
			for i := range delegation {
				if len(delegation[i].Addresses) != 0 {
					continue
				}
				addresses, resolveErr := resolveNameserver(ctx, delegation[i].Name, opts, nsDepth+1)
				if resolveErr != nil {
					delegation[i].Error = resolveErr.Error()
					continue
				}
				for _, address := range addresses {
					delegation[i].Addresses = append(delegation[i].Addresses, address.String())
				}
			}
		}
		result.Delegation = delegation
		nextServers := delegationAddresses(delegation)
		if len(nextServers) == 0 {
			result.ErrorCode = "no_delegation_address"
			if nsDepth >= opts.MaxNSDepth {
				result.Error = fmt.Sprintf("referral required nameserver resolution beyond max depth %d", opts.MaxNSDepth)
			} else {
				result.Error = "referral nameservers could not be resolved to usable A/AAAA addresses"
			}
			return result, nil
		}
		servers = nextServers
	}
	result.ErrorCode = "max_hops"
	result.Error = fmt.Sprintf("trace exceeded %d hops", opts.MaxHops)
	return result, nil
}

func normalizeOptions(opts *Options) {
	if opts.Port == 0 {
		opts.Port = 53
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.MaxHops <= 0 {
		opts.MaxHops = 32
	}
	if opts.MaxNSDepth <= 0 {
		opts.MaxNSDepth = 4
	}
	if opts.Exchange == nil {
		opts.Exchange = dnsmeasure.QueryWithRecursion
	}
}

func resolveNameserver(ctx context.Context, name string, opts Options, nsDepth int) ([]netip.Addr, error) {
	var addresses []netip.Addr
	var failures []string
	for _, qtype := range []uint16{dnswire.TypeA, dnswire.TypeAAAA} {
		resolved, err := trace(ctx, name, qtype, opts, nsDepth)
		if err != nil {
			return nil, err
		}
		if resolved.ErrorCode != "" {
			failures = append(failures, resolved.ErrorCode+": "+resolved.Error)
			continue
		}
		for _, answer := range resolved.FinalAnswers {
			if answer.Address == "" {
				continue
			}
			address, err := netip.ParseAddr(answer.Address)
			if err == nil {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	addresses = uniqueValid(addresses)
	if len(addresses) == 0 {
		if len(failures) == 0 {
			return nil, fmt.Errorf("no A/AAAA address observed for %s", name)
		}
		return nil, fmt.Errorf("%s: %s", name, strings.Join(failures, "; "))
	}
	return addresses, nil
}

func queryAny(ctx context.Context, opts Options, servers []netip.Addr, name string, qtype uint16) (dnsmeasure.Observation, error) {
	var failures []string
	var lastObserved *dnsmeasure.Observation
	for _, server := range uniqueValid(servers) {
		observation, err := opts.Exchange(ctx, server, opts.Port, name, qtype, dnsmeasure.UDP, opts.Timeout, false)
		if err != nil {
			failures = append(failures, server.String()+": "+err.Error())
			continue
		}
		if observation.Header.TC {
			tcpObservation, tcpErr := opts.Exchange(ctx, server, opts.Port, name, qtype, dnsmeasure.TCP, opts.Timeout, false)
			if tcpErr != nil {
				failures = append(failures, server.String()+" tcp fallback: "+tcpErr.Error())
				continue
			}
			observation = tcpObservation
		}
		candidate := observation
		lastObserved = &candidate

		// Iterative resolution can terminate only on authoritative NOERROR/NXDOMAIN
		// evidence. Other RCODEs are server/query failures and should not prevent an
		// alternate authority from answering.
		if observation.Header.RCode != 0 && observation.Header.RCode != 3 {
			failures = append(failures, fmt.Sprintf("%s: unusable dns rcode %d", server, observation.Header.RCode))
			continue
		}
		if observation.Header.AA {
			return observation, nil
		}
		if observation.Header.RCode == 3 {
			failures = append(failures, server.String()+": non-authoritative NXDOMAIN")
			continue
		}

		// Non-authoritative NOERROR is useful only when it is a valid delegation.
		// Cached/lame terminal answers must never become iterative truth.
		_, names, referralErr := referralAuthority(observation.Authorities, name)
		if referralErr != nil {
			failures = append(failures, server.String()+": "+referralErr.Error())
			continue
		}
		if len(names) > 0 {
			return observation, nil
		}
		failures = append(failures, server.String()+": response was neither authoritative nor a valid referral")
	}
	if lastObserved != nil {
		return *lastObserved, nil
	}
	if len(failures) == 0 {
		return dnsmeasure.Observation{}, fmt.Errorf("no usable nameserver addresses")
	}
	return dnsmeasure.Observation{}, fmt.Errorf("%s", strings.Join(failures, "; "))
}

func makeHop(observation dnsmeasure.Observation) Hop {
	return Hop{
		NameServer: observation.Address.String(), QueryName: observation.Domain, QueryType: observation.QueryType,
		Transport: observation.Transport, LatencyMs: float64(observation.Latency) / float64(time.Millisecond),
		RCode: observation.Header.RCode, Authoritative: observation.Header.AA, Truncated: observation.Header.TC,
		Answers: mapRecords(observation.Answers), Authorities: mapRecords(observation.Authorities), Additionals: mapRecords(observation.Additionals),
	}
}

func mapRecords(values []dnswire.ResourceRecord) []Record {
	if len(values) == 0 {
		return nil
	}
	out := make([]Record, 0, len(values))
	for _, value := range values {
		record := Record{Name: value.Name, Type: value.Type, TTL: value.TTL, Target: value.Target}
		if value.Address.IsValid() {
			record.Address = value.Address.Unmap().String()
		}
		out = append(out, record)
	}
	return out
}

func answerChain(values []dnswire.ResourceRecord, queryName string, qtype uint16) ([]dnswire.ResourceRecord, string, bool, bool) {
	answers, _, nextName, conflict, loop, _ := answerChainDetailed(values, queryName, qtype)
	return answers, nextName, conflict, loop
}

func answerChainDetailed(
	values []dnswire.ResourceRecord,
	queryName string,
	qtype uint16,
) ([]dnswire.ResourceRecord, []AliasStep, string, bool, bool, error) {
	current := normalizeTraceName(queryName)
	seen := map[string]struct{}{strings.ToLower(current): {}}
	var aliases []AliasStep
	followed := false

	for {
		var answers []dnswire.ResourceRecord
		cnameTargets := map[string]string{}
		for _, value := range values {
			if !equalTraceName(value.Name, current) {
				continue
			}
			if value.Type == qtype {
				answers = append(answers, value)
			}
			if qtype != dnswire.TypeCNAME && value.Type == dnswire.TypeCNAME {
				candidate := normalizeTraceName(value.Target)
				if candidate != "" {
					cnameTargets[strings.ToLower(candidate)] = candidate
				}
			}
		}

		if len(answers) > 0 && (qtype == dnswire.TypeCNAME || qtype == dnswire.TypeDNAME) {
			return answers, aliases, "", false, false, nil
		}

		dnameOwner, dnameTarget, dnameConflict := applicableDNAME(values, current)
		if dnameConflict || len(cnameTargets) > 1 {
			return nil, aliases, "", true, false, nil
		}

		var cnameTarget string
		for _, candidate := range cnameTargets {
			cnameTarget = candidate
		}

		var alias AliasStep
		hasAlias := false
		if dnameOwner != "" {
			resultName, err := synthesizeDNAME(current, dnameOwner, dnameTarget)
			if err != nil {
				return nil, aliases, "", false, false, err
			}
			if cnameTarget != "" && !equalTraceName(cnameTarget, resultName) {
				return nil, aliases, "", true, false, nil
			}
			alias = AliasStep{
				QueryName: current,
				Owner: dnameOwner,
				Target: dnameTarget,
				ResultName: resultName,
				Type: dnswire.TypeDNAME,
				Synthesized: true,
			}
			hasAlias = true
		} else if cnameTarget != "" {
			alias = AliasStep{
				QueryName: current,
				Owner: current,
				Target: cnameTarget,
				ResultName: cnameTarget,
				Type: dnswire.TypeCNAME,
			}
			hasAlias = true
		}

		if len(answers) > 0 {
			if hasAlias {
				return nil, aliases, "", true, false, nil
			}
			return answers, aliases, "", false, false, nil
		}
		if !hasAlias {
			if followed {
				return nil, aliases, current, false, false, nil
			}
			return nil, aliases, "", false, false, nil
		}

		key := strings.ToLower(normalizeTraceName(alias.ResultName))
		if _, exists := seen[key]; exists {
			return nil, aliases, alias.ResultName, false, true, nil
		}
		seen[key] = struct{}{}
		aliases = append(aliases, alias)
		current = alias.ResultName
		followed = true
	}
}

func applicableDNAME(values []dnswire.ResourceRecord, queryName string) (string, string, bool) {
	queryName = normalizeTraceName(queryName)
	bestLabels := -1
	bestOwner := ""
	targets := map[string]string{}

	for _, value := range values {
		if value.Type != dnswire.TypeDNAME {
			continue
		}
		owner := normalizeTraceName(value.Name)
		target := normalizeTraceName(value.Target)
		if owner == "" || target == "" || !strictDNSDescendant(queryName, owner) {
			continue
		}
		labels := dnsLabelCount(owner)
		if labels > bestLabels {
			bestLabels = labels
			bestOwner = owner
			targets = map[string]string{strings.ToLower(target): target}
			continue
		}
		if labels == bestLabels && equalTraceName(owner, bestOwner) {
			targets[strings.ToLower(target)] = target
		}
	}
	if bestOwner == "" {
		return "", "", false
	}
	if len(targets) != 1 {
		return "", "", true
	}
	for _, target := range targets {
		return bestOwner, target, false
	}
	return "", "", true
}

func synthesizeDNAME(queryName, owner, target string) (string, error) {
	queryName = normalizeTraceName(queryName)
	owner = normalizeTraceName(owner)
	target = normalizeTraceName(target)
	if !strictDNSDescendant(queryName, owner) {
		return "", fmt.Errorf("DNAME owner %q is not an ancestor of %q", owner, queryName)
	}

	queryLabels := splitDNSLabels(queryName)
	ownerLabels := splitDNSLabels(owner)
	targetLabels := splitDNSLabels(target)
	prefixCount := len(queryLabels) - len(ownerLabels)
	labels := append([]string(nil), queryLabels[:prefixCount]...)
	labels = append(labels, targetLabels...)
	if len(labels) == 0 {
		return ".", nil
	}

	wireLength := 1
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("DNAME synthesis produced invalid label %q", label)
		}
		wireLength += 1 + len(label)
	}
	if wireLength > 255 {
		return "", fmt.Errorf("DNAME synthesis exceeds the 255-octet DNS name limit")
	}
	return strings.Join(labels, "."), nil
}

func strictDNSDescendant(name, owner string) bool {
	name = strings.ToLower(normalizeTraceName(name))
	owner = strings.ToLower(normalizeTraceName(owner))
	if name == "" || owner == "" || name == owner {
		return false
	}
	if owner == "." {
		return name != "."
	}
	return strings.HasSuffix(name, "."+owner)
}

func dnsLabelCount(name string) int {
	return len(splitDNSLabels(name))
}

func splitDNSLabels(name string) []string {
	name = normalizeTraceName(name)
	if name == "" || name == "." {
		return nil
	}
	return strings.Split(name, ".")
}

func equalTraceName(left, right string) bool {
	return strings.EqualFold(normalizeTraceName(left), normalizeTraceName(right))
}

func targetsOfType(values []dnswire.ResourceRecord, rrType uint16) []string {
	set := make(map[string]struct{})
	for _, value := range values {
		if value.Type != rrType || strings.TrimSpace(value.Target) == "" {
			continue
		}
		set[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value.Target), "."))] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func referralAuthority(values []dnswire.ResourceRecord, queryName string) (string, []string, error) {
	queryName = strings.ToLower(normalizeTraceName(queryName))
	zones := make(map[string]map[string]struct{})
	for _, value := range values {
		if value.Type != dnswire.TypeNS {
			continue
		}
		zone := strings.ToLower(normalizeTraceName(value.Name))
		target := strings.ToLower(normalizeTraceName(value.Target))
		if zone == "" || target == "" || !dnsNameWithinZone(queryName, zone) {
			continue
		}
		if zones[zone] == nil {
			zones[zone] = make(map[string]struct{})
		}
		zones[zone][target] = struct{}{}
	}
	if len(zones) == 0 {
		return "", nil, nil
	}
	if len(zones) > 1 {
		owners := make([]string, 0, len(zones))
		for zone := range zones {
			owners = append(owners, zone)
		}
		sort.Strings(owners)
		return "", nil, fmt.Errorf("ambiguous NS referral zones for %s: %s", queryName, strings.Join(owners, ", "))
	}
	var zone string
	for candidate := range zones {
		zone = candidate
	}
	names := make([]string, 0, len(zones[zone]))
	for target := range zones[zone] {
		names = append(names, target)
	}
	sort.Strings(names)
	return zone, names, nil
}

func dnsNameWithinZone(name, zone string) bool {
	name = strings.ToLower(normalizeTraceName(name))
	zone = strings.ToLower(normalizeTraceName(zone))
	if name == "" || zone == "" {
		return false
	}
	if zone == "." {
		return true
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func delegationFromGlue(values []dnswire.ResourceRecord, names []string, zone string) []AuthorityEndpoint {
	byName := make(map[string][]string, len(names))
	for _, value := range values {
		if !value.Address.IsValid() {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(value.Name, "."))
		if !withinBailiwick(key, zone) {
			continue
		}
		byName[key] = append(byName[key], value.Address.Unmap().String())
	}
	out := make([]AuthorityEndpoint, 0, len(names))
	for _, name := range names {
		key := strings.ToLower(strings.TrimSuffix(name, "."))
		addresses := append([]string(nil), byName[key]...)
		sort.Strings(addresses)
		out = append(out, AuthorityEndpoint{Name: name, Addresses: dedupeStrings(addresses)})
	}
	return out
}

func referralZone(values []dnswire.ResourceRecord) string {
	for _, value := range values {
		if value.Type == dnswire.TypeNS && strings.TrimSpace(value.Name) != "" {
			return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value.Name), "."))
		}
	}
	return ""
}

func withinBailiwick(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if name == "" || zone == "" {
		return false
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func delegationAddresses(values []AuthorityEndpoint) []netip.Addr {
	var out []netip.Addr
	for _, value := range values {
		for _, raw := range value.Addresses {
			address, err := netip.ParseAddr(raw)
			if err == nil {
				out = append(out, address.Unmap())
			}
		}
	}
	return uniqueValid(out)
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	var last string
	for i, value := range values {
		if i == 0 || value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func uniqueValid(values []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(values))
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if !value.IsValid() {
			continue
		}
		value = value.Unmap()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}


func normalizeTraceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "." {
		return "."
	}
	return strings.TrimSuffix(value, ".")
}
