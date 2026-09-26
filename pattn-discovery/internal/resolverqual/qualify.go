package resolverqual

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnswire"
	"pattn-discovery/internal/resolverdepth"
)

type Options struct {
	Address          netip.Addr
	Port             uint16
	Domain           string
	Timeout          time.Duration
	ReferenceAnswers              []netip.Addr
	AuthenticatedReferenceAnswers []netip.Addr
	AuthenticatedReferenceStatus  string
	CheckUDP                      bool
	CheckTCP         bool
	CheckHijack      bool
}

type TransportEvidence struct {
	Transport          dnsmeasure.Transport `json:"transport"`
	Responded          bool                 `json:"responded"`
	LatencyMs          float64              `json:"latencyMs,omitempty"`
	RCode              uint8                `json:"rcode,omitempty"`
	RecursionAvailable bool                 `json:"recursionAvailable"`
	Authoritative      bool                 `json:"authoritative"`
	Truncated          bool                 `json:"truncated"`
	AnswerIPs          []string             `json:"answerIps,omitempty"`
	Error              string               `json:"error,omitempty"`
}

type Result struct {
	Address               string             `json:"address"`
	Port                  uint16             `json:"port"`
	Domain                string             `json:"domain"`
	UDP                   *TransportEvidence `json:"udp,omitempty"`
	TCP                   *TransportEvidence `json:"tcp,omitempty"`
	Responded             bool               `json:"responded"`
	RecursionAvailable    bool               `json:"recursionAvailable"`
	PreferredTransport    string             `json:"preferredTransport,omitempty"`
	TransportAgreement    *bool              `json:"transportAgreement,omitempty"`
	PrivateAnswerObserved bool               `json:"privateAnswerObserved"`
	ReferenceCompared             bool               `json:"referenceCompared"`
	ReferenceDivergence           bool               `json:"referenceDivergence"`
	DNSSECReferenceCompared       bool               `json:"dnssecReferenceCompared"`
	DNSSECReferenceDivergence     bool               `json:"dnssecReferenceDivergence"`
	DNSSECReferenceStatus         string             `json:"dnssecReferenceStatus,omitempty"`
	HijackChecked         bool               `json:"hijackChecked"`
	HijackDetected        bool               `json:"hijackDetected"`
	HijackEvidence        *TransportEvidence `json:"hijackEvidence,omitempty"`
	Depth                 *resolverdepth.Result `json:"depth,omitempty"`
	Status                string                `json:"status"`
}

const (
	StatusUsable    = "usable"
	StatusHijack    = "hijack"
	StatusDivergent       = "divergent"
	StatusDNSSECDivergent = "dnssec-divergent"
	StatusInvalid         = "invalid"
)

func Qualify(ctx context.Context, opts Options) Result {
	if opts.Port == 0 {
		opts.Port = 53
	}
	if strings.TrimSpace(opts.Domain) == "" {
		opts.Domain = "example.com"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if !opts.CheckUDP && !opts.CheckTCP {
		opts.CheckUDP, opts.CheckTCP = true, true
	}

	result := Result{
		Address: opts.Address.String(), Port: opts.Port, Domain: opts.Domain, Status: StatusInvalid,
		DNSSECReferenceStatus: opts.AuthenticatedReferenceStatus,
	}
	if opts.CheckUDP {
		ev := observe(ctx, opts.Address, opts.Port, opts.Domain, dnsmeasure.UDP, opts.Timeout)
		result.UDP = &ev
	}
	if opts.CheckTCP {
		ev := observe(ctx, opts.Address, opts.Port, opts.Domain, dnsmeasure.TCP, opts.Timeout)
		result.TCP = &ev
	}

	evidence := available(result.UDP, result.TCP)
	result.Responded = len(evidence) > 0
	for _, ev := range evidence {
		result.RecursionAvailable = result.RecursionAvailable || ev.RecursionAvailable
		result.PrivateAnswerObserved = result.PrivateAnswerObserved || containsNonGlobal(ev.AnswerIPs)
	}
	result.PreferredTransport = fastest(result.UDP, result.TCP)
	if result.UDP != nil && result.UDP.Responded && result.TCP != nil && result.TCP.Responded {
		agree := sameStrings(result.UDP.AnswerIPs, result.TCP.AnswerIPs) && result.UDP.RCode == result.TCP.RCode
		result.TransportAgreement = &agree
	}

	dnssecRefs := normalizeReference(opts.AuthenticatedReferenceAnswers)
	if len(dnssecRefs) > 0 {
		result.DNSSECReferenceCompared = true
		result.DNSSECReferenceStatus = opts.AuthenticatedReferenceStatus
		if best := bestAnswerEvidence(result.UDP, result.TCP); best != nil && best.RCode == 0 {
			result.DNSSECReferenceDivergence = !sameSet(best.AnswerIPs, dnssecRefs)
		}
	}

	refs := normalizeReference(opts.ReferenceAnswers)
	if len(refs) > 0 {
		result.ReferenceCompared = true
		if best := bestAnswerEvidence(result.UDP, result.TCP); best != nil && best.RCode == 0 {
			result.ReferenceDivergence = !intersects(best.AnswerIPs, refs)
		}
	}

	if opts.CheckHijack {
		result.HijackChecked = true
		invalidName := randomInvalidName()
		transport := dnsmeasure.UDP
		if result.PreferredTransport == string(dnsmeasure.TCP) {
			transport = dnsmeasure.TCP
		}
		ev := observe(ctx, opts.Address, opts.Port, invalidName, transport, opts.Timeout)
		result.HijackEvidence = &ev
		result.HijackDetected = isPositiveInvalidNameAnswer(ev)
	}

	switch {
	case !result.Responded || !result.RecursionAvailable:
		result.Status = StatusInvalid
	case result.HijackDetected:
		result.Status = StatusHijack
	case result.DNSSECReferenceCompared && result.DNSSECReferenceDivergence:
		result.Status = StatusDNSSECDivergent
	case result.PrivateAnswerObserved || (result.ReferenceCompared && result.ReferenceDivergence):
		result.Status = StatusDivergent
	default:
		result.Status = StatusUsable
	}
	return result
}

func observe(ctx context.Context, address netip.Addr, port uint16, domain string, transport dnsmeasure.Transport, timeout time.Duration) TransportEvidence {
	observation, err := dnsmeasure.Query(ctx, address, port, domain, dnswire.TypeA, transport, timeout)
	if err != nil {
		return TransportEvidence{Transport: transport, Error: err.Error()}
	}
	answers := make([]string, 0, len(observation.AnswerIPs))
	for _, answer := range observation.AnswerIPs {
		answers = append(answers, answer.String())
	}
	sort.Strings(answers)
	return TransportEvidence{
		Transport: transport, Responded: true,
		LatencyMs: float64(observation.Latency) / float64(time.Millisecond),
		RCode:     observation.Header.RCode, RecursionAvailable: observation.Header.RA,
		Authoritative: observation.Header.AA, Truncated: observation.Header.TC, AnswerIPs: answers,
	}
}

func isPositiveInvalidNameAnswer(value TransportEvidence) bool {
	// Any synthesized address for the reserved .invalid namespace is injection
	// evidence, even when the response header simultaneously claims NXDOMAIN or
	// another error RCODE. Empty error responses remain non-hijack evidence.
	return value.Responded && len(value.AnswerIPs) > 0
}

func available(values ...*TransportEvidence) []*TransportEvidence {
	out := make([]*TransportEvidence, 0, len(values))
	for _, value := range values {
		if value != nil && value.Responded {
			out = append(out, value)
		}
	}
	return out
}

func fastest(values ...*TransportEvidence) string {
	var best *TransportEvidence
	for _, value := range values {
		if value == nil || !value.Responded {
			continue
		}
		if best == nil || value.LatencyMs < best.LatencyMs {
			best = value
		}
	}
	if best == nil {
		return ""
	}
	return string(best.Transport)
}

func bestAnswerEvidence(values ...*TransportEvidence) *TransportEvidence {
	for _, value := range values {
		if value != nil && value.Responded && value.RCode == 0 && len(value.AnswerIPs) > 0 {
			return value
		}
	}
	return nil
}

func containsNonGlobal(values []string) bool {
	for _, value := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !isPublicUnicast(address.Unmap()) {
			return true
		}
	}
	return false
}

func isPublicUnicast(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || address.IsPrivate() {
		return false
	}
	if address.Is4() {
		b := address.As4()
		if b[0] == 0 || b[0] >= 240 {
			return false
		}
	}
	return true
}

func normalizeReference(values []netip.Addr) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !value.IsValid() {
			continue
		}
		text := value.Unmap().String()
		if _, ok := seen[text]; ok {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

func intersects(values, refs []string) bool {
	refSet := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		refSet[ref] = struct{}{}
	}
	for _, value := range values {
		if _, ok := refSet[value]; ok {
			return true
		}
	}
	return false
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func randomInvalidName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pattn-%d.invalid", time.Now().UnixNano())
	}
	return "pattn-" + hex.EncodeToString(b[:]) + ".invalid"
}


func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	return sameStrings(left, right)
}
