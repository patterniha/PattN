package dnschain

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

type Options struct {
	Trace        dnstrace.Options
	TrustAnchors []dnssec.TrustAnchor
}

type Step struct {
	Zone                    string                       `json:"zone"`
	Parent                  string                       `json:"parent,omitempty"`
	DS                      *dnstrace.Result             `json:"ds,omitempty"`
	DNSKEY                  dnstrace.Result              `json:"dnskey"`
	DSValidation            *dnssec.DelegationValidation `json:"dsValidation,omitempty"`
	DSSignatures            []dnssec.SignatureValidation `json:"dsSignatures,omitempty"`
	DSAbsenceProof          *dnssec.DenialProof          `json:"dsAbsenceProof,omitempty"`
	DNSKEYSignatures        []dnssec.SignatureValidation `json:"dnskeySignatures,omitempty"`
	DelegationAuthenticated bool                         `json:"delegationAuthenticated"`
	InsecureDelegation      bool                         `json:"insecureDelegation"`
	Authenticated           bool                         `json:"authenticated"`
	Status                  string                       `json:"status"`
	TrustedKeyCount         int                          `json:"trustedKeyCount"`
	TrustedKeys             []dnswire.ResourceRecord     `json:"-"`
}

type Result struct {
	TargetZone          string                   `json:"targetZone"`
	TrustAnchors        []dnssec.TrustAnchor     `json:"trustAnchors"`
	Steps               []Step                   `json:"steps"`
	RootAuthenticated   bool                     `json:"rootAuthenticated"`
	ChainAuthenticated  bool                     `json:"chainAuthenticated"`
	InsecureDelegation  bool                     `json:"insecureDelegation"`
	AuthenticatedZone   string                   `json:"authenticatedZone,omitempty"`
	InsecureZone        string                   `json:"insecureZone,omitempty"`
	Status              string                   `json:"status"`
	ErrorCode           string                   `json:"errorCode,omitempty"`
	Error               string                   `json:"error,omitempty"`
	TrustedKeys         []dnswire.ResourceRecord `json:"-"`
}

const (
	StatusAuthenticated       = "root-anchored"
	StatusInsecureDelegation  = "root-anchored-insecure-delegation"
	StatusRootFailure         = "root-anchor-failure"
	StatusDSFailure           = "ds-rrset-unverified"
	StatusDelegation          = "delegation-mismatch"
	StatusDNSKEYFailure       = "dnskey-rrset-unverified"
	StatusIndeterminate       = "indeterminate"
)

func Validate(ctx context.Context, targetZone string, opts Options) (Result, error) {
	targetZone = normalizeZone(targetZone)
	if targetZone == "" {
		return Result{}, fmt.Errorf("target zone is required")
	}
	if opts.Trace.Exchange == nil {
		opts.Trace.Exchange = dnssecExchange
	}
	anchors := opts.TrustAnchors
	if len(anchors) == 0 {
		anchors = dnssec.IANARootTrustAnchors()
	}
	result := Result{
		TargetZone: targetZone,
		TrustAnchors: append([]dnssec.TrustAnchor(nil), anchors...),
		Status: StatusIndeterminate,
	}

	rootStep, err := authenticateRoot(ctx, opts.Trace, anchors)
	if err != nil {
		return Result{}, err
	}
	result.Steps = append(result.Steps, rootStep)
	result.RootAuthenticated = rootStep.Authenticated
	if !rootStep.Authenticated {
		result.Status = StatusRootFailure
		result.ErrorCode = rootStep.Status
		return result, nil
	}
	parentKeys := rootStep.TrustedKeys
	parentZone := "."
	result.AuthenticatedZone = "."

	for _, zone := range zonePath(targetZone) {
		step, err := authenticateChild(ctx, parentZone, zone, parentKeys, opts.Trace)
		if err != nil {
			return Result{}, err
		}
		result.Steps = append(result.Steps, step)
		if step.InsecureDelegation {
			// The parent-authenticated denial proves that the child intentionally
			// has no DS. That is a secure classification of an insecure boundary,
			// not a bogus chain and not permission to trust child data.
			result.InsecureDelegation = true
			result.InsecureZone = zone
			result.Status = StatusInsecureDelegation
			result.AuthenticatedZone = parentZone
			return result, nil
		}
		if !step.Authenticated {
			result.Status = step.Status
			result.ErrorCode = step.Status
			return result, nil
		}
		parentKeys = step.TrustedKeys
		parentZone = zone
		result.AuthenticatedZone = zone
	}

	result.ChainAuthenticated = true
	result.Status = StatusAuthenticated
	result.TrustedKeys = append([]dnswire.ResourceRecord(nil), parentKeys...)
	return result, nil
}

func authenticateRoot(ctx context.Context, traceOpts dnstrace.Options, anchors []dnssec.TrustAnchor) (Step, error) {
	keyTrace, err := dnstrace.Trace(ctx, ".", dnswire.TypeDNSKEY, traceOpts)
	if err != nil {
		return Step{}, err
	}
	anchorRecords := dnssec.TrustAnchorRecords(anchors)
	delegation := dnssec.ValidateDelegation(".", anchorRecords, keyTrace.WireAnswers)
	matchedKeys := dnssec.MatchedKeyRecords(delegation, keyTrace.WireAnswers)
	signatures := dnssec.ValidateDNSKEYRRSetWithKeys(".", keyTrace.WireAnswers, matchedKeys, time.Now())
	authenticated := dnssec.AnyValidSignature(signatures)
	keys := []dnswire.ResourceRecord(nil)
	if authenticated {
		keys = dnssec.AuthenticatedDNSKEYRecords(keyTrace.WireAnswers)
	}
	status := StatusRootFailure
	if authenticated {
		status = StatusAuthenticated
	}
	return Step{
		Zone: ".", DNSKEY: keyTrace, DSValidation: &delegation,
		DNSKEYSignatures: signatures, Authenticated: authenticated,
		Status: status, TrustedKeyCount: len(keys), TrustedKeys: keys,
	}, nil
}

func authenticateChild(
	ctx context.Context,
	parentZone, zone string,
	parentKeys []dnswire.ResourceRecord,
	traceOpts dnstrace.Options,
) (Step, error) {
	dsTrace, err := dnstrace.Trace(ctx, zone, dnswire.TypeDS, traceOpts)
	if err != nil {
		return Step{}, err
	}
	step := Step{Zone: zone, Parent: parentZone, DS: &dsTrace, Status: StatusIndeterminate}
	if !hasType(dsTrace.WireAnswers, dnswire.TypeDS) {
		if proof := authenticatedDSAbsenceProof(zone, dsTrace, parentKeys); proof != nil {
			step.DSAbsenceProof = proof
			step.DelegationAuthenticated = true
			step.InsecureDelegation = true
			step.Status = StatusInsecureDelegation
			return step, nil
		}
		step.Status = StatusDSFailure
		return step, nil
	}
	dsSignatures := dnssec.ValidateRRSet(zone, dnswire.TypeDS, dsTrace.WireAnswers, parentKeys, time.Now())
	step.DSSignatures = dsSignatures
	if !dnssec.AnyValidSignature(dsSignatures) {
		step.Status = StatusDSFailure
		return step, nil
	}
	step.DelegationAuthenticated = true

	keyTrace, err := dnstrace.Trace(ctx, zone, dnswire.TypeDNSKEY, traceOpts)
	if err != nil {
		return Step{}, err
	}
	step.DNSKEY = keyTrace
	delegation := dnssec.ValidateDelegation(zone, dsTrace.WireAnswers, keyTrace.WireAnswers)
	step.DSValidation = &delegation
	if delegation.Status != dnssec.StatusMatch {
		step.Status = StatusDelegation
		return step, nil
	}
	matchedKeys := dnssec.MatchedKeyRecords(delegation, keyTrace.WireAnswers)
	keySignatures := dnssec.ValidateDNSKEYRRSetWithKeys(zone, keyTrace.WireAnswers, matchedKeys, time.Now())
	step.DNSKEYSignatures = keySignatures
	if !dnssec.AnyValidSignature(keySignatures) {
		step.Status = StatusDNSKEYFailure
		return step, nil
	}
	keys := dnssec.AuthenticatedDNSKEYRecords(keyTrace.WireAnswers)
	step.Authenticated = true
	step.Status = StatusAuthenticated
	step.TrustedKeys = keys
	step.TrustedKeyCount = len(keys)
	return step, nil
}

func authenticatedDSAbsenceProof(
	zone string,
	dsTrace dnstrace.Result,
	parentKeys []dnswire.ResourceRecord,
) *dnssec.DenialProof {
	if len(parentKeys) == 0 || len(dsTrace.WireAuthorities) == 0 {
		return nil
	}

	var nsecs []dnssec.NSEC
	var nsec3s []dnssec.NSEC3
	seenNSEC := make(map[string]struct{})
	seenNSEC3 := make(map[string]struct{})
	for _, record := range dsTrace.WireAuthorities {
		switch record.Type {
		case dnswire.TypeNSEC:
			owner := normalizeZone(record.Name)
			if _, seen := seenNSEC[owner]; seen {
				continue
			}
			signatures := dnssec.ValidateRRSet(record.Name, dnswire.TypeNSEC, dsTrace.WireAuthorities, parentKeys, time.Now())
			if !dnssec.AnyValidSignature(signatures) {
				continue
			}
			value, err := dnssec.ParseNSEC(record)
			if err != nil {
				continue
			}
			seenNSEC[owner] = struct{}{}
			nsecs = append(nsecs, value)
		case dnswire.TypeNSEC3:
			owner := normalizeZone(record.Name)
			if _, seen := seenNSEC3[owner]; seen {
				continue
			}
			signatures := dnssec.ValidateRRSet(record.Name, dnswire.TypeNSEC3, dsTrace.WireAuthorities, parentKeys, time.Now())
			if !dnssec.AnyValidSignature(signatures) {
				continue
			}
			value, err := dnssec.ParseNSEC3(record)
			if err != nil {
				continue
			}
			seenNSEC3[owner] = struct{}{}
			nsec3s = append(nsec3s, value)
		}
	}

	if len(nsecs) > 0 {
		proof := dnssec.ComposeNSECProof(zone, dnswire.TypeDS, dsTrace.TerminalRCode, nsecs)
		if proof.Complete && proof.InsecureDelegation && proof.Status == dnssec.ProofInsecureDelegation {
			return &proof
		}
	}
	if len(nsec3s) > 0 {
		proof := dnssec.ComposeNSEC3Proof(zone, dnswire.TypeDS, dsTrace.TerminalRCode, nsec3s)
		if proof.Complete && proof.InsecureDelegation && proof.Status == dnssec.ProofInsecureDelegation {
			return &proof
		}
	}
	return nil
}

func signatureByMatchedKey(validation dnssec.DelegationValidation, signatures []dnssec.SignatureValidation) bool {
	for _, match := range validation.Matches {
		for _, signature := range signatures {
			if signature.Status == dnssec.SignatureValid &&
				signature.KeyTag == match.DNSKEY.KeyTag &&
				signature.Algorithm == match.DNSKEY.Algorithm {
				return true
			}
		}
	}
	return false
}

func zonePath(zone string) []string {
	zone = normalizeZone(zone)
	if zone == "." {
		return nil
	}
	labels := strings.Split(zone, ".")
	out := make([]string, 0, len(labels))
	for i := len(labels) - 1; i >= 0; i-- {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

func normalizeZone(value string) string {
	value = strings.TrimSpace(value)
	if value == "." {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

func hasType(records []dnswire.ResourceRecord, rrType uint16) bool {
	for _, record := range records {
		if record.Type == rrType {
			return true
		}
	}
	return false
}

func dnssecExchange(
	ctx context.Context,
	address netip.Addr,
	port uint16,
	domain string,
	qtype uint16,
	transport dnsmeasure.Transport,
	timeout time.Duration,
	recursionDesired bool,
) (dnsmeasure.Observation, error) {
	return dnsmeasure.QueryAdvanced(ctx, address, port, domain, qtype, transport, timeout, dnsmeasure.QueryOptions{
		RecursionDesired: recursionDesired,
		EDNS: true,
		UDPSize: 1232,
		DNSSECOK: true,
	})
}
