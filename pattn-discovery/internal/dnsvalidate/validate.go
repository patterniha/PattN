package dnsvalidate

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"pattn-discovery/internal/dnschain"
	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnssecdiag"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

type DenialValidation struct {
	Evidence      dnssec.DenialEvidence        `json:"evidence"`
	Signatures    []dnssec.SignatureValidation `json:"signatures,omitempty"`
	Authenticated bool                         `json:"authenticated"`
}

type AliasValidation struct {
	Step          dnstrace.AliasStep            `json:"step"`
	SignerZone    string                        `json:"signerZone,omitempty"`
	Chain         *dnschain.Result              `json:"chain,omitempty"`
	Signatures    []dnssec.SignatureValidation  `json:"signatures,omitempty"`
	Authenticated bool                          `json:"authenticated"`
	Status        string                        `json:"status"`
}

type Result struct {
	ValidatedAt        string                       `json:"validatedAt"`
	Domain             string                       `json:"domain"`
	QueryType          uint16                       `json:"queryType"`
	RCode              uint8                        `json:"rcode"`
	Trace              dnstrace.Result              `json:"trace"`
	SignerZone         string                       `json:"signerZone,omitempty"`
	SignerInspection   *dnssecdiag.Result           `json:"signerInspection,omitempty"`
	Chain              *dnschain.Result             `json:"chain,omitempty"`
	RRSetSignatures       []dnssec.SignatureValidation `json:"rrsetSignatures,omitempty"`
	AliasValidations      []AliasValidation             `json:"aliasValidations,omitempty"`
	AliasChainAuthenticated bool                        `json:"aliasChainAuthenticated"`
	Denial                []DenialValidation            `json:"denial,omitempty"`
	DenialProof           *dnssec.DenialProof           `json:"denialProof,omitempty"`
	AnswerAuthenticated   bool                          `json:"answerAuthenticated"`
	DenialAuthenticated   bool                          `json:"denialAuthenticated"`
	TrustScope         string                       `json:"trustScope"`
	Status             string                       `json:"status"`
}

const (
	StatusAuthenticatedAnswer = "root-anchored-authenticated-answer"
	StatusAuthenticatedDenial = "root-anchored-authenticated-denial-evidence"
	StatusUnsigned            = "unsigned"
	StatusBogusAnswer         = "bogus-answer"
	StatusBogusDenial         = "bogus-denial"
	StatusIndeterminate       = "indeterminate"

	AliasStatusAuthenticated = "root-anchored-authenticated-alias"
	AliasStatusUnsigned      = "unsigned-alias"
	AliasStatusBogus         = "bogus-alias"
	AliasStatusInsecure      = "insecure-alias"
	AliasStatusIndeterminate = "indeterminate-alias"
)

func Validate(ctx context.Context, domain string, qtype uint16, opts dnstrace.Options) (Result, error) {
	return ValidateAt(ctx, domain, qtype, opts, time.Now())
}

func ValidateAt(ctx context.Context, domain string, qtype uint16, opts dnstrace.Options, validationTime time.Time) (Result, error) {
	if validationTime.IsZero() {
		validationTime = time.Now()
	}
	validationTime = validationTime.UTC()
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if qtype == 0 {
		qtype = dnswire.TypeA
	}
	if opts.Exchange == nil {
		opts.Exchange = dnssecExchange
	}
	trace, err := dnstrace.Trace(ctx, domain, qtype, opts)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		ValidatedAt: validationTime.Format(time.RFC3339),
		Domain: domain,
		QueryType: qtype,
		RCode: trace.TerminalRCode,
		Trace: trace,
		TrustScope: "unanchored",
		Status: StatusIndeterminate,
	}

	aliasValidations, aliasChainAuthenticated, aliasBogus, err := validateAliasChain(ctx, trace, opts, validationTime)
	if err != nil {
		return Result{}, err
	}
	result.AliasValidations = aliasValidations
	result.AliasChainAuthenticated = aliasChainAuthenticated

	terminalName := terminalQueryName(trace, domain)
	terminalHasAnswer := hasRRTypeForOwner(trace.WireAnswers, terminalName, qtype)
	signer := findSigner(trace.WireAnswers, trace.WireAuthorities, terminalName, qtype)
	if signer == "" {
		return result, nil
	}
	result.SignerZone = signer
	if strings.TrimSpace(trace.TerminalZone) == "" {
		return result, nil
	}
	if !signerMatchesAuthoritativeZone(signer, trace.TerminalZone) {
		if terminalHasAnswer {
			result.Status = StatusBogusAnswer
		} else {
			result.Status = StatusBogusDenial
		}
		return result, nil
	}
	inspection, err := dnssecdiag.Inspect(ctx, signer, opts)
	if err != nil {
		return Result{}, err
	}
	result.SignerInspection = &inspection
	chain, err := dnschain.Validate(ctx, signer, dnschain.Options{Trace: opts})
	if err != nil {
		return Result{}, err
	}
	result.Chain = &chain
	if !chain.ChainAuthenticated {
		return result, nil
	}
	result.TrustScope = "root-anchored"
	trustedKeys := append([]dnswire.ResourceRecord(nil), chain.TrustedKeys...)
	if len(trustedKeys) == 0 {
		return result, nil
	}

	if terminalHasAnswer {
		result.RRSetSignatures = dnssec.ValidateRRSet(terminalName, qtype, trace.WireAnswers, trustedKeys, validationTime)
		terminalAuthenticated := dnssec.AnyValidSignature(result.RRSetSignatures)
		result.AnswerAuthenticated = terminalAuthenticated && aliasChainAuthenticated
		if result.AnswerAuthenticated {
			result.Status = StatusAuthenticatedAnswer
		} else if aliasBogus || (!terminalAuthenticated && hasDefinitivelyInvalidSignatures(result.RRSetSignatures)) {
			result.Status = StatusBogusAnswer
		}
		return result, nil
	}

	result.Denial = validateDenial(terminalName, qtype, trace.WireAuthorities, trustedKeys, validationTime)
	proof := composeAuthenticatedDenialProof(terminalName, qtype, trace.TerminalRCode, trace.WireAuthorities, result.Denial)
	result.DenialProof = proof
	if proof != nil && proof.Complete &&
		(proof.Status == dnssec.ProofNXDOMAIN || proof.Status == dnssec.ProofNODATA || proof.Status == dnssec.ProofInsecureDelegation) {
		result.DenialAuthenticated = true
	}
	result.DenialAuthenticated = result.DenialAuthenticated && aliasChainAuthenticated
	if result.DenialAuthenticated {
		result.Status = StatusAuthenticatedDenial
	} else if aliasBogus || hasDefinitivelyInvalidDenial(result.Denial) {
		result.Status = StatusBogusDenial
	}
	return result, nil
}

func validateAliasChain(
	ctx context.Context,
	trace dnstrace.Result,
	opts dnstrace.Options,
	validationTime time.Time,
) ([]AliasValidation, bool, bool, error) {
	if len(trace.AliasChain) == 0 {
		return nil, true, false, nil
	}

	out := make([]AliasValidation, 0, len(trace.AliasChain))
	allAuthenticated := true
	bogus := false
	for _, step := range trace.AliasChain {
		item := AliasValidation{Step: step, Status: AliasStatusUnsigned}
		signer := findSigner(trace.WireAnswers, nil, step.Owner, step.Type)
		if signer == "" {
			allAuthenticated = false
			out = append(out, item)
			continue
		}
		item.SignerZone = signer
		if strings.TrimSpace(step.AuthoritativeZone) == "" {
			allAuthenticated = false
			item.Status = AliasStatusIndeterminate
			out = append(out, item)
			continue
		}
		if !signerMatchesAuthoritativeZone(signer, step.AuthoritativeZone) {
			allAuthenticated = false
			bogus = true
			item.Status = AliasStatusBogus
			out = append(out, item)
			continue
		}

		chain, err := dnschain.Validate(ctx, signer, dnschain.Options{Trace: opts})
		if err != nil {
			return nil, false, false, err
		}
		item.Chain = &chain
		if !chain.ChainAuthenticated {
			allAuthenticated = false
			if chain.InsecureDelegation {
				item.Status = AliasStatusInsecure
			} else {
				item.Status = AliasStatusIndeterminate
			}
			out = append(out, item)
			continue
		}

		item.Signatures = dnssec.ValidateRRSet(
			step.Owner,
			step.Type,
			trace.WireAnswers,
			chain.TrustedKeys,
			validationTime,
		)
		item.Authenticated = dnssec.AnyValidSignature(item.Signatures)
		if item.Authenticated {
			item.Status = AliasStatusAuthenticated
		} else {
			allAuthenticated = false
			if hasDefinitivelyInvalidSignatures(item.Signatures) {
				item.Status = AliasStatusBogus
				bogus = true
			} else {
				item.Status = AliasStatusIndeterminate
			}
		}
		out = append(out, item)
	}
	return out, allAuthenticated, bogus, nil
}

func validateDenial(domain string, qtype uint16, records, trustedKeys []dnswire.ResourceRecord, validationTime time.Time) []DenialValidation {
	var out []DenialValidation
	for _, record := range records {
		switch record.Type {
		case dnswire.TypeNSEC:
			value, err := dnssec.ParseNSEC(record)
			if err != nil {
				continue
			}
			signatures := dnssec.ValidateRRSet(record.Name, dnswire.TypeNSEC, records, trustedKeys, validationTime)
			out = append(out, DenialValidation{
				Evidence: dnssec.EvaluateNSEC(domain, qtype, value),
				Signatures: signatures,
				Authenticated: dnssec.AnyValidSignature(signatures),
			})
		case dnswire.TypeNSEC3:
			value, err := dnssec.ParseNSEC3(record)
			if err != nil {
				continue
			}
			signatures := dnssec.ValidateRRSet(record.Name, dnswire.TypeNSEC3, records, trustedKeys, validationTime)
			out = append(out, DenialValidation{
				Evidence: dnssec.EvaluateNSEC3(domain, qtype, value),
				Signatures: signatures,
				Authenticated: dnssec.AnyValidSignature(signatures),
			})
		}
	}
	return out
}

func findSigner(answer, authority []dnswire.ResourceRecord, owner string, qtype uint16) string {
	answerSigners := signerSet(answer, func(record dnswire.ResourceRecord, sig dnssec.RRSIG) bool {
		return sameDNSName(record.Name, owner) && sig.TypeCovered == qtype
	})
	if signer := onlySigner(answerSigners); signer != "" || len(answerSigners) > 1 {
		return signer
	}

	denialSigners := signerSet(authority, func(_ dnswire.ResourceRecord, sig dnssec.RRSIG) bool {
		return sig.TypeCovered == dnswire.TypeNSEC || sig.TypeCovered == dnswire.TypeNSEC3
	})
	return onlySigner(denialSigners)
}

func signerSet(records []dnswire.ResourceRecord, include func(dnswire.ResourceRecord, dnssec.RRSIG) bool) map[string]struct{} {
	set := map[string]struct{}{}
	for _, record := range records {
		if record.Type != dnswire.TypeRRSIG {
			continue
		}
		sig, err := dnssec.ParseRRSIG(record)
		if err != nil || !include(record, sig) || sig.SignerName == "" {
			continue
		}
		set[sig.SignerName] = struct{}{}
	}
	return set
}

func onlySigner(set map[string]struct{}) string {
	if len(set) != 1 {
		return ""
	}
	for value := range set {
		return value
	}
	return ""
}

func terminalQueryName(trace dnstrace.Result, fallback string) string {
	if len(trace.FinalAnswers) > 0 && strings.TrimSpace(trace.FinalAnswers[0].Name) != "" {
		return normalizeDNSName(trace.FinalAnswers[0].Name)
	}
	if len(trace.Hops) > 0 {
		if name := strings.TrimSpace(trace.Hops[len(trace.Hops)-1].QueryName); name != "" {
			return normalizeDNSName(name)
		}
	}
	return normalizeDNSName(fallback)
}

func hasRRTypeForOwner(records []dnswire.ResourceRecord, owner string, rrType uint16) bool {
	for _, record := range records {
		if record.Type == rrType && sameDNSName(record.Name, owner) {
			return true
		}
	}
	return false
}

func sameDNSName(left, right string) bool {
	return strings.EqualFold(normalizeDNSName(left), normalizeDNSName(right))
}

func signerMatchesAuthoritativeZone(signer, authoritativeZone string) bool {
	signer = normalizeDNSName(signer)
	authoritativeZone = normalizeDNSName(authoritativeZone)
	if signer == "" || authoritativeZone == "" {
		return false
	}
	return signer == authoritativeZone
}

func normalizeDNSName(value string) string {
	value = strings.TrimSpace(value)
	if value == "." {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
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


func hasDefinitivelyInvalidSignatures(values []dnssec.SignatureValidation) bool {
	for _, signature := range values {
		switch signature.Status {
		case dnssec.SignatureInvalid, dnssec.SignatureExpired, dnssec.SignatureNotYetValid, dnssec.SignatureNoKey:
			return true
		}
	}
	return false
}

func hasDefinitivelyInvalidDenial(values []DenialValidation) bool {
	for _, value := range values {
		for _, signature := range value.Signatures {
			switch signature.Status {
			case dnssec.SignatureInvalid, dnssec.SignatureExpired, dnssec.SignatureNotYetValid, dnssec.SignatureNoKey:
				return true
			}
		}
	}
	return false
}


func composeAuthenticatedDenialProof(domain string, qtype uint16, rcode uint8, records []dnswire.ResourceRecord, validations []DenialValidation) *dnssec.DenialProof {
	authenticated := make(map[string]bool)
	for _, validation := range validations {
		if validation.Authenticated {
			authenticated[validation.Evidence.Mechanism+"|"+validation.Evidence.Owner] = true
		}
	}
	var nsecs []dnssec.NSEC
	var nsec3s []dnssec.NSEC3
	for _, record := range records {
		switch record.Type {
		case dnswire.TypeNSEC:
			value, err := dnssec.ParseNSEC(record)
			if err == nil && authenticated["nsec|"+value.Owner] {
				nsecs = append(nsecs, value)
			}
		case dnswire.TypeNSEC3:
			value, err := dnssec.ParseNSEC3(record)
			if err == nil && authenticated["nsec3|"+value.OwnerHash] {
				nsec3s = append(nsec3s, value)
			}
		}
	}
	if len(nsecs) > 0 {
		proof := dnssec.ComposeNSECProof(domain, qtype, rcode, nsecs)
		return &proof
	}
	if len(nsec3s) > 0 {
		proof := dnssec.ComposeNSEC3Proof(domain, qtype, rcode, nsec3s)
		return &proof
	}
	return nil
}
