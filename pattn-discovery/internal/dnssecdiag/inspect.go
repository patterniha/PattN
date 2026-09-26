package dnssecdiag

import (
	"context"
	"net/netip"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

type Result struct {
	Zone                 string                      `json:"zone"`
	DS                   dnstrace.Result             `json:"ds"`
	DNSKEY               dnstrace.Result             `json:"dnskey"`
	Validation           dnssec.DelegationValidation `json:"validation"`
	DNSKEYSignatures     []dnssec.SignatureValidation `json:"dnskeySignatures,omitempty"`
	DNSKEYAuthenticated  bool                        `json:"dnskeyAuthenticated"`
	AuthenticationStatus string                      `json:"authenticationStatus"`
}

const (
	AuthDNSKEY       = "dnskey-authenticated"
	AuthDelegation   = "delegation-match-only"
	AuthNoDSObserved = "no-ds-observed"
	AuthBogus        = "dnskey-signature-invalid"
	AuthIndeterminate = "indeterminate"
)

func Inspect(ctx context.Context, zone string, opts dnstrace.Options) (Result, error) {
	if opts.Exchange == nil {
		opts.Exchange = dnssecExchange
	}
	dsTrace, err := dnstrace.Trace(ctx, zone, dnswire.TypeDS, opts)
	if err != nil {
		return Result{}, err
	}
	keyTrace, err := dnstrace.Trace(ctx, zone, dnswire.TypeDNSKEY, opts)
	if err != nil {
		return Result{}, err
	}
	delegation := dnssec.ValidateDelegation(zone, dsTrace.WireAnswers, keyTrace.WireAnswers)
	matchedKeys := dnssec.MatchedKeyRecords(delegation, keyTrace.WireAnswers)
	signatures := dnssec.ValidateDNSKEYRRSetWithKeys(zone, keyTrace.WireAnswers, matchedKeys, time.Now())
	authenticated := dnssec.AnyValidSignature(signatures)
	status := AuthIndeterminate
	switch {
	case delegation.Status == dnssec.StatusUnsigned:
		// Bare DS absence is only an observation. RFC 4035 requires an authenticated
		// parent denial proof before the child can be classified as insecure.
		status = AuthNoDSObserved
	case authenticated:
		status = AuthDNSKEY
	case delegation.Status == dnssec.StatusMatch && hasInvalidOrTemporalSignature(signatures):
		status = AuthBogus
	case delegation.Status == dnssec.StatusMatch:
		status = AuthDelegation
	}
	return Result{
		Zone: zone,
		DS: dsTrace,
		DNSKEY: keyTrace,
		Validation: delegation,
		DNSKEYSignatures: signatures,
		DNSKEYAuthenticated: authenticated,
		AuthenticationStatus: status,
	}, nil
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

func trustedSignatureValid(delegation dnssec.DelegationValidation, signatures []dnssec.SignatureValidation) bool {
	for _, match := range delegation.Matches {
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

func hasInvalidOrTemporalSignature(signatures []dnssec.SignatureValidation) bool {
	for _, signature := range signatures {
		switch signature.Status {
		case dnssec.SignatureInvalid, dnssec.SignatureExpired, dnssec.SignatureNotYetValid, dnssec.SignatureNoKey:
			return true
		}
	}
	return false
}
