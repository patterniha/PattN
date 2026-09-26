package dnstruth

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnsauthority"
	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnsrr"
	"pattn-discovery/internal/dnsvalidate"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/resolvercatalog"
	"pattn-discovery/internal/resolverdepth"
	"pattn-discovery/internal/dnswire"
)

type ResolverEndpoint struct {
	Name       string     `json:"name"`
	Address    string     `json:"address"`
	Port       uint16     `json:"port,omitempty"`
	Kind       SourceKind `json:"kind"`
	CatalogID  string     `json:"catalogId,omitempty"`
	Policy     resolvercatalog.PolicyClass `json:"policy,omitempty"`
	ServerName string     `json:"serverName,omitempty"`
	DoTPort    uint16     `json:"dotPort,omitempty"`
	DoHURL     string     `json:"dohUrl,omitempty"`
}

type CompareOptions struct {
	Trace         dnstrace.Options
	Resolvers     []ResolverEndpoint
	Timeout       time.Duration
	Exchange      dnstrace.ExchangeFunc
	CheckDNSSEC   bool
	DNSSECExchange dnstrace.ExchangeFunc
	CheckDepth              bool
	DepthAttempts           int
	DepthMinimumSuccesses   int
}

type ResolverObservation struct {
	Name              string     `json:"name"`
	Address           string     `json:"address"`
	Port              uint16     `json:"port"`
	Kind              SourceKind `json:"kind"`
	CatalogID         string     `json:"catalogId,omitempty"`
	Policy            resolvercatalog.PolicyClass `json:"policy,omitempty"`
	ReferenceEligible bool       `json:"referenceEligible"`
	Transport         string     `json:"transport,omitempty"`
	LatencyMs         float64    `json:"latencyMs,omitempty"`
	RCode             uint8      `json:"rcode,omitempty"`
	Signature         string     `json:"signature,omitempty"`
	Depth             *resolverdepth.Result `json:"depth,omitempty"`
	Error             string                `json:"error,omitempty"`
}

type CandidateAssessment struct {
	Source             string `json:"source"`
	Signature          string `json:"signature,omitempty"`
	AuthorityReference string `json:"authorityReference,omitempty"`
	Status             string `json:"status"`
	DNSSECStatus       string `json:"dnssecStatus,omitempty"`
	Error              string `json:"error,omitempty"`
}

type ComparisonResult struct {
	Domain                       string                       `json:"domain"`
	QueryType                    uint16                       `json:"queryType"`
	Authority                    dnsauthority.Result          `json:"authority"`
	Resolvers                    []ResolverObservation        `json:"resolvers"`
	Consensus                    Consensus                    `json:"consensus"`
	ReferenceConsensus           Consensus                    `json:"referenceConsensus"`
	AuthorityReferenceSignature  string                       `json:"authorityReferenceSignature,omitempty"`
	AuthorityReferenceDefinitive bool                         `json:"authorityReferenceDefinitive"`
	DNSSECReference              *dnsvalidate.Result          `json:"dnssecReference,omitempty"`
	DNSSECReferenceSignature     string                       `json:"dnssecReferenceSignature,omitempty"`
	DNSSECReferenceDefinitive    bool                         `json:"dnssecReferenceDefinitive"`
	Candidates                   []CandidateAssessment        `json:"candidates,omitempty"`
}

const (
	CandidateAgreesAuthority    = "agrees-authority"
	CandidateDiffersAuthority   = "differs-authority"
	CandidateNoAuthorityBaseline = "no-authority-baseline"
	CandidateFailed               = "query-failed"
	CandidateAgreesDNSSEC          = "agrees-dnssec"
	CandidateDiffersDNSSEC         = "differs-dnssec"
	CandidateNoDNSSECBaseline      = "no-dnssec-baseline"
)

func DefaultTrustedResolvers() []ResolverEndpoint {
	var out []ResolverEndpoint
	for _, identity := range resolvercatalog.Builtin() {
		if len(identity.IPv4) == 0 {
			continue
		}
		out = append(out, ResolverEndpoint{
			Name: identity.Name,
			Address: identity.IPv4[0],
			Port: identity.Port,
			Kind: SourceTrusted,
			CatalogID: identity.ID,
			Policy: identity.Policy,
			ServerName: identity.DoTServerName,
			DoTPort: identity.DoTPort,
			DoHURL: identity.DoHURL,
		})
	}
	return out
}

func Compare(ctx context.Context, domain string, qtype uint16, opts CompareOptions) (ComparisonResult, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return ComparisonResult{}, fmt.Errorf("domain is required")
	}
	if qtype == 0 {
		qtype = dnswire.TypeA
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Exchange == nil {
		opts.Exchange = dnsmeasure.QueryWithRecursion
	}
	if opts.Trace.Exchange == nil {
		opts.Trace.Exchange = opts.Exchange
	}

	authority, err := dnsauthority.Compare(ctx, domain, qtype, dnsauthority.Options{Trace: opts.Trace})
	if err != nil {
		return ComparisonResult{}, err
	}
	result := ComparisonResult{
		Domain: domain,
		QueryType: qtype,
		Authority: authority,
		Resolvers: make([]ResolverObservation, 0, len(opts.Resolvers)),
	}
	var evidence []Observation
	var referenceEvidence []Observation
	for _, observation := range authority.Observations {
		source := observation.Authority
		if observation.Address != "" {
			source += "@" + observation.Address
		}
		evidence = append(evidence, Observation{
			Source: source,
			Kind: SourceAuthoritative,
			Signature: observation.Signature,
			Error: observation.Error,
		})
		referenceEvidence = append(referenceEvidence, Observation{
			Source: source,
			Kind: SourceAuthoritative,
			Signature: observation.Signature,
			Error: observation.Error,
		})
	}

	if authority.Responding > 0 && authority.MajorityCount*2 > authority.Responding {
		result.AuthorityReferenceSignature = authority.MajoritySignature
		result.AuthorityReferenceDefinitive = true
	}

	if opts.CheckDNSSEC {
		dnssecTrace := opts.Trace
		dnssecTrace.Exchange = opts.DNSSECExchange
		validation, validateErr := dnsvalidate.Validate(ctx, domain, qtype, dnssecTrace)
		if validateErr == nil {
			result.DNSSECReference = &validation
			if validation.AnswerAuthenticated && validation.TrustScope == "root-anchored" {
				result.DNSSECReferenceSignature = dnsrr.AnswerSignature(validation.RCode, validation.Trace.WireAnswers, qtype)
				result.DNSSECReferenceDefinitive = result.DNSSECReferenceSignature != ""
			}
		}
	}

	for _, endpoint := range opts.Resolvers {
		observation := queryResolver(ctx, domain, qtype, endpoint, opts)
		if opts.CheckDepth {
			address, parseErr := netip.ParseAddr(strings.TrimSpace(strings.Trim(endpoint.Address, "[]")))
			if parseErr == nil {
				depth := resolverdepth.Profile(ctx, resolverdepth.Options{
					Address: address.Unmap(), Port: endpoint.Port, Domain: domain, Timeout: opts.Timeout,
					ServerName: endpoint.ServerName, DoTPort: endpoint.DoTPort, DoHURL: endpoint.DoHURL,
					Attempts: opts.DepthAttempts, MinimumSuccesses: opts.DepthMinimumSuccesses,
					CheckUDP: true, CheckTCP: true, CheckEDNS: true, CheckTXT: true,
					CheckDoT: endpoint.ServerName != "", CheckDoH: endpoint.DoHURL != "",
				})
				observation.Depth = &depth
			}
		}
		result.Resolvers = append(result.Resolvers, observation)
		evidence = append(evidence, Observation{
			Source: observation.Name,
			Kind: observation.Kind,
			Signature: observation.Signature,
			Error: observation.Error,
		})
		if observation.ReferenceEligible {
			referenceEvidence = append(referenceEvidence, Observation{
				Source: observation.Name,
				Kind: observation.Kind,
				Signature: observation.Signature,
				Error: observation.Error,
			})
		}
		if endpoint.Kind == SourceCandidate {
			assessment := CandidateAssessment{
				Source: observation.Name,
				Signature: observation.Signature,
				AuthorityReference: result.AuthorityReferenceSignature,
			}
			switch {
			case observation.Error != "":
				assessment.Status = CandidateFailed
				assessment.Error = observation.Error
			case !result.AuthorityReferenceDefinitive:
				assessment.Status = CandidateNoAuthorityBaseline
			case observation.Signature == result.AuthorityReferenceSignature:
				assessment.Status = CandidateAgreesAuthority
			default:
				assessment.Status = CandidateDiffersAuthority
			}
			switch {
			case observation.Error != "":
				assessment.DNSSECStatus = CandidateFailed
			case !result.DNSSECReferenceDefinitive:
				assessment.DNSSECStatus = CandidateNoDNSSECBaseline
			case observation.Signature == result.DNSSECReferenceSignature:
				assessment.DNSSECStatus = CandidateAgreesDNSSEC
			default:
				assessment.DNSSECStatus = CandidateDiffersDNSSEC
			}
			result.Candidates = append(result.Candidates, assessment)
		}
	}
	result.Consensus = Aggregate(evidence)
	result.ReferenceConsensus = Aggregate(referenceEvidence)
	sort.Slice(result.Resolvers, func(i, j int) bool {
		if result.Resolvers[i].Kind != result.Resolvers[j].Kind {
			return result.Resolvers[i].Kind < result.Resolvers[j].Kind
		}
		return result.Resolvers[i].Name < result.Resolvers[j].Name
	})
	return result, nil
}

func queryResolver(ctx context.Context, domain string, qtype uint16, endpoint ResolverEndpoint, opts CompareOptions) ResolverObservation {
	out := ResolverObservation{
		Name: endpoint.Name, Address: endpoint.Address, Port: endpoint.Port, Kind: endpoint.Kind,
		CatalogID: endpoint.CatalogID, Policy: endpoint.Policy, ReferenceEligible: isReferenceEligible(endpoint),
	}
	if strings.TrimSpace(out.Name) == "" {
		out.Name = endpoint.Address
	}
	if out.Port == 0 {
		out.Port = 53
	}
	address, err := netip.ParseAddr(strings.TrimSpace(strings.Trim(endpoint.Address, "[]")))
	if err != nil {
		out.Error = "invalid resolver address"
		return out
	}
	observation, err := opts.Exchange(ctx, address.Unmap(), out.Port, domain, qtype, dnsmeasure.UDP, opts.Timeout, true)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if observation.Header.TC {
		observation, err = opts.Exchange(ctx, address.Unmap(), out.Port, domain, qtype, dnsmeasure.TCP, opts.Timeout, true)
		if err != nil {
			out.Error = err.Error()
			return out
		}
	}
	out.Transport = string(observation.Transport)
	out.LatencyMs = float64(observation.Latency) / float64(time.Millisecond)
	out.RCode = observation.Header.RCode
	out.Signature = dnsrr.AnswerSignature(observation.Header.RCode, observation.Answers, qtype)
	return out
}


func isReferenceEligible(endpoint ResolverEndpoint) bool {
	if endpoint.Kind != SourceTrusted {
		return false
	}
	return endpoint.Policy != resolvercatalog.PolicySecurityFiltering
}
