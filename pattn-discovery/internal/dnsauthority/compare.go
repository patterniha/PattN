package dnsauthority

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnsrr"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

type Options struct {
	Trace dnstrace.Options
}

type Record struct {
	Name    string `json:"name"`
	Type    uint16 `json:"type"`
	TTL     uint32 `json:"ttl"`
	Address string `json:"address,omitempty"`
	Target  string `json:"target,omitempty"`
}

type Observation struct {
	Authority     string               `json:"authority"`
	Address       string               `json:"address"`
	Transport     dnsmeasure.Transport `json:"transport,omitempty"`
	LatencyMs     float64              `json:"latencyMs,omitempty"`
	RCode         uint8                `json:"rcode,omitempty"`
	Authoritative bool                 `json:"authoritative"`
	Truncated     bool                 `json:"truncated"`
	Signature     string               `json:"signature,omitempty"`
	Answers       []Record             `json:"answers,omitempty"`
	Error         string               `json:"error,omitempty"`
}

type AgreementGroup struct {
	Signature string   `json:"signature"`
	Count     int      `json:"count"`
	Endpoints []string `json:"endpoints"`
}

type Result struct {
	Domain            string                      `json:"domain"`
	QueryType         uint16                      `json:"queryType"`
	Delegation        []dnstrace.AuthorityEndpoint `json:"delegation,omitempty"`
	Observations      []Observation               `json:"observations"`
	Groups            []AgreementGroup            `json:"groups,omitempty"`
	Responding        int                         `json:"responding"`
	Unanimous         bool                        `json:"unanimous"`
	Divergent         bool                        `json:"divergent"`
	MajorityCount     int                         `json:"majorityCount,omitempty"`
	MajoritySignature string                      `json:"majoritySignature,omitempty"`
	ErrorCode         string                      `json:"errorCode,omitempty"`
	Error             string                      `json:"error,omitempty"`
}

func Compare(ctx context.Context, domain string, qtype uint16, opts Options) (Result, error) {
	if qtype == 0 {
		qtype = dnswire.TypeA
	}
	traceResult, err := dnstrace.Trace(ctx, domain, qtype, opts.Trace)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Domain: domain, QueryType: qtype, Delegation: traceResult.Delegation,
		Observations: make([]Observation, 0),
	}
	if len(traceResult.Delegation) == 0 {
		result.ErrorCode = "no_authority_set"
		if traceResult.ErrorCode != "" {
			result.Error = traceResult.ErrorCode + ": " + traceResult.Error
		} else {
			result.Error = "trace did not expose an authoritative delegation set"
		}
		return result, nil
	}

	exchange := opts.Trace.Exchange
	if exchange == nil {
		exchange = dnsmeasure.QueryWithRecursion
	}
	port := opts.Trace.Port
	if port == 0 {
		port = 53
	}
	timeout := opts.Trace.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	groups := make(map[string][]string)
	for _, authority := range traceResult.Delegation {
		if len(authority.Addresses) == 0 {
			result.Observations = append(result.Observations, Observation{
				Authority: authority.Name,
				Error:     nonEmpty(authority.Error, "authority has no resolved address"),
			})
			continue
		}
		for _, rawAddress := range authority.Addresses {
			address, parseErr := netip.ParseAddr(strings.TrimSpace(rawAddress))
			if parseErr != nil {
				result.Observations = append(result.Observations, Observation{
					Authority: authority.Name, Address: rawAddress, Error: "invalid authority address",
				})
				continue
			}
			observation, queryErr := queryAuthority(ctx, exchange, address.Unmap(), port, domain, qtype, timeout)
			if queryErr != nil {
				result.Observations = append(result.Observations, Observation{
					Authority: authority.Name, Address: address.Unmap().String(), Error: queryErr.Error(),
				})
				continue
			}
			if !observation.Header.AA {
				result.Observations = append(result.Observations, Observation{
					Authority: authority.Name, Address: address.Unmap().String(), Transport: observation.Transport,
					LatencyMs: float64(observation.Latency) / float64(time.Millisecond),
					RCode: observation.Header.RCode, Authoritative: false, Truncated: observation.Header.TC,
					Answers: mapRecords(observation.Answers), Error: "response was not authoritative",
				})
				continue
			}
			if observation.Header.RCode != 0 && observation.Header.RCode != 3 {
				result.Observations = append(result.Observations, Observation{
					Authority: authority.Name, Address: address.Unmap().String(), Transport: observation.Transport,
					LatencyMs: float64(observation.Latency) / float64(time.Millisecond),
					RCode: observation.Header.RCode, Authoritative: true, Truncated: observation.Header.TC,
					Answers: mapRecords(observation.Answers),
					Error: fmt.Sprintf("authoritative server returned unusable rcode %d", observation.Header.RCode),
				})
				continue
			}
			signature := dnsrr.AnswerSignature(observation.Header.RCode, observation.Answers, qtype)
			endpoint := authority.Name + "@" + address.Unmap().String()
			groups[signature] = append(groups[signature], endpoint)
			result.Responding++
			result.Observations = append(result.Observations, Observation{
				Authority: authority.Name, Address: address.Unmap().String(), Transport: observation.Transport,
				LatencyMs: float64(observation.Latency) / float64(time.Millisecond),
				RCode: observation.Header.RCode, Authoritative: observation.Header.AA, Truncated: observation.Header.TC,
				Signature: signature, Answers: mapRecords(observation.Answers),
			})
		}
	}

	for signature, endpoints := range groups {
		sort.Strings(endpoints)
		result.Groups = append(result.Groups, AgreementGroup{
			Signature: signature,
			Count:     len(endpoints),
			Endpoints: endpoints,
		})
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		if result.Groups[i].Count != result.Groups[j].Count {
			return result.Groups[i].Count > result.Groups[j].Count
		}
		return result.Groups[i].Signature < result.Groups[j].Signature
	})
	if len(result.Groups) > 0 {
		result.MajorityCount = result.Groups[0].Count
		result.MajoritySignature = result.Groups[0].Signature
		result.Unanimous = len(result.Groups) == 1 && result.Responding > 0
		result.Divergent = len(result.Groups) > 1
	}
	return result, nil
}

func queryAuthority(
	ctx context.Context,
	exchange dnstrace.ExchangeFunc,
	address netip.Addr,
	port uint16,
	domain string,
	qtype uint16,
	timeout time.Duration,
) (dnsmeasure.Observation, error) {
	observation, err := exchange(ctx, address, port, domain, qtype, dnsmeasure.UDP, timeout, false)
	if err != nil {
		return dnsmeasure.Observation{}, err
	}
	if !observation.Header.TC {
		return observation, nil
	}
	return exchange(ctx, address, port, domain, qtype, dnsmeasure.TCP, timeout, false)
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

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func ValidateResult(result Result) error {
	if strings.TrimSpace(result.Domain) == "" {
		return fmt.Errorf("domain is required")
	}
	return nil
}
