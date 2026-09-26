package dnsrepair

import (
	"context"
	"fmt"
	"strings"

	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnsvalidate"
	"pattn-discovery/internal/dnswire"
	"pattn-discovery/internal/resolvercatalog"
)

type ValidateFunc func(context.Context, string, uint16, dnstrace.Options) (dnsvalidate.Result, error)
type TraceFunc func(context.Context, string, uint16, dnstrace.Options) (dnstrace.Result, error)

type Options struct {
	TraceOptions dnstrace.Options
	Validate     ValidateFunc
	Trace        TraceFunc
	Catalog      func() []resolvercatalog.Identity
}

type FamilyResult struct {
	Family              string              `json:"family"`
	QueryType           uint16              `json:"queryType"`
	Trace               dnstrace.Result     `json:"trace"`
	DNSSEC              *dnsvalidate.Result `json:"dnssec,omitempty"`
	DNSSECAuthenticated bool                `json:"dnssecAuthenticated"`
	DNSSECStatus        string              `json:"dnssecStatus,omitempty"`
	FallbackUsed        bool                `json:"fallbackUsed"`
	Error               string              `json:"error,omitempty"`
}

type Result struct {
	Domain                 string                     `json:"domain"`
	IPv4                   FamilyResult               `json:"ipv4"`
	IPv6                   FamilyResult               `json:"ipv6"`
	ResolverCatalogVersion string                     `json:"resolverCatalogVersion"`
	ResolverRecommendations []resolvercatalog.Identity `json:"resolverRecommendations"`
}

func Inspect(ctx context.Context, domain string, opts Options) (Result, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return Result{}, fmt.Errorf("domain is required")
	}
	if opts.Validate == nil {
		opts.Validate = dnsvalidate.Validate
	}
	if opts.Trace == nil {
		opts.Trace = dnstrace.Trace
	}
	if opts.Catalog == nil {
		opts.Catalog = resolvercatalog.Builtin
	}

	catalog := opts.Catalog()
	if err := resolvercatalog.Validate(catalog); err != nil {
		return Result{}, fmt.Errorf("resolver catalog: %w", err)
	}

	ipv4 := inspectFamily(ctx, domain, dnswire.TypeA, "ipv4", opts)
	ipv6 := inspectFamily(ctx, domain, dnswire.TypeAAAA, "ipv6", opts)
	return Result{
		Domain: domain,
		IPv4: ipv4,
		IPv6: ipv6,
		ResolverCatalogVersion: resolvercatalog.Version,
		ResolverRecommendations: catalog,
	}, nil
}

func inspectFamily(ctx context.Context, domain string, qtype uint16, family string, opts Options) FamilyResult {
	out := FamilyResult{Family: family, QueryType: qtype}
	validation, err := opts.Validate(ctx, domain, qtype, opts.TraceOptions)
	if err == nil {
		out.Trace = validation.Trace
		out.DNSSEC = &validation
		out.DNSSECAuthenticated = validation.AnswerAuthenticated
		out.DNSSECStatus = validation.Status
		out.Error = validation.Trace.Error
		return out
	}

	out.FallbackUsed = true
	out.DNSSECStatus = "validation-unavailable"
	trace, traceErr := opts.Trace(ctx, domain, qtype, opts.TraceOptions)
	if traceErr != nil {
		out.Error = err.Error() + "; trace: " + traceErr.Error()
		return out
	}
	out.Trace = trace
	if trace.Error != "" {
		out.Error = trace.Error
	} else {
		out.Error = err.Error()
	}
	return out
}
