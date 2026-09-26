package dnsfixture

import (
	"context"
	"fmt"

	"pattn-discovery/internal/dnsvalidate"
)

func ValidateDNSSECBundle(
	ctx context.Context,
	bundlePath string,
	target string,
	qtype uint16,
) (dnsvalidate.Result, error) {
	if target == "" {
		return dnsvalidate.Result{}, fmt.Errorf("validation target is required")
	}
	runtime, err := LoadExchangeBundle(bundlePath)
	if err != nil {
		return dnsvalidate.Result{}, err
	}
	opts, err := runtime.TraceOptions()
	if err != nil {
		return dnsvalidate.Result{}, err
	}
	result, err := dnsvalidate.ValidateAt(ctx, target, qtype, opts, runtime.ValidationTime())
	if err != nil {
		return dnsvalidate.Result{}, err
	}
	if !result.Trace.Complete {
		return dnsvalidate.Result{}, fmt.Errorf(
			"offline DNSSEC validation incomplete: %s: %s",
			result.Trace.ErrorCode,
			result.Trace.Error,
		)
	}
	return result, nil
}
