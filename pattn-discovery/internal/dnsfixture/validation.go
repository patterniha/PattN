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
	return dnsvalidate.Validate(ctx, target, qtype, opts)
}
