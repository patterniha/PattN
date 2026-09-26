package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"pattn-discovery/internal/scheduler"
	"pattn-discovery/internal/targets"
)

type TCPOptions struct {
	Ranges      []targets.Range
	Ports       []uint16
	Timeout     time.Duration
	Concurrency int
	MaxTargets  int64
	Gate        *scheduler.Gate
}

type TCPResult struct {
	Address   netip.Addr
	Port      uint16
	Open      bool
	Latency   time.Duration
	ErrorText string
}

type TCPProgress struct {
	AddressesDispatched int64
	EndpointsProcessed  int64
	OpenEndpoints       int64
}

type TCPSummary struct {
	AddressesDispatched int64
	EndpointsProcessed  int64
	OpenEndpoints       int64
	Cancelled           bool
}

type TCPCallbacks struct {
	Result   func(TCPResult) error
	Progress func(TCPProgress) error
}

type tcpJob struct {
	address netip.Addr
	port    uint16
}

// RunTCP performs a lazy, bounded-connectivity sweep. It never materializes expanded
// address ranges and centralizes pause/cancel semantics in the scheduler gate.
func RunTCP(ctx context.Context, opts TCPOptions, callbacks TCPCallbacks) (TCPSummary, error) {
	if len(opts.Ranges) == 0 {
		return TCPSummary{}, fmt.Errorf("at least one target range is required")
	}
	if len(opts.Ports) == 0 {
		return TCPSummary{}, fmt.Errorf("at least one port is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1500 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 256
	}
	if opts.Concurrency > 2048 {
		opts.Concurrency = 2048
	}
	if opts.MaxTargets <= 0 {
		opts.MaxTargets = 100_000
	}
	if opts.Gate == nil {
		opts.Gate = scheduler.NewGate()
	}

	jobs := make(chan tcpJob, opts.Concurrency*2)
	resultErr := make(chan error, 1)
	var once sync.Once
	reportErr := func(err error) {
		if err == nil {
			return
		}
		once.Do(func() { resultErr <- err })
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var addressesDispatched atomic.Int64
	var endpointsProcessed atomic.Int64
	var openEndpoints atomic.Int64
	var workerWG sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			dialer := &net.Dialer{Timeout: opts.Timeout}
			for {
				select {
				case <-runCtx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					if err := opts.Gate.Wait(runCtx); err != nil {
						return
					}
					started := time.Now()
					conn, err := dialer.DialContext(runCtx, "tcp", net.JoinHostPort(job.address.String(), strconv.Itoa(int(job.port))))
					latency := time.Since(started)
					result := TCPResult{Address: job.address, Port: job.port, Open: err == nil, Latency: latency}
					if err != nil {
						result.ErrorText = err.Error()
					} else {
						_ = conn.Close()
						openEndpoints.Add(1)
					}
					processed := endpointsProcessed.Add(1)
					if result.Open && callbacks.Result != nil {
						if err := callbacks.Result(result); err != nil {
							reportErr(err)
							cancel()
							return
						}
					}
					if callbacks.Progress != nil && (processed == 1 || processed%100 == 0) {
						if err := callbacks.Progress(TCPProgress{
							AddressesDispatched: addressesDispatched.Load(),
							EndpointsProcessed:  processed,
							OpenEndpoints:       openEndpoints.Load(),
						}); err != nil {
							reportErr(err)
							cancel()
							return
						}
					}
				}
			}
		}()
	}

	producerDone := make(chan error, 1)
	go func() {
		defer close(jobs)
		err := targets.Stream(runCtx, opts.Ranges, opts.MaxTargets, func(address netip.Addr) error {
			if err := opts.Gate.Wait(runCtx); err != nil {
				return err
			}
			for _, port := range opts.Ports {
				select {
				case <-runCtx.Done():
					return runCtx.Err()
				case jobs <- tcpJob{address: address, port: port}:
				}
			}
			addressesDispatched.Add(1)
			return nil
		})
		producerDone <- err
	}()

	workersDone := make(chan struct{})
	go func() {
		workerWG.Wait()
		close(workersDone)
	}()

	var producerErr error
	select {
	case producerErr = <-producerDone:
	case err := <-resultErr:
		producerErr = err
		cancel()
		<-producerDone
	case <-ctx.Done():
		producerErr = ctx.Err()
		cancel()
		<-producerDone
	}
	<-workersDone

	// The producer can finish before the last workers invoke callbacks. Re-check the callback-error channel
	// after all workers stop so a late sink failure cannot be mistaken for a successful scan.
	select {
	case callbackErr := <-resultErr:
		if callbackErr != nil {
			producerErr = callbackErr
		}
	default:
	}

	summary := TCPSummary{
		AddressesDispatched: addressesDispatched.Load(),
		EndpointsProcessed:  endpointsProcessed.Load(),
		OpenEndpoints:       openEndpoints.Load(),
		Cancelled:           ctx.Err() != nil || runCtx.Err() != nil,
	}
	if callbacks.Progress != nil {
		if err := callbacks.Progress(TCPProgress{
			AddressesDispatched: summary.AddressesDispatched,
			EndpointsProcessed:  summary.EndpointsProcessed,
			OpenEndpoints:       summary.OpenEndpoints,
		}); err != nil && producerErr == nil {
			producerErr = err
		}
	}
	if producerErr != nil && producerErr != context.Canceled {
		return summary, producerErr
	}
	return summary, nil
}
