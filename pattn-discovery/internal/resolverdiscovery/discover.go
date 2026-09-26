package resolverdiscovery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnswire"
	"pattn-discovery/internal/scheduler"
	"pattn-discovery/internal/targets"
)

type Options struct {
	Ranges      []targets.Range
	Port        uint16
	Domain      string
	Timeout     time.Duration
	Concurrency int
	MaxTargets  int64
	Gate        *scheduler.Gate
}

type Result struct {
	Address            netip.Addr
	Port               uint16
	Latency            time.Duration
	RCode              uint8
	RecursionAvailable bool
	Truncated          bool
	AnswerIPs          []netip.Addr
}

type Progress struct {
	AddressesDispatched int64
	AddressesProcessed  int64
	Candidates          int64
}

type Summary = Progress

type Callbacks struct {
	Result   func(Result) error
	Progress func(Progress) error
}

func ProbeUDP(ctx context.Context, address netip.Addr, port uint16, domain string, timeout time.Duration) (Result, error) {
	if !address.IsValid() {
		return Result{}, errors.New("invalid resolver address")
	}
	if port == 0 {
		port = 53
	}
	if domain == "" {
		domain = "example.com"
	}
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	observation, err := dnsmeasure.Query(ctx, address, port, domain, dnswire.TypeA, dnsmeasure.UDP, timeout)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Address:            address,
		Port:               port,
		Latency:            observation.Latency,
		RCode:              observation.Header.RCode,
		RecursionAvailable: observation.Header.RA,
		Truncated:          observation.Header.TC,
		AnswerIPs:          observation.AnswerIPs,
	}, nil
}

func Run(ctx context.Context, opts Options, callbacks Callbacks) (Summary, error) {
	if opts.Port == 0 {
		opts.Port = 53
	}
	if opts.Domain == "" {
		opts.Domain = "example.com"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1200 * time.Millisecond
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 128
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

	jobs := make(chan netip.Addr, opts.Concurrency)
	var dispatched, processed, candidates atomic.Int64
	var callbackMu sync.Mutex
	var callbackErr error
	setCallbackErr := func(err error) {
		if err == nil {
			return
		}
		callbackMu.Lock()
		if callbackErr == nil {
			callbackErr = err
		}
		callbackMu.Unlock()
	}
	getCallbackErr := func() error {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		return callbackErr
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for address := range jobs {
				if workerCtx.Err() != nil {
					return
				}
				result, err := ProbeUDP(workerCtx, address, opts.Port, opts.Domain, opts.Timeout)
				currentProcessed := processed.Add(1)
				if err == nil {
					candidates.Add(1)
					if callbacks.Result != nil {
						if err := callbacks.Result(result); err != nil {
							setCallbackErr(err)
							cancel()
							return
						}
					}
				}
				if callbacks.Progress != nil && (currentProcessed == 1 || currentProcessed%128 == 0) {
					if err := callbacks.Progress(Progress{
						AddressesDispatched: dispatched.Load(),
						AddressesProcessed:  currentProcessed,
						Candidates:          candidates.Load(),
					}); err != nil {
						setCallbackErr(err)
						cancel()
						return
					}
				}
			}
		}()
	}

	streamErr := targets.Stream(workerCtx, opts.Ranges, opts.MaxTargets, func(address netip.Addr) error {
		if err := opts.Gate.Wait(workerCtx); err != nil {
			return err
		}
		select {
		case <-workerCtx.Done():
			return workerCtx.Err()
		case jobs <- address:
			dispatched.Add(1)
			return nil
		}
	})
	close(jobs)
	wg.Wait()

	summary := Summary{
		AddressesDispatched: dispatched.Load(),
		AddressesProcessed:  processed.Load(),
		Candidates:          candidates.Load(),
	}
	if callbacks.Progress != nil {
		if err := callbacks.Progress(summary); err != nil {
			setCallbackErr(err)
		}
	}
	if err := getCallbackErr(); err != nil {
		return summary, err
	}
	if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
		return summary, streamErr
	}
	if ctx.Err() != nil {
		return summary, ctx.Err()
	}
	return summary, nil
}
