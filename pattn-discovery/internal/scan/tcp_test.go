package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"pattn-discovery/internal/scheduler"
	"pattn-discovery/internal/targets"
)

func TestRunTCPStreamsOpenEndpointWithoutRangeExpansion(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	portInt, _ := strconv.Atoi(portText)

	ranges, invalid := targets.ParseMany([]string{"127.0.0.1/32", "2001:db8::/64"})
	if len(invalid) != 0 {
		t.Fatal(invalid)
	}
	var got atomic.Int64
	summary, err := RunTCP(context.Background(), TCPOptions{
		Ranges:      ranges,
		Ports:       []uint16{uint16(portInt)},
		Timeout:     250 * time.Millisecond,
		Concurrency: 4,
		MaxTargets:  1, // proves the huge IPv6 range is never expanded
		Gate:        scheduler.NewGate(),
	}, TCPCallbacks{
		Result: func(result TCPResult) error {
			if result.Open && result.Address.String() == "127.0.0.1" {
				got.Add(1)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Load() != 1 || summary.AddressesDispatched != 1 || summary.OpenEndpoints != 1 {
		t.Fatalf("got=%d summary=%+v", got.Load(), summary)
	}
}

func TestRunTCPPauseBlocksDispatchUntilResume(t *testing.T) {
	gate := scheduler.NewGate()
	gate.Pause()
	ranges, _ := targets.ParseMany([]string{"127.0.0.1"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan TCPSummary, 1)
	go func() {
		summary, _ := RunTCP(ctx, TCPOptions{
			Ranges:      ranges,
			Ports:       []uint16{1},
			Timeout:     20 * time.Millisecond,
			Concurrency: 1,
			MaxTargets:  1,
			Gate:        gate,
		}, TCPCallbacks{})
		done <- summary
	}()
	time.Sleep(30 * time.Millisecond)
	gate.Resume()
	summary := <-done
	if summary.AddressesDispatched != 1 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestRunTCPReturnsLateWorkerCallbackErrorAfterProducerCompletes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	portInt, _ := strconv.Atoi(portText)
	ranges, _ := targets.ParseMany([]string{"127.0.0.1"})

	want := errors.New("result sink failed")
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, runErr := RunTCP(context.Background(), TCPOptions{
			Ranges: ranges, Ports: []uint16{uint16(portInt)}, Timeout: time.Second,
			Concurrency: 1, MaxTargets: 1,
		}, TCPCallbacks{Result: func(TCPResult) error {
			close(callbackStarted)
			<-releaseCallback
			return want
		}})
		done <- runErr
	}()

	<-callbackStarted
	// The single target has already been handed to the worker; give the producer time to publish completion
	// before releasing the deliberately late callback error.
	time.Sleep(20 * time.Millisecond)
	close(releaseCallback)
	if got := <-done; !errors.Is(got, want) {
		t.Fatalf("RunTCP error=%v, want %v", got, want)
	}
}
