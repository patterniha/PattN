package resolverdiscovery

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/targets"
)

func TestProbeUDPRecognizesValidRecursiveResolver(t *testing.T) {
	server, port := startResolverStub(t)
	defer server.Close()

	result, err := ProbeUDP(context.Background(), netip.MustParseAddr("127.0.0.1"), port, "example.com", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RecursionAvailable || result.RCode != 0 || len(result.AnswerIPs) != 1 || result.AnswerIPs[0].String() != "203.0.113.9" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRunStreamsCandidatesWithoutMaterializingRanges(t *testing.T) {
	server, port := startResolverStub(t)
	defer server.Close()

	r, err := targets.Parse("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var results []Result
	summary, err := Run(context.Background(), Options{
		Ranges: []targets.Range{r}, Port: port, Domain: "example.com", Timeout: time.Second,
		Concurrency: 2, MaxTargets: 1,
	}, Callbacks{Result: func(result Result) error {
		results = append(results, result)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if summary.AddressesDispatched != 1 || summary.AddressesProcessed != 1 || summary.Candidates != 1 || len(results) != 1 {
		t.Fatalf("summary=%+v results=%v", summary, results)
	}
}

func startResolverStub(t *testing.T) (net.PacketConn, uint16) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			query := append([]byte(nil), buf[:n]...)
			response := make([]byte, 12, n+16)
			copy(response[0:2], query[0:2])
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[4:6], 1)
			binary.BigEndian.PutUint16(response[6:8], 1)
			response = append(response, query[12:]...)
			response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01)
			response = binary.BigEndian.AppendUint32(response, 60)
			response = binary.BigEndian.AppendUint16(response, 4)
			response = append(response, 203, 0, 113, 9)
			_, _ = conn.WriteTo(response, peer)
		}
	}()
	return conn, port
}

func TestRunReturnsFinalProgressCallbackError(t *testing.T) {
	server, port := startResolverStub(t)
	defer server.Close()
	r, err := targets.Parse("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("progress sink failed")
	progressCalls := 0

	_, got := Run(context.Background(), Options{
		Ranges: []targets.Range{r}, Port: port, Domain: "example.com", Timeout: time.Second,
		Concurrency: 1, MaxTargets: 1,
	}, Callbacks{Progress: func(Progress) error {
		progressCalls++
		if progressCalls > 1 {
			return want
		}
		return nil
	}})

	if !errors.Is(got, want) {
		t.Fatalf("Run error=%v, want %v", got, want)
	}
}
