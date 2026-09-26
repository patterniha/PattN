package resolverqual

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestQualifySeparatesUsableResolverFromReferenceDivergence(t *testing.T) {
	stop, port := startDualResolver(t, false)
	defer stop()

	clean := Qualify(context.Background(), Options{
		Address: netip.MustParseAddr("127.0.0.1"), Port: port, Domain: "example.com", Timeout: time.Second,
		ReferenceAnswers: []netip.Addr{netip.MustParseAddr("203.0.113.9")}, CheckUDP: true, CheckTCP: true, CheckHijack: true,
	})
	if clean.Status != StatusUsable || !clean.Responded || !clean.RecursionAvailable || clean.HijackDetected || clean.ReferenceDivergence {
		t.Fatalf("clean=%+v", clean)
	}
	if clean.TransportAgreement == nil || !*clean.TransportAgreement {
		t.Fatalf("transport agreement=%v", clean.TransportAgreement)
	}

	divergent := Qualify(context.Background(), Options{
		Address: netip.MustParseAddr("127.0.0.1"), Port: port, Domain: "example.com", Timeout: time.Second,
		ReferenceAnswers: []netip.Addr{netip.MustParseAddr("198.51.100.7")}, CheckUDP: true, CheckTCP: true,
	})
	if divergent.Status != StatusDivergent || !divergent.ReferenceCompared || !divergent.ReferenceDivergence {
		t.Fatalf("divergent=%+v", divergent)
	}
}

func TestQualifyDetectsInvalidNameHijack(t *testing.T) {
	stop, port := startDualResolver(t, true)
	defer stop()

	result := Qualify(context.Background(), Options{
		Address: netip.MustParseAddr("127.0.0.1"), Port: port, Domain: "example.com", Timeout: time.Second,
		CheckUDP: true, CheckTCP: true, CheckHijack: true,
	})
	if result.Status != StatusHijack || !result.HijackChecked || !result.HijackDetected {
		t.Fatalf("result=%+v", result)
	}
}

func startDualResolver(t *testing.T, hijackInvalid bool) (func(), uint16) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(tcp.Addr().(*net.TCPAddr).Port)
	udp, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", decimalPort(port)))
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				response := qualifyResponse(query, hijackInvalid)
				binary.BigEndian.PutUint16(length[:], uint16(len(response)))
				_, _ = conn.Write(append(length[:], response...))
			}(conn)
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			_, _ = udp.WriteTo(qualifyResponse(query, hijackInvalid), peer)
		}
	}()

	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
		_ = tcp.Close()
		_ = udp.Close()
	}, port
}

func qualifyResponse(query []byte, hijackInvalid bool) []byte {
	isInvalid := strings.Contains(string(query), "invalid")
	rcode := uint16(0)
	answer := true
	if isInvalid && !hijackInvalid {
		rcode = 3
		answer = false
	}
	flags := uint16(0x8180) | rcode
	response := make([]byte, 12, len(query)+16)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	if answer {
		binary.BigEndian.PutUint16(response[6:8], 1)
	}
	response = append(response, query[12:]...)
	if answer {
		response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01)
		response = binary.BigEndian.AppendUint32(response, 60)
		response = binary.BigEndian.AppendUint16(response, 4)
		response = append(response, 203, 0, 113, 9)
	}
	return response
}

func decimalPort(port uint16) string {
	if port == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	value := int(port)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}


func TestQualifyCanUseAuthenticatedDnssecReference(t *testing.T) {
	stop, port := startDualResolver(t, false)
	defer stop()

	result := Qualify(context.Background(), Options{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port: port,
		Domain: "example.com",
		Timeout: time.Second,
		AuthenticatedReferenceAnswers: []netip.Addr{netip.MustParseAddr("198.51.100.77")},
		AuthenticatedReferenceStatus: "root-anchored-authenticated-answer",
		CheckUDP: true,
		CheckTCP: true,
	})
	if result.Status != StatusDNSSECDivergent ||
		!result.DNSSECReferenceCompared ||
		!result.DNSSECReferenceDivergence ||
		result.DNSSECReferenceStatus != "root-anchored-authenticated-answer" {
		t.Fatalf("result=%+v", result)
	}
}


func TestInvalidNameHijackRequiresPositiveSynthesizedAnswer(t *testing.T) {
	tests := []struct {
		name     string
		evidence TransportEvidence
		want     bool
	}{
		{
			name: "positive-noerror-answer",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     0,
				AnswerIPs: []string{"203.0.113.9"},
			},
			want: true,
		},
		{
			name: "nxdomain",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     3,
			},
		},
		{
			name: "nxdomain-with-synthesized-answer",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     3,
				AnswerIPs: []string{"203.0.113.9"},
			},
			want: true,
		},
		{
			name: "servfail",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     2,
			},
		},
		{
			name: "refused",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     5,
			},
		},
		{
			name: "empty-noerror",
			evidence: TransportEvidence{
				Responded: true,
				RCode:     0,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPositiveInvalidNameAnswer(test.evidence); got != test.want {
				t.Fatalf("isPositiveInvalidNameAnswer(%+v)=%v want %v", test.evidence, got, test.want)
			}
		})
	}
}
