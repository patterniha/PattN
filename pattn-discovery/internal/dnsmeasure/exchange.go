package dnsmeasure

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"pattn-discovery/internal/dnswire"
)

type Transport string

const (
	UDP Transport = "udp"
	TCP Transport = "tcp"
)

type Observation struct {
	Address     netip.Addr
	Port        uint16
	Domain      string
	QueryType   uint16
	Transport   Transport
	Latency     time.Duration
	Header      dnswire.Header
	AnswerIPs   []netip.Addr
	Answers     []dnswire.ResourceRecord
	Authorities []dnswire.ResourceRecord
	Additionals []dnswire.ResourceRecord
}

type QueryOptions struct {
	RecursionDesired bool
	EDNS              bool
	UDPSize           uint16
	DNSSECOK          bool
}

func Query(ctx context.Context, address netip.Addr, port uint16, domain string, qtype uint16, transport Transport, timeout time.Duration) (Observation, error) {
	return QueryAdvanced(ctx, address, port, domain, qtype, transport, timeout, QueryOptions{RecursionDesired: true})
}

func QueryWithRecursion(ctx context.Context, address netip.Addr, port uint16, domain string, qtype uint16, transport Transport, timeout time.Duration, recursionDesired bool) (Observation, error) {
	return QueryAdvanced(ctx, address, port, domain, qtype, transport, timeout, QueryOptions{RecursionDesired: recursionDesired})
}

func QueryAdvanced(ctx context.Context, address netip.Addr, port uint16, domain string, qtype uint16, transport Transport, timeout time.Duration, options QueryOptions) (Observation, error) {
	if !address.IsValid() {
		return Observation{}, fmt.Errorf("invalid resolver address")
	}
	if port == 0 {
		port = 53
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	query, txid, err := dnswire.BuildQueryWithOptions(domain, qtype, dnswire.QueryOptions{
		RecursionDesired: options.RecursionDesired,
		EDNS:              options.EDNS,
		UDPSize:           options.UDPSize,
		DNSSECOK:          options.DNSSECOK,
	})
	if err != nil {
		return Observation{}, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := string(transport)
	if transport != UDP && transport != TCP {
		return Observation{}, fmt.Errorf("unsupported dns transport %q", transport)
	}

	dialer := net.Dialer{}
	started := time.Now()
	conn, err := dialer.DialContext(probeCtx, network, net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
	if err != nil {
		return Observation{}, err
	}
	defer conn.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var packet []byte
	switch transport {
	case UDP:
		if _, err := conn.Write(query); err != nil {
			return Observation{}, err
		}
		buf := make([]byte, 64*1024)
		n, err := conn.Read(buf)
		if err != nil {
			return Observation{}, err
		}
		packet = buf[:n]
	case TCP:
		if len(query) > 65535 {
			return Observation{}, fmt.Errorf("dns query too large")
		}
		framed := make([]byte, 2, len(query)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(query)))
		framed = append(framed, query...)
		if _, err := conn.Write(framed); err != nil {
			return Observation{}, err
		}
		var lengthBuf [2]byte
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return Observation{}, err
		}
		length := int(binary.BigEndian.Uint16(lengthBuf[:]))
		if length < 12 {
			return Observation{}, fmt.Errorf("invalid tcp dns response length %d", length)
		}
		packet = make([]byte, length)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return Observation{}, err
		}
	}

	parsed, err := dnswire.ParseMessage(packet, txid, domain, qtype)
	if err != nil {
		return Observation{}, err
	}
	answerIPs := make([]netip.Addr, 0, len(parsed.Answers))
	for _, record := range parsed.Answers {
		if record.Address.IsValid() {
			answerIPs = append(answerIPs, record.Address.Unmap())
		}
	}
	return Observation{
		Address: address, Port: port, Domain: domain, QueryType: qtype, Transport: transport,
		Latency: time.Since(started), Header: parsed.Header, AnswerIPs: answerIPs,
		Answers: parsed.Answers, Authorities: parsed.Authorities, Additionals: parsed.Additionals,
	}, nil
}
