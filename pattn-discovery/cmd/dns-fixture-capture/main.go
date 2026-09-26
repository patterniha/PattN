package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"pattn-discovery/internal/dnsfixture"
	"pattn-discovery/internal/dnswire"
)

func main() {
	server := flag.String("server", "1.1.1.1:53", "DNS server host:port")
	name := flag.String("name", "", "DNS query name")
	qtype := flag.Uint("type", uint(dnswire.TypeA), "numeric DNS query type")
	timeout := flag.Duration("timeout", 3*time.Second, "capture timeout")
	recursive := flag.Bool("recursive", true, "set the RD bit; disable for authoritative captures")
	dnssecOK := flag.Bool("dnssec", true, "request DNSSEC records with EDNS DO")
	transport := flag.String("transport", "auto", "DNS transport: auto, udp, or tcp; auto retries truncated UDP over TCP")
	out := flag.String("out", "", "output fixture JSON path")
	notes := flag.String("notes", "", "optional fixture notes")
	flag.Parse()

	mode := strings.ToLower(strings.TrimSpace(*transport))
	if *name == "" || *out == "" || *qtype == 0 || *qtype > 65535 {
		fmt.Fprintln(os.Stderr, "-name and -out are required; -type must be 1..65535")
		os.Exit(2)
	}
	if mode != "auto" && mode != "udp" && mode != "tcp" {
		fmt.Fprintln(os.Stderr, "-transport must be auto, udp, or tcp")
		os.Exit(2)
	}

	packet, id, err := dnswire.BuildQueryWithOptions(
		*name,
		uint16(*qtype),
		dnswire.QueryOptions{
			RecursionDesired: *recursive,
			EDNS:              *dnssecOK,
			UDPSize:           1232,
			DNSSECOK:          *dnssecOK,
		},
	)
	if err != nil {
		fail(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	usedTransport := mode
	var response []byte
	switch mode {
	case "tcp":
		response, err = exchangeTCP(ctx, *server, packet)
	case "udp":
		response, err = exchangeUDP(ctx, *server, packet)
	case "auto":
		usedTransport = "udp"
		response, err = exchangeUDP(ctx, *server, packet)
		if err == nil && dnsTruncated(response) {
			usedTransport = "tcp"
			response, err = exchangeTCP(ctx, *server, packet)
		}
	}
	if err != nil {
		fail(err)
	}
	if dnsTruncated(response) {
		fail(fmt.Errorf("captured DNS response is truncated; use TCP or auto transport"))
	}

	fixture, err := dnsfixture.NewCaptured(
		*name+" type "+strconv.Itoa(int(*qtype)),
		usedTransport+"://"+*server,
		time.Now(),
		*name,
		uint16(*qtype),
		id,
		response,
		*notes,
	)
	if err != nil {
		fail(err)
	}
	if _, err := fixture.Replay(); err != nil {
		fail(fmt.Errorf("captured packet failed replay validation: %w", err))
	}
	if err := fixture.Save(*out); err != nil {
		fail(err)
	}
}

func exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), response[:n]...), nil
}

func exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, fmt.Errorf("DNS query exceeds TCP framing limit")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 {
		return nil, fmt.Errorf("invalid DNS-over-TCP response length %d", n)
	}
	response := make([]byte, n)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func dnsTruncated(packet []byte) bool {
	return len(packet) >= 4 && binary.BigEndian.Uint16(packet[2:4])&0x0200 != 0
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
