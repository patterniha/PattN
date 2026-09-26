package measure

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// DialTarget separates the physical socket destination from the logical HTTP/TLS identity.
// This is required for edge/CDN testing and for Reviver endpoint substitutions.
type DialTarget struct {
	Address    netip.Addr
	Port       uint16
	ServerName string
	HTTPHost   string
}

func (t DialTarget) socketAddress() string {
	return net.JoinHostPort(t.Address.String(), strconv.Itoa(int(t.Port)))
}

type HTTPProbeOptions struct {
	Scheme             string
	Path               string
	Method             string
	Timeout            time.Duration
	InsecureSkipVerify bool
	Headers            http.Header
}

type HTTPObservation struct {
	StatusCode int
	Latency    time.Duration
	Edge       EdgeObservation
	Headers    http.Header
}

// ProbePinnedHTTP makes a request whose URL/Host/TLS identity stays logical while the transport
// is forced to the candidate IP. It never rewrites the caller's logical hostname to the IP.
func ProbePinnedHTTP(ctx context.Context, target DialTarget, opts HTTPProbeOptions) (HTTPObservation, error) {
	if !target.Address.IsValid() || target.Port == 0 {
		return HTTPObservation{}, fmt.Errorf("invalid dial target")
	}
	if opts.Scheme == "" {
		opts.Scheme = "https"
	}
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.Method == "" {
		opts.Method = http.MethodHead
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	logicalHost := target.HTTPHost
	if logicalHost == "" {
		logicalHost = target.ServerName
	}
	if logicalHost == "" {
		return HTTPObservation{}, fmt.Errorf("logical host is required")
	}

	dialer := &net.Dialer{Timeout: opts.Timeout}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target.socketAddress())
		},
		TLSClientConfig: &tls.Config{
			ServerName:         target.ServerName,
			InsecureSkipVerify: opts.InsecureSkipVerify, // discovery can opt into reachability-only probing
			MinVersion:         tls.VersionTLS12,
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := opts.Scheme + "://" + logicalHost + opts.Path
	req, err := http.NewRequestWithContext(ctx, opts.Method, url, nil)
	if err != nil {
		return HTTPObservation{}, err
	}
	req.Host = logicalHost
	for key, values := range opts.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	started := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(started)
	if err != nil {
		return HTTPObservation{}, err
	}
	defer resp.Body.Close()
	return HTTPObservation{
		StatusCode: resp.StatusCode,
		Latency:    latency,
		Headers:    resp.Header.Clone(),
		Edge:       DetectEdge(resp.Header),
	}, nil
}
