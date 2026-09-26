package resolverdepth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnsrr"
	"pattn-discovery/internal/dnswire"
)

type Options struct {
	Address       netip.Addr
	Port          uint16
	Domain        string
	Timeout       time.Duration
	ServerName    string
	DoTPort       uint16
	DoHURL        string
	Attempts      int
	MinimumSuccesses int
	CheckUDP      bool
	CheckTCP      bool
	CheckEDNS     bool
	CheckTXT      bool
	CheckDoT      bool
	CheckDoH      bool
}

type Attempt struct {
	Responded          bool     `json:"responded"`
	LatencyMs          float64  `json:"latencyMs,omitempty"`
	RCode              uint8    `json:"rcode,omitempty"`
	RecursionAvailable bool     `json:"recursionAvailable"`
	Truncated          bool     `json:"truncated"`
	EDNSObserved        bool     `json:"ednsObserved"`
	AnswerCount         int      `json:"answerCount,omitempty"`
	AnswerSignature     string   `json:"answerSignature,omitempty"`
	TXT                 []string `json:"txt,omitempty"`
	TLSVersion          string   `json:"tlsVersion,omitempty"`
	ALPN                string   `json:"alpn,omitempty"`
	TLSServerName       string   `json:"tlsServerName,omitempty"`
	TLSVerified         bool     `json:"tlsVerified"`
	HTTPStatus          int      `json:"httpStatus,omitempty"`
	HTTPVersion         string   `json:"httpVersion,omitempty"`
	ContentType         string   `json:"contentType,omitempty"`
	Error               string   `json:"error,omitempty"`
}

type Probe struct {
	Transport          string    `json:"transport"`
	Attempted          bool      `json:"attempted"`
	Responded          bool      `json:"responded"`
	Attempts           int       `json:"attempts"`
	Successes          int       `json:"successes"`
	QuorumMet          bool      `json:"quorumMet"`
	Reliability        float64   `json:"reliability"`
	MedianLatencyMs    float64   `json:"medianLatencyMs,omitempty"`
	LatencyMs          float64   `json:"latencyMs,omitempty"`
	RCode              uint8     `json:"rcode,omitempty"`
	RecursionAvailable bool      `json:"recursionAvailable"`
	Truncated          bool      `json:"truncated"`
	EDNSObserved        bool      `json:"ednsObserved"`
	AnswerCount         int       `json:"answerCount,omitempty"`
	AnswerSignature     string    `json:"answerSignature,omitempty"`
	TXT                 []string  `json:"txt,omitempty"`
	TLSVersion          string    `json:"tlsVersion,omitempty"`
	ALPN                string    `json:"alpn,omitempty"`
	TLSServerName       string    `json:"tlsServerName,omitempty"`
	TLSVerified         bool      `json:"tlsVerified"`
	HTTPStatus          int       `json:"httpStatus,omitempty"`
	HTTPVersion         string    `json:"httpVersion,omitempty"`
	ContentType         string    `json:"contentType,omitempty"`
	Error               string    `json:"error,omitempty"`
	Samples             []Attempt `json:"samples,omitempty"`
}

type Result struct {
	Address                   string   `json:"address"`
	Domain                    string   `json:"domain"`
	UDP                       *Probe   `json:"udp,omitempty"`
	TCP                       *Probe   `json:"tcp,omitempty"`
	EDNS512                   *Probe   `json:"edns512,omitempty"`
	EDNS1232                  *Probe   `json:"edns1232,omitempty"`
	TXT                       *Probe   `json:"txt,omitempty"`
	DoT                       *Probe   `json:"dot,omitempty"`
	DoH                       *Probe   `json:"doh,omitempty"`
	EDNSCompatible            bool     `json:"ednsCompatible"`
	EDNSDowngrade             bool     `json:"ednsDowngrade"`
	UDPAndTCPAgree            *bool    `json:"udpAndTcpAgree,omitempty"`
	ClassicEncryptedAgree     *bool    `json:"classicEncryptedAgree,omitempty"`
	EncryptedDNS              bool     `json:"encryptedDnsAvailable"`
	InterceptionSuspected     bool     `json:"interceptionSuspected"`
	InterceptionReasons       []string `json:"interceptionReasons,omitempty"`
	QuorumTransportCount      int      `json:"quorumTransportCount"`
	ReliabilityFloor          float64  `json:"reliabilityFloor"`
	Quality                   string   `json:"quality"`
	QualityReasons            []string `json:"qualityReasons,omitempty"`
	Status                    string   `json:"status"`
}

func Profile(ctx context.Context, opts Options) Result {
	normalizeOptions(&opts)
	result := Result{Address: opts.Address.String(), Domain: opts.Domain, Status: "unreachable"}

	if opts.CheckUDP {
		p := runProbe(opts, "udp", func() Attempt {
			return queryPlain(ctx, opts, dnswire.TypeA, dnsmeasure.UDP, dnsmeasure.QueryOptions{RecursionDesired: true})
		})
		result.UDP = &p
	}
	if opts.CheckTCP {
		p := runProbe(opts, "tcp", func() Attempt {
			return queryPlain(ctx, opts, dnswire.TypeA, dnsmeasure.TCP, dnsmeasure.QueryOptions{RecursionDesired: true})
		})
		result.TCP = &p
	}
	if opts.CheckEDNS {
		p512 := runProbe(opts, "edns-udp-512", func() Attempt {
			return queryPlain(ctx, opts, dnswire.TypeA, dnsmeasure.UDP, dnsmeasure.QueryOptions{RecursionDesired: true, EDNS: true, UDPSize: 512})
		})
		p1232 := runProbe(opts, "edns-udp-1232", func() Attempt {
			return queryPlain(ctx, opts, dnswire.TypeA, dnsmeasure.UDP, dnsmeasure.QueryOptions{RecursionDesired: true, EDNS: true, UDPSize: 1232})
		})
		result.EDNS512, result.EDNS1232 = &p512, &p1232
		result.EDNSCompatible = p512.QuorumMet || p1232.QuorumMet
		result.EDNSDowngrade = result.UDP != nil && result.UDP.QuorumMet && !result.EDNSCompatible
	}
	if opts.CheckTXT {
		p := runProbe(opts, "txt", func() Attempt {
			return queryPlain(ctx, opts, dnswire.TypeTXT, dnsmeasure.UDP, dnsmeasure.QueryOptions{RecursionDesired: true, EDNS: true, UDPSize: 1232})
		})
		result.TXT = &p
	}
	if opts.CheckDoT {
		p := runProbe(opts, "dot", func() Attempt { return queryDoT(ctx, opts) })
		result.DoT = &p
		result.EncryptedDNS = result.EncryptedDNS || p.QuorumMet
	}
	if opts.CheckDoH {
		p := runProbe(opts, "doh", func() Attempt { return queryDoH(ctx, opts) })
		result.DoH = &p
		result.EncryptedDNS = result.EncryptedDNS || p.QuorumMet
	}

	for _, probe := range []*Probe{result.UDP, result.TCP, result.EDNS512, result.EDNS1232, result.TXT, result.DoT, result.DoH} {
		if probe != nil && probe.QuorumMet {
			result.QuorumTransportCount++
		}
	}
	if result.UDP != nil && result.UDP.QuorumMet && result.TCP != nil && result.TCP.QuorumMet {
		agree := comparableSignature(result.UDP) == comparableSignature(result.TCP)
		result.UDPAndTCPAgree = &agree
	}
	deriveEncryptedComparison(&result)
	deriveQuality(&result)
	switch {
	case result.QuorumTransportCount > 0:
		result.Status = "usable"
	case anyResponded(result):
		result.Status = "unstable"
	case anyAttempted(result):
		result.Status = "attempted-no-quorum"
	}
	return result
}

func normalizeOptions(opts *Options) {
	if opts.Port == 0 { opts.Port = 53 }
	if opts.DoTPort == 0 { opts.DoTPort = 853 }
	if opts.Timeout <= 0 { opts.Timeout = 2 * time.Second }
	if strings.TrimSpace(opts.Domain) == "" { opts.Domain = "example.com" }
	if opts.Attempts <= 0 { opts.Attempts = 3 }
	if opts.Attempts > 7 { opts.Attempts = 7 }
	if opts.MinimumSuccesses <= 0 {
		opts.MinimumSuccesses = opts.Attempts/2 + 1
	}
	if opts.MinimumSuccesses > opts.Attempts { opts.MinimumSuccesses = opts.Attempts }
	if !opts.CheckUDP && !opts.CheckTCP && !opts.CheckEDNS && !opts.CheckTXT && !opts.CheckDoT && !opts.CheckDoH {
		opts.CheckUDP, opts.CheckTCP, opts.CheckEDNS, opts.CheckTXT = true, true, true, true
	}
}

func runProbe(opts Options, transport string, fn func() Attempt) Probe {
	out := Probe{Transport: transport, Attempted: true, Attempts: opts.Attempts}
	out.Samples = make([]Attempt, 0, opts.Attempts)
	for i := 0; i < opts.Attempts; i++ {
		sample := fn()
		out.Samples = append(out.Samples, sample)
		if sample.Responded { out.Successes++ }
	}
	out.Reliability = float64(out.Successes) / float64(out.Attempts)
	out.QuorumMet = out.Successes >= opts.MinimumSuccesses
	out.Responded = out.Successes > 0

	successes := make([]Attempt, 0, out.Successes)
	latencies := make([]float64, 0, out.Successes)
	signatures := make(map[string]int)
	for _, sample := range out.Samples {
		if !sample.Responded { continue }
		successes = append(successes, sample)
		latencies = append(latencies, sample.LatencyMs)
		if sample.AnswerSignature != "" { signatures[sample.AnswerSignature]++ }
	}
	if len(successes) == 0 {
		for i := len(out.Samples)-1; i >= 0; i-- {
			if out.Samples[i].Error != "" { out.Error = out.Samples[i].Error; break }
		}
		return out
	}
	sort.Float64s(latencies)
	out.MedianLatencyMs = median(latencies)
	representative := chooseRepresentative(successes, signatures)
	copyAttempt(&out, representative)
	return out
}

func chooseRepresentative(values []Attempt, signatures map[string]int) Attempt {
	bestSignature := ""
	bestCount := -1
	for signature, count := range signatures {
		if count > bestCount || (count == bestCount && signature < bestSignature) {
			bestSignature, bestCount = signature, count
		}
	}
	candidates := values
	if bestSignature != "" {
		candidates = nil
		for _, value := range values {
			if value.AnswerSignature == bestSignature { candidates = append(candidates, value) }
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].LatencyMs < candidates[j].LatencyMs })
	return candidates[len(candidates)/2]
}

func copyAttempt(out *Probe, value Attempt) {
	out.LatencyMs = value.LatencyMs
	out.RCode = value.RCode
	out.RecursionAvailable = value.RecursionAvailable
	out.Truncated = value.Truncated
	out.EDNSObserved = value.EDNSObserved
	out.AnswerCount = value.AnswerCount
	out.AnswerSignature = value.AnswerSignature
	out.TXT = append([]string(nil), value.TXT...)
	out.TLSVersion = value.TLSVersion
	out.ALPN = value.ALPN
	out.TLSServerName = value.TLSServerName
	out.TLSVerified = value.TLSVerified
	out.HTTPStatus = value.HTTPStatus
	out.HTTPVersion = value.HTTPVersion
	out.ContentType = value.ContentType
	out.Error = value.Error
}

func queryPlain(ctx context.Context, opts Options, qtype uint16, transport dnsmeasure.Transport, queryOpts dnsmeasure.QueryOptions) Attempt {
	out := Attempt{}
	observation, err := dnsmeasure.QueryAdvanced(ctx, opts.Address, opts.Port, opts.Domain, qtype, transport, opts.Timeout, queryOpts)
	if err != nil { out.Error = err.Error(); return out }
	fillObservation(&out, observation)
	return out
}

func queryDoT(ctx context.Context, opts Options) Attempt {
	out := Attempt{TLSServerName: opts.ServerName}
	if strings.TrimSpace(opts.ServerName) == "" {
		out.Error = "DoT serverName is required for identity validation"
		return out
	}
	query, id, err := dnswire.BuildQueryWithOptions(opts.Domain, dnswire.TypeA, dnswire.QueryOptions{RecursionDesired: true, EDNS: true, UDPSize: 1232})
	if err != nil { out.Error = err.Error(); return out }
	probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{ServerName: opts.ServerName, MinVersion: tls.VersionTLS12, NextProtos: []string{"dot"}},
	}
	start := time.Now()
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(opts.Address.String(), strconv.Itoa(int(opts.DoTPort))))
	if err != nil { out.Error = err.Error(); return out }
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok { out.Error = "DoT connection is not TLS"; return out }
	if deadline, ok := probeCtx.Deadline(); ok { _ = conn.SetDeadline(deadline) }
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)
	if _, err := conn.Write(frame); err != nil { out.Error = err.Error(); return out }
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil { out.Error = err.Error(); return out }
	packet := make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if _, err := io.ReadFull(conn, packet); err != nil { out.Error = err.Error(); return out }
	message, err := dnswire.ParseMessage(packet, id, opts.Domain, dnswire.TypeA)
	if err != nil { out.Error = err.Error(); return out }
	state := tlsConn.ConnectionState()
	out.Responded = true
	out.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	fillMessage(&out, message, dnswire.TypeA)
	out.TLSVersion = tlsVersionName(state.Version)
	out.ALPN = state.NegotiatedProtocol
	out.TLSVerified = len(state.VerifiedChains) > 0
	return out
}

func queryDoH(ctx context.Context, opts Options) Attempt {
	out := Attempt{}
	parsed, err := url.Parse(opts.DoHURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		out.Error = "valid HTTPS DoH URL is required"
		return out
	}
	serverName := parsed.Hostname()
	out.TLSServerName = serverName
	query, id, err := dnswire.BuildQueryWithOptions(opts.Domain, dnswire.TypeA, dnswire.QueryOptions{RecursionDesired: true, EDNS: true, UDPSize: 1232})
	if err != nil { out.Error = err.Error(); return out }
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
	}
	if opts.Address.IsValid() {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			port := parsed.Port()
			if port == "" { port = "443" }
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(opts.Address.String(), port))
		}
	}
	client := &http.Client{Transport: transport, Timeout: opts.Timeout}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.DoHURL, bytes.NewReader(query))
	if err != nil { out.Error = err.Error(); return out }
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	start := time.Now()
	response, err := client.Do(request)
	if err != nil { out.Error = err.Error(); return out }
	defer response.Body.Close()
	out.HTTPStatus = response.StatusCode
	out.HTTPVersion = response.Proto
	out.ContentType = response.Header.Get("Content-Type")
	if response.TLS != nil {
		out.TLSVersion = tlsVersionName(response.TLS.Version)
		out.ALPN = response.TLS.NegotiatedProtocol
		out.TLSVerified = len(response.TLS.VerifiedChains) > 0
	}
	if response.StatusCode != http.StatusOK {
		out.Error = fmt.Sprintf("DoH HTTP status %d", response.StatusCode)
		return out
	}
	if !strings.HasPrefix(strings.ToLower(out.ContentType), "application/dns-message") {
		out.Error = "DoH response content-type is not application/dns-message"
		return out
	}
	packet, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil { out.Error = err.Error(); return out }
	message, err := dnswire.ParseMessage(packet, id, opts.Domain, dnswire.TypeA)
	if err != nil { out.Error = err.Error(); return out }
	out.Responded = true
	out.LatencyMs = float64(time.Since(start)) / float64(time.Millisecond)
	fillMessage(&out, message, dnswire.TypeA)
	return out
}

func fillObservation(out *Attempt, observation dnsmeasure.Observation) {
	out.Responded = true
	out.LatencyMs = float64(observation.Latency) / float64(time.Millisecond)
	out.RCode = observation.Header.RCode
	out.RecursionAvailable = observation.Header.RA
	out.Truncated = observation.Header.TC
	out.AnswerCount = len(observation.Answers)
	out.EDNSObserved = hasOPT(observation.Additionals)
	out.AnswerSignature = dnsrr.AnswerSignature(observation.Header.RCode, observation.Answers, observation.QueryType)
	for _, record := range observation.Answers {
		if record.Type == dnswire.TypeTXT {
			out.TXT = append(out.TXT, decodeTXT(record.RawData)...)
		}
	}
}

func fillMessage(out *Attempt, message dnswire.Message, qtype uint16) {
	out.RCode = message.Header.RCode
	out.RecursionAvailable = message.Header.RA
	out.Truncated = message.Header.TC
	out.AnswerCount = len(message.Answers)
	out.EDNSObserved = hasOPT(message.Additionals)
	out.AnswerSignature = dnsrr.AnswerSignature(message.Header.RCode, message.Answers, qtype)
}

func deriveEncryptedComparison(result *Result) {
	if probeGroupDivergent(result.UDP, result.TCP) {
		result.InterceptionReasons = append(result.InterceptionReasons, "classic-transports-diverge")
	}
	if probeGroupDivergent(result.DoT, result.DoH) {
		result.InterceptionReasons = append(result.InterceptionReasons, "encrypted-transports-diverge")
	}

	classic := stableSignature(result.UDP, result.TCP)
	encrypted := stableSignature(result.DoT, result.DoH)
	if classic == "" || encrypted == "" { return }

	agree := classic == encrypted
	result.ClassicEncryptedAgree = &agree
	if !agree {
		result.InterceptionSuspected = true
		result.InterceptionReasons = append(result.InterceptionReasons, "classic-encrypted-answer-divergence")
		if result.UDPAndTCPAgree != nil && *result.UDPAndTCPAgree {
			result.InterceptionReasons = append(result.InterceptionReasons, "classic-transports-agree-but-encrypted-differs")
		}
		if !probeGroupDivergent(result.DoT, result.DoH) {
			result.InterceptionReasons = append(result.InterceptionReasons, "encrypted-transports-agree-against-classic")
		}
	}
}

func stableSignature(values ...*Probe) string {
	var stable string
	for _, value := range values {
		if value == nil || !value.QuorumMet { continue }
		signature := comparableSignature(value)
		if signature == "" { continue }
		if stable == "" {
			stable = signature
			continue
		}
		if stable != signature {
			return ""
		}
	}
	return stable
}

func probeGroupDivergent(values ...*Probe) bool {
	var signature string
	count := 0
	for _, value := range values {
		if value == nil || !value.QuorumMet { continue }
		current := comparableSignature(value)
		if current == "" { continue }
		count++
		if signature == "" {
			signature = current
			continue
		}
		if signature != current {
			return true
		}
	}
	return count > 1 && signature == ""
}

func comparableSignature(value *Probe) string {
	if value == nil { return "" }
	return value.AnswerSignature
}

func decodeTXT(data []byte) []string {
	var out []string
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) { break }
		out = append(out, string(data[offset:offset+length]))
		offset += length
	}
	return out
}

func hasOPT(records []dnswire.ResourceRecord) bool {
	for _, record := range records {
		if record.Type == dnswire.TypeOPT { return true }
	}
	return false
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func median(values []float64) float64 {
	if len(values) == 0 { return 0 }
	mid := len(values)/2
	if len(values)%2 == 1 { return values[mid] }
	return (values[mid-1]+values[mid])/2
}

func anyResponded(result Result) bool {
	for _, probe := range []*Probe{result.UDP, result.TCP, result.EDNS512, result.EDNS1232, result.TXT, result.DoT, result.DoH} {
		if probe != nil && probe.Responded { return true }
	}
	return false
}

func anyAttempted(result Result) bool {
	for _, probe := range []*Probe{result.UDP, result.TCP, result.EDNS512, result.EDNS1232, result.TXT, result.DoT, result.DoH} {
		if probe != nil && probe.Attempted { return true }
	}
	return false
}


func deriveQuality(result *Result) {
	reliabilities := make([]float64, 0, 7)
	for _, probe := range []*Probe{result.UDP, result.TCP, result.EDNS512, result.EDNS1232, result.TXT, result.DoT, result.DoH} {
		if probe != nil && probe.Attempted {
			reliabilities = append(reliabilities, probe.Reliability)
		}
	}
	if len(reliabilities) > 0 {
		result.ReliabilityFloor = reliabilities[0]
		for _, value := range reliabilities[1:] {
			if value < result.ReliabilityFloor { result.ReliabilityFloor = value }
		}
	}
	result.Quality = "unknown"
	switch {
	case result.InterceptionSuspected:
		result.Quality = "suspicious"
		result.QualityReasons = append(result.QualityReasons, result.InterceptionReasons...)
	case result.QuorumTransportCount == 0:
		result.Quality = "unusable"
		result.QualityReasons = append(result.QualityReasons, "no-transport-met-quorum")
	case result.ReliabilityFloor < 0.5:
		result.Quality = "unstable"
		result.QualityReasons = append(result.QualityReasons, "low-reliability-floor")
	case result.EDNSDowngrade:
		result.Quality = "degraded"
		result.QualityReasons = append(result.QualityReasons, "edns-downgrade")
	case result.ClassicEncryptedAgree != nil && *result.ClassicEncryptedAgree && result.EncryptedDNS:
		result.Quality = "strong"
		result.QualityReasons = append(result.QualityReasons, "classic-encrypted-agreement")
	default:
		result.Quality = "usable"
	}
	if result.UDPAndTCPAgree != nil && !*result.UDPAndTCPAgree {
		result.QualityReasons = append(result.QualityReasons, "udp-tcp-divergence")
		if result.Quality == "usable" || result.Quality == "strong" {
			result.Quality = "degraded"
		}
	}
}
