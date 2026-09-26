package dnsfixture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnstrace"
)

const ExchangeBundleVersion = 1

type ExchangeBundle struct {
	Version     int                  `json:"version"`
	RootServers []string             `json:"rootServers"`
	Port        uint16               `json:"port,omitempty"`
	Exchanges   []ExchangeBundleStep `json:"exchanges"`
}

type ExchangeBundleStep struct {
	Address          string               `json:"address"`
	Port             uint16               `json:"port,omitempty"`
	Domain           string               `json:"domain"`
	QueryType        uint16               `json:"queryType"`
	Transport        dnsmeasure.Transport `json:"transport"`
	RecursionDesired bool                 `json:"recursionDesired"`
	Fixture          string               `json:"fixture"`
	LatencyMs        int                  `json:"latencyMs,omitempty"`
}

type BundleRuntime struct {
	bundle   ExchangeBundle
	fixtures map[string]Fixture
}

func LoadExchangeBundle(path string) (*BundleRuntime, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle ExchangeBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("decode dns exchange bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}

	base := filepath.Dir(path)
	runtime := &BundleRuntime{
		bundle: bundle,
		fixtures: make(map[string]Fixture, len(bundle.Exchanges)),
	}
	for _, step := range bundle.Exchanges {
		fixturePath := filepath.Join(base, filepath.Clean(step.Fixture))
		fixture, err := Load(fixturePath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", step.Fixture, err)
		}
		if !equalDNSName(fixture.QueryName, step.Domain) || fixture.QueryType != step.QueryType {
			return nil, fmt.Errorf("%s: fixture query metadata does not match exchange step", step.Fixture)
		}
		runtime.fixtures[exchangeKey(step.Address, effectivePort(step.Port, bundle.Port), step.Domain, step.QueryType, step.Transport, step.RecursionDesired)] = fixture
	}
	return runtime, nil
}

func (b ExchangeBundle) Validate() error {
	if b.Version != ExchangeBundleVersion {
		return fmt.Errorf("unsupported dns exchange bundle version %d", b.Version)
	}
	if len(b.RootServers) == 0 {
		return fmt.Errorf("dns exchange bundle requires at least one root server")
	}
	for _, raw := range b.RootServers {
		if _, err := netip.ParseAddr(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid root server %q", raw)
		}
	}
	if len(b.Exchanges) == 0 {
		return fmt.Errorf("dns exchange bundle requires at least one exchange")
	}

	seen := map[string]bool{}
	for i, step := range b.Exchanges {
		if _, err := netip.ParseAddr(strings.TrimSpace(step.Address)); err != nil {
			return fmt.Errorf("exchange %d has invalid address %q", i, step.Address)
		}
		if strings.TrimSpace(step.Domain) == "" || step.QueryType == 0 {
			return fmt.Errorf("exchange %d requires domain and queryType", i)
		}
		if step.Transport != dnsmeasure.UDP && step.Transport != dnsmeasure.TCP {
			return fmt.Errorf("exchange %d has unsupported transport %q", i, step.Transport)
		}
		if step.LatencyMs < 0 {
			return fmt.Errorf("exchange %d has negative latencyMs", i)
		}
		if unsafeRelativePath(step.Fixture) {
			return fmt.Errorf("exchange %d has unsafe fixture path %q", i, step.Fixture)
		}
		port := effectivePort(step.Port, b.Port)
		key := exchangeKey(step.Address, port, step.Domain, step.QueryType, step.Transport, step.RecursionDesired)
		if seen[key] {
			return fmt.Errorf("duplicate dns exchange bundle step %s", key)
		}
		seen[key] = true
	}
	return nil
}

func (r *BundleRuntime) TraceOptions() (dnstrace.Options, error) {
	roots := make([]netip.Addr, 0, len(r.bundle.RootServers))
	for _, raw := range r.bundle.RootServers {
		value, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return dnstrace.Options{}, err
		}
		roots = append(roots, value.Unmap())
	}
	return dnstrace.Options{
		RootServers: roots,
		Port: effectivePort(0, r.bundle.Port),
		Timeout: time.Second,
		MaxHops: 64,
		MaxNSDepth: 8,
		Exchange: r.Exchange,
	}, nil
}

func (r *BundleRuntime) Exchange(
	ctx context.Context,
	address netip.Addr,
	port uint16,
	domain string,
	qtype uint16,
	transport dnsmeasure.Transport,
	timeout time.Duration,
	recursionDesired bool,
) (dnsmeasure.Observation, error) {
	if err := ctx.Err(); err != nil {
		return dnsmeasure.Observation{}, err
	}
	key := exchangeKey(address.String(), port, domain, qtype, transport, recursionDesired)
	fixture, ok := r.fixtures[key]
	if !ok {
		return dnsmeasure.Observation{}, fmt.Errorf("dns exchange fixture not found for %s", key)
	}
	message, err := fixture.Replay()
	if err != nil {
		return dnsmeasure.Observation{}, err
	}

	var answerIPs []netip.Addr
	for _, record := range message.Answers {
		if record.Address.IsValid() {
			answerIPs = append(answerIPs, record.Address.Unmap())
		}
	}

	latencyMs := 1
	for _, step := range r.bundle.Exchanges {
		if exchangeKey(step.Address, effectivePort(step.Port, r.bundle.Port), step.Domain, step.QueryType, step.Transport, step.RecursionDesired) == key {
			if step.LatencyMs > 0 {
				latencyMs = step.LatencyMs
			}
			break
		}
	}

	return dnsmeasure.Observation{
		Address: address.Unmap(),
		Port: port,
		Domain: domain,
		QueryType: qtype,
		Transport: transport,
		Latency: time.Duration(latencyMs) * time.Millisecond,
		Header: message.Header,
		AnswerIPs: answerIPs,
		Answers: message.Answers,
		Authorities: message.Authorities,
		Additionals: message.Additionals,
	}, nil
}

func exchangeKey(
	address string,
	port uint16,
	domain string,
	qtype uint16,
	transport dnsmeasure.Transport,
	recursionDesired bool,
) string {
	return strings.ToLower(strings.TrimSpace(address)) + "|" +
		strconv.Itoa(int(port)) + "|" +
		normalizeDNSName(domain) + "|" +
		strconv.Itoa(int(qtype)) + "|" +
		string(transport) + "|" +
		strconv.FormatBool(recursionDesired)
}

func effectivePort(stepPort, bundlePort uint16) uint16 {
	if stepPort != 0 {
		return stepPort
	}
	if bundlePort != 0 {
		return bundlePort
	}
	return 53
}

func unsafeRelativePath(value string) bool {
	clean := filepath.Clean(strings.TrimSpace(value))
	return clean == "." || clean == "" || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..")
}

func normalizeDNSName(value string) string {
	value = strings.TrimSpace(value)
	if value == "." {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

func equalDNSName(left, right string) bool {
	return normalizeDNSName(left) == normalizeDNSName(right)
}
