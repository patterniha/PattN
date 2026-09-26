package dnssecdiag

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/dnsmeasure"
	"pattn-discovery/internal/dnssec"
	"pattn-discovery/internal/dnstrace"
	"pattn-discovery/internal/dnswire"
)

func TestInspectSeparatesObservationFromDelegationVerdict(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	keyRaw := []byte{0x01, 0x01, 3, 8, 1, 2, 3, 4, 5, 6}
	keyRecord := dnswire.ResourceRecord{Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: keyRaw}
	key, err := dnssec.ParseDNSKEY(keyRecord)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dnssec.DNSKEYDigest("example.com", keyRaw, 2)
	if err != nil {
		t.Fatal(err)
	}
	dsRaw := []byte{byte(key.KeyTag >> 8), byte(key.KeyTag), key.Algorithm, 2}
	dsRaw = append(dsRaw, digest...)
	dsRecord := dnswire.ResourceRecord{Name: "example.com", Type: dnswire.TypeDS, Class: dnswire.ClassIN, RawData: dsRaw}

	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		records := []dnswire.ResourceRecord{}
		if qtype == dnswire.TypeDS {
			records = []dnswire.ResourceRecord{dsRecord}
		}
		if qtype == dnswire.TypeDNSKEY {
			records = []dnswire.ResourceRecord{keyRecord}
		}
		return dnsmeasure.Observation{
			Address: address, Domain: name, QueryType: qtype, Transport: transport,
			Header: dnswire.Header{QR: true, AA: true}, Answers: records,
		}, nil
	}

	result, err := Inspect(context.Background(), "example.com", dnstrace.Options{RootServers: []netip.Addr{root}, Exchange: exchange})
	if err != nil {
		t.Fatal(err)
	}
	if result.Validation.Status != dnssec.StatusMatch || len(result.Validation.Matches) != 1 {
		t.Fatalf("validation=%+v", result.Validation)
	}
	if len(result.DS.Hops) != 1 || len(result.DNSKEY.Hops) != 1 {
		t.Fatalf("ds=%+v dnskey=%+v", result.DS, result.DNSKEY)
	}
}


func TestInspectDoesNotTreatBareDSAbsenceAsAuthenticatedUnsignedDelegation(t *testing.T) {
	root := netip.MustParseAddr("192.0.2.1")
	exchange := func(_ context.Context, address netip.Addr, _ uint16, name string, qtype uint16, transport dnsmeasure.Transport, _ time.Duration, _ bool) (dnsmeasure.Observation, error) {
		return dnsmeasure.Observation{
			Address: address,
			Domain: name,
			QueryType: qtype,
			Transport: transport,
			Header: dnswire.Header{QR: true, AA: true},
		}, nil
	}

	result, err := Inspect(context.Background(), "example.com", dnstrace.Options{
		RootServers: []netip.Addr{root},
		Exchange: exchange,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Validation.Status != dnssec.StatusUnsigned {
		t.Fatalf("delegation observation=%+v", result.Validation)
	}
	if result.AuthenticationStatus != AuthNoDSObserved {
		t.Fatalf("authentication status=%q", result.AuthenticationStatus)
	}
}
