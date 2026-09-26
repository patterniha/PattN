package dnssec

import (
	"encoding/hex"
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestValidateDelegationMatchesSHA256DS(t *testing.T) {
	keyRaw := []byte{0x01, 0x01, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	keyRecord := dnswire.ResourceRecord{Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: keyRaw}
	key, err := ParseDNSKEY(keyRecord)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DNSKEYDigest("Example.COM.", keyRaw, 2)
	if err != nil {
		t.Fatal(err)
	}
	dsRaw := []byte{byte(key.KeyTag >> 8), byte(key.KeyTag), key.Algorithm, 2}
	dsRaw = append(dsRaw, digest...)
	dsRecord := dnswire.ResourceRecord{Type: dnswire.TypeDS, Class: dnswire.ClassIN, RawData: dsRaw}

	result := ValidateDelegation("example.com", []dnswire.ResourceRecord{dsRecord}, []dnswire.ResourceRecord{keyRecord})
	if result.Status != StatusMatch || len(result.Matches) != 1 || result.SupportedDSCount != 1 {
		t.Fatalf("result=%+v digest=%s", result, hex.EncodeToString(digest))
	}
}

func TestValidateDelegationDistinguishesUnsignedMissingAndMismatch(t *testing.T) {
	if got := ValidateDelegation("example.com", nil, nil); got.Status != StatusUnsigned {
		t.Fatalf("unsigned=%+v", got)
	}
	ds := dnswire.ResourceRecord{Type: dnswire.TypeDS, RawData: []byte{0, 1, 8, 2, 1, 2, 3}}
	if got := ValidateDelegation("example.com", []dnswire.ResourceRecord{ds}, nil); got.Status != StatusMissingDNSKEY {
		t.Fatalf("missing key=%+v", got)
	}
	key := dnswire.ResourceRecord{Type: dnswire.TypeDNSKEY, RawData: []byte{0x01, 0x01, 3, 8, 9, 9, 9}}
	parsed, _ := ParseDNSKEY(key)
	ds.RawData[0] = byte(parsed.KeyTag >> 8)
	ds.RawData[1] = byte(parsed.KeyTag)
	if got := ValidateDelegation("example.com", []dnswire.ResourceRecord{ds}, []dnswire.ResourceRecord{key}); got.Status != StatusMismatch {
		t.Fatalf("mismatch=%+v", got)
	}
}
