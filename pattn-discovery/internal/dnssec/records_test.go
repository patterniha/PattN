package dnssec

import (
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestParseDS(t *testing.T) {
	record := dnswire.ResourceRecord{Type: dnswire.TypeDS, RawData: []byte{0x12, 0x34, 8, 2, 0xaa, 0xbb}}
	got, err := ParseDS(record)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyTag != 0x1234 || got.Algorithm != 8 || got.DigestType != 2 || got.Digest != "aabb" {
		t.Fatalf("got=%+v", got)
	}
}

func TestParseDNSKEYComputesKeyTag(t *testing.T) {
	record := dnswire.ResourceRecord{Type: dnswire.TypeDNSKEY, RawData: []byte{0x01, 0x01, 3, 8, 1, 2, 3, 4, 5}}
	got, err := ParseDNSKEY(record)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != 257 || got.Protocol != 3 || got.Algorithm != 8 || got.PublicKey == "" || got.KeyTag == 0 {
		t.Fatalf("got=%+v", got)
	}
}


func TestMatchedKeyRecordsRechecksExactDSDigestAcrossKeyTagCollision(t *testing.T) {
	const zone = "example.com"
	trustedRaw := []byte{0x01, 0x01, 3, 15, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	collidingRaw := append([]byte(nil), trustedRaw...)
	if !retagCollisionWithoutChangingTag(collidingRaw) {
		t.Fatal("could not construct deterministic DNSKEY key-tag collision")
	}
	if string(trustedRaw) == string(collidingRaw) || keyTag(trustedRaw) != keyTag(collidingRaw) {
		t.Fatalf("collision construction failed: trusted=%d colliding=%d", keyTag(trustedRaw), keyTag(collidingRaw))
	}

	digest, err := DNSKEYDigest(zone, trustedRaw, 2)
	if err != nil {
		t.Fatal(err)
	}
	tag := keyTag(trustedRaw)
	dsRaw := []byte{byte(tag >> 8), byte(tag), 15, 2}
	dsRaw = append(dsRaw, digest...)

	dsRecord := dnswire.ResourceRecord{Name: zone, Type: dnswire.TypeDS, Class: dnswire.ClassIN, RawData: dsRaw}
	trusted := dnswire.ResourceRecord{Name: zone, Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: trustedRaw}
	colliding := dnswire.ResourceRecord{Name: zone, Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: collidingRaw}

	validation := ValidateDelegation(zone, []dnswire.ResourceRecord{dsRecord}, []dnswire.ResourceRecord{trusted, colliding})
	if validation.Status != StatusMatch || len(validation.Matches) != 1 {
		t.Fatalf("validation=%+v", validation)
	}

	matched := MatchedKeyRecords(validation, []dnswire.ResourceRecord{trusted, colliding})
	if len(matched) != 1 || string(matched[0].RawData) != string(trustedRaw) {
		t.Fatalf("matched=%+v", matched)
	}
}
