package dnssec

import (
	"crypto/ed25519"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"pattn-discovery/internal/dnswire"
)

func TestValidateRRSetAuthenticatesSignedARecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyRData := []byte{0x01, 0x01, 3, 15}
	keyRData = append(keyRData, pub...)
	keyRecord := dnswire.ResourceRecord{Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: keyRData, CanonicalRData: keyRData}
	key, _ := ParseDNSKEY(keyRecord)

	aRaw := []byte{203, 0, 113, 7}
	answer := dnswire.ResourceRecord{
		Name: "www.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 300,
		Address: netip.MustParseAddr("203.0.113.7"), RawData: aRaw, CanonicalRData: aRaw,
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{TypeCovered: dnswire.TypeA, Algorithm: 15, Labels: 3, OriginalTTL: 300, Expiration: 2000, Inception: 500, KeyTag: key.KeyTag, SignerName: "example.com"}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)

	signed, err := signedRRSetData(answer.Name, dnswire.TypeA, sig, []dnswire.ResourceRecord{answer})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, signed)
	signer, _ := canonicalNameWire(sig.SignerName)
	rdata := append([]byte(nil), sig.rawPrefix...)
	rdata = append(rdata, signer...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{Name: answer.Name, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN, RawData: rdata, CanonicalRData: rdata}

	got := ValidateRRSet(answer.Name, dnswire.TypeA, []dnswire.ResourceRecord{answer, sigRecord}, []dnswire.ResourceRecord{keyRecord}, now)
	if len(got) != 1 || got[0].Status != SignatureValid {
		t.Fatalf("got=%+v", got)
	}

	crossZoneKey := keyRecord
	crossZoneKey.Name = "attacker.example"
	crossZone := ValidateRRSet(
		answer.Name,
		dnswire.TypeA,
		[]dnswire.ResourceRecord{answer, sigRecord},
		[]dnswire.ResourceRecord{crossZoneKey},
		now)
	if len(crossZone) != 1 || crossZone[0].Status != SignatureNoKey {
		t.Fatalf("cross-zone DNSKEY authenticated RRset: %+v", crossZone)
	}
}

func TestWildcardOwner(t *testing.T) {
	got, err := wildcardOwner("a.b.example.com", 2)
	if err != nil || got != "*.example.com" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}


func TestValidateRRSetTriesEveryCollidingKeyCandidate(t *testing.T) {
	signerPublic, signerPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerRaw := []byte{0x01, 0x01, 3, 15}
	signerRaw = append(signerRaw, signerPublic...)

	otherRaw := append([]byte(nil), signerRaw...)
	if !retagCollisionWithoutChangingTag(otherRaw) {
		t.Fatal("could not construct deterministic DNSKEY key-tag collision")
	}
	if keyTag(otherRaw) != keyTag(signerRaw) || string(otherRaw) == string(signerRaw) {
		t.Fatal("failed to construct distinct colliding DNSKEY")
	}

	other := dnswire.ResourceRecord{
		Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: otherRaw,
	}
	signer := dnswire.ResourceRecord{
		Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: signerRaw,
	}
	answer := dnswire.ResourceRecord{
		Name: "www.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 300,
		Address: netip.MustParseAddr("203.0.113.8"),
		RawData: []byte{203, 0, 113, 8}, CanonicalRData: []byte{203, 0, 113, 8},
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{
		TypeCovered: dnswire.TypeA, Algorithm: 15, Labels: 3, OriginalTTL: 300,
		Expiration: 2000, Inception: 500, KeyTag: keyTag(signerRaw), SignerName: "example.com",
	}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)

	signed, err := signedRRSetData(answer.Name, dnswire.TypeA, sig, []dnswire.ResourceRecord{answer})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(signerPrivate, signed)
	signerName, _ := canonicalNameWire(sig.SignerName)
	rdata := append([]byte(nil), sig.rawPrefix...)
	rdata = append(rdata, signerName...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{
		Name: answer.Name, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN,
		RawData: rdata, CanonicalRData: rdata,
	}

	got := ValidateRRSet(
		answer.Name,
		dnswire.TypeA,
		[]dnswire.ResourceRecord{answer, sigRecord},
		[]dnswire.ResourceRecord{other, signer},
		now)
	if len(got) != 1 || got[0].Status != SignatureValid {
		t.Fatalf("colliding first key prevented valid signature: %+v", got)
	}
}

func TestValidateRRSetRejectsNonZoneVerificationKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyRaw := []byte{0x00, 0x01, 3, 15}
	keyRaw = append(keyRaw, pub...)
	keyRecord := dnswire.ResourceRecord{
		Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, RawData: keyRaw,
	}
	answer := dnswire.ResourceRecord{
		Name: "www.example.com", Type: dnswire.TypeA, Class: dnswire.ClassIN, TTL: 300,
		Address: netip.MustParseAddr("203.0.113.9"),
		RawData: []byte{203, 0, 113, 9}, CanonicalRData: []byte{203, 0, 113, 9},
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{
		TypeCovered: dnswire.TypeA, Algorithm: 15, Labels: 3, OriginalTTL: 300,
		Expiration: 2000, Inception: 500, KeyTag: keyTag(keyRaw), SignerName: "example.com",
	}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)

	signed, err := signedRRSetData(answer.Name, dnswire.TypeA, sig, []dnswire.ResourceRecord{answer})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, signed)
	signerName, _ := canonicalNameWire(sig.SignerName)
	rdata := append([]byte(nil), sig.rawPrefix...)
	rdata = append(rdata, signerName...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{
		Name: answer.Name, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN,
		RawData: rdata, CanonicalRData: rdata,
	}

	got := ValidateRRSet(
		answer.Name,
		dnswire.TypeA,
		[]dnswire.ResourceRecord{answer, sigRecord},
		[]dnswire.ResourceRecord{keyRecord},
		now)
	if len(got) != 1 || got[0].Status != SignatureNoKey {
		t.Fatalf("non-zone DNSKEY verified ordinary RRset: %+v", got)
	}
}
