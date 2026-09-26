package dnssec

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	"pattn-discovery/internal/dnswire"
)

func TestParseRRSIG(t *testing.T) {
	rdata := make([]byte, 0)
	rdata = binary.BigEndian.AppendUint16(rdata, dnswire.TypeDNSKEY)
	rdata = append(rdata, 15, 2)
	rdata = binary.BigEndian.AppendUint32(rdata, 3600)
	rdata = binary.BigEndian.AppendUint32(rdata, 200)
	rdata = binary.BigEndian.AppendUint32(rdata, 100)
	rdata = binary.BigEndian.AppendUint16(rdata, 1234)
	rdata = append(rdata, 0x07)
	rdata = append(rdata, []byte("example")...)
	rdata = append(rdata, 0x03)
	rdata = append(rdata, []byte("com")...)
	rdata = append(rdata, 0)
	rdata = append(rdata, make([]byte, 64)...)
	got, err := ParseRRSIG(dnswire.ResourceRecord{Type: dnswire.TypeRRSIG, RawData: rdata})
	if err != nil {
		t.Fatal(err)
	}
	if got.TypeCovered != dnswire.TypeDNSKEY || got.Algorithm != 15 || got.SignerName != "example.com" || got.KeyTag != 1234 {
		t.Fatalf("got=%+v", got)
	}
}

func TestValidateDNSKEYRRSetEd25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyRData := []byte{0x01, 0x01, 3, 15}
	keyRData = append(keyRData, publicKey...)
	keyRecord := dnswire.ResourceRecord{Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, TTL: 3600, RawData: keyRData}
	key, err := ParseDNSKEY(keyRecord)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{
		TypeCovered: dnswire.TypeDNSKEY,
		Algorithm: 15,
		Labels: 2,
		OriginalTTL: 3600,
		Expiration: 2000,
		Inception: 500,
		KeyTag: key.KeyTag,
		SignerName: "example.com",
	}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)
	signed, err := signedDNSKEYData("example.com", sig, []dnswire.ResourceRecord{keyRecord})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, signed)
	rdata := append([]byte(nil), sig.rawPrefix...)
	signer, _ := canonicalNameWire(sig.SignerName)
	rdata = append(rdata, signer...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{Name: "example.com", Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN, TTL: 3600, RawData: rdata}

	results := ValidateDNSKEYRRSet("example.com", []dnswire.ResourceRecord{keyRecord, sigRecord}, now)
	if len(results) != 1 || results[0].Status != SignatureValid {
		t.Fatalf("results=%+v", results)
	}
}


func TestSignatureTimeStatusUsesSerialArithmeticAcrossUint32Wrap(t *testing.T) {
	inception := uint32(0xfffffff0)
	expiration := uint32(0x00000020)

	cases := []struct {
		name string
		now  int64
		want string
	}{
		{name: "before-inception", now: int64(uint32(0xffffffe0)), want: SignatureNotYetValid},
		{name: "before-wrap-valid", now: int64(uint32(0xfffffff8)), want: SignatureValid},
		{name: "after-wrap-valid", now: int64(uint32(0x00000010)), want: SignatureValid},
		{name: "after-expiration", now: int64(uint32(0x00000030)), want: SignatureExpired},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := signatureTimeStatus(inception, expiration, time.Unix(test.now, 0))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("status=%q want %q", got, test.want)
			}
		})
	}
}

func TestSignatureTimeStatusRejectsUndefinedHalfRangeComparison(t *testing.T) {
	status, err := signatureTimeStatus(0, serialHalfRange, time.Unix(1, 0))
	if status != SignatureInvalid || err == nil {
		t.Fatalf("status=%q err=%v", status, err)
	}
}


func TestValidateDNSKEYRRSetWithKeysDoesNotConfuseCollidingKeyTag(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	attackerRaw := []byte{0x01, 0x01, 3, 15}
	attackerRaw = append(attackerRaw, publicKey...)
	trustedRaw := append([]byte(nil), attackerRaw...)
	if !retagCollisionWithoutChangingTag(trustedRaw) {
		t.Fatal("could not construct deterministic DNSKEY key-tag collision")
	}
	if string(trustedRaw) == string(attackerRaw) || keyTag(trustedRaw) != keyTag(attackerRaw) {
		t.Fatalf("collision construction failed: trusted=%d attacker=%d", keyTag(trustedRaw), keyTag(attackerRaw))
	}

	const zone = "example.com"
	trustedRecord := dnswire.ResourceRecord{
		Name: zone, Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, TTL: 3600, RawData: trustedRaw,
	}
	attackerRecord := dnswire.ResourceRecord{
		Name: zone, Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, TTL: 3600, RawData: attackerRaw,
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{
		TypeCovered: dnswire.TypeDNSKEY,
		Algorithm: 15,
		Labels: 2,
		OriginalTTL: 3600,
		Expiration: 2000,
		Inception: 500,
		KeyTag: keyTag(attackerRaw),
		SignerName: zone,
	}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)

	rrset := []dnswire.ResourceRecord{trustedRecord, attackerRecord}
	signed, err := signedDNSKEYData(zone, sig, rrset)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, signed)
	rdata := append([]byte(nil), sig.rawPrefix...)
	signer, _ := canonicalNameWire(sig.SignerName)
	rdata = append(rdata, signer...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{
		Name: zone, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN, TTL: 3600, RawData: rdata,
	}
	records := []dnswire.ResourceRecord{trustedRecord, attackerRecord, sigRecord}

	diagnostic := ValidateDNSKEYRRSet(zone, records, now)
	if len(diagnostic) != 1 || diagnostic[0].Status != SignatureValid {
		t.Fatalf("diagnostic validation should try every colliding candidate: %+v", diagnostic)
	}

	trustedOnly := ValidateDNSKEYRRSetWithKeys(zone, records, []dnswire.ResourceRecord{trustedRecord}, now)
	if len(trustedOnly) != 1 || trustedOnly[0].Status == SignatureValid {
		t.Fatalf("untrusted colliding key authenticated DNSKEY RRset: %+v", trustedOnly)
	}
}

func TestValidateDNSKEYRRSetWithKeysRejectsNonZoneKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte{0x00, 0x01, 3, 15} // Zone Key flag intentionally clear.
	raw = append(raw, publicKey...)
	record := dnswire.ResourceRecord{
		Name: "example.com", Type: dnswire.TypeDNSKEY, Class: dnswire.ClassIN, TTL: 3600, RawData: raw,
	}
	now := time.Unix(1000, 0)
	sig := RRSIG{
		TypeCovered: dnswire.TypeDNSKEY,
		Algorithm: 15,
		Labels: 2,
		OriginalTTL: 3600,
		Expiration: 2000,
		Inception: 500,
		KeyTag: keyTag(raw),
		SignerName: "example.com",
	}
	sig.rawPrefix = make([]byte, 18)
	binary.BigEndian.PutUint16(sig.rawPrefix[0:2], sig.TypeCovered)
	sig.rawPrefix[2] = sig.Algorithm
	sig.rawPrefix[3] = sig.Labels
	binary.BigEndian.PutUint32(sig.rawPrefix[4:8], sig.OriginalTTL)
	binary.BigEndian.PutUint32(sig.rawPrefix[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(sig.rawPrefix[12:16], sig.Inception)
	binary.BigEndian.PutUint16(sig.rawPrefix[16:18], sig.KeyTag)
	signed, err := signedDNSKEYData(sig.SignerName, sig, []dnswire.ResourceRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, signed)
	rdata := append([]byte(nil), sig.rawPrefix...)
	signer, _ := canonicalNameWire(sig.SignerName)
	rdata = append(rdata, signer...)
	rdata = append(rdata, signature...)
	sigRecord := dnswire.ResourceRecord{
		Name: sig.SignerName, Type: dnswire.TypeRRSIG, Class: dnswire.ClassIN, TTL: 3600, RawData: rdata,
	}

	results := ValidateDNSKEYRRSetWithKeys(
		sig.SignerName,
		[]dnswire.ResourceRecord{record, sigRecord},
		[]dnswire.ResourceRecord{record},
		now)
	if len(results) != 1 || results[0].Status != SignatureNoKey {
		t.Fatalf("non-zone DNSKEY was used for RRSIG verification: %+v", results)
	}
}

func retagCollisionWithoutChangingTag(rdata []byte) bool {
	for first := 4; first+3 < len(rdata); first += 2 {
		left := binary.BigEndian.Uint16(rdata[first : first+2])
		right := binary.BigEndian.Uint16(rdata[first+2 : first+4])
		if left < 0xffff && right > 0 {
			binary.BigEndian.PutUint16(rdata[first:first+2], left+1)
			binary.BigEndian.PutUint16(rdata[first+2:first+4], right-1)
			return true
		}
		if left > 0 && right < 0xffff {
			binary.BigEndian.PutUint16(rdata[first:first+2], left-1)
			binary.BigEndian.PutUint16(rdata[first+2:first+4], right+1)
			return true
		}
	}
	return false
}
