package dnssec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnswire"
)

type RRSIG struct {
	TypeCovered uint16 `json:"typeCovered"`
	Algorithm   uint8  `json:"algorithm"`
	Labels      uint8  `json:"labels"`
	OriginalTTL uint32 `json:"originalTtl"`
	Expiration  uint32 `json:"expiration"`
	Inception   uint32 `json:"inception"`
	KeyTag      uint16 `json:"keyTag"`
	SignerName  string `json:"signerName"`
	Signature   string `json:"signature"`
	rawSignature []byte
	rawPrefix    []byte
}

type SignatureValidation struct {
	TypeCovered uint16 `json:"typeCovered"`
	Algorithm   uint8  `json:"algorithm"`
	KeyTag      uint16 `json:"keyTag"`
	SignerName  string `json:"signerName"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

const (
	SignatureValid       = "valid"
	SignatureExpired     = "expired"
	SignatureNotYetValid = "not-yet-valid"
	SignatureNoKey       = "no-matching-key"
	SignatureUnsupported = "unsupported-algorithm"
	SignatureInvalid     = "invalid"
)

func ParseRRSIG(record dnswire.ResourceRecord) (RRSIG, error) {
	if record.Type != dnswire.TypeRRSIG {
		return RRSIG{}, fmt.Errorf("record type %d is not RRSIG", record.Type)
	}
	if len(record.RawData) < 19 {
		return RRSIG{}, fmt.Errorf("RRSIG rdata too short: %d", len(record.RawData))
	}
	signer, next, err := parseUncompressedName(record.RawData, 18)
	if err != nil {
		return RRSIG{}, err
	}
	if next >= len(record.RawData) {
		return RRSIG{}, fmt.Errorf("RRSIG has empty signature")
	}
	return RRSIG{
		TypeCovered: binary.BigEndian.Uint16(record.RawData[0:2]),
		Algorithm: record.RawData[2],
		Labels: record.RawData[3],
		OriginalTTL: binary.BigEndian.Uint32(record.RawData[4:8]),
		Expiration: binary.BigEndian.Uint32(record.RawData[8:12]),
		Inception: binary.BigEndian.Uint32(record.RawData[12:16]),
		KeyTag: binary.BigEndian.Uint16(record.RawData[16:18]),
		SignerName: normalizeName(signer),
		Signature: base64.StdEncoding.EncodeToString(record.RawData[next:]),
		rawSignature: append([]byte(nil), record.RawData[next:]...),
		rawPrefix: append([]byte(nil), record.RawData[:18]...),
	}, nil
}

func ValidateDNSKEYRRSet(zone string, records []dnswire.ResourceRecord, now time.Time) []SignatureValidation {
	return ValidateDNSKEYRRSetWithKeys(zone, records, records, now)
}

// ValidateDNSKEYRRSetWithKeys validates signatures over the complete DNSKEY RRset,
// but only permits verificationKeys to authenticate it. This distinction matters
// because DNSSEC key tags are selection hints, not unique key identities.
func ValidateDNSKEYRRSetWithKeys(
	zone string,
	records []dnswire.ResourceRecord,
	verificationKeys []dnswire.ResourceRecord,
	now time.Time,
) []SignatureValidation {
	var rrset []dnswire.ResourceRecord
	var signatures []dnswire.ResourceRecord
	for _, record := range records {
		switch record.Type {
		case dnswire.TypeDNSKEY:
			rrset = append(rrset, record)
		case dnswire.TypeRRSIG:
			signature, err := ParseRRSIG(record)
			if err == nil && signature.TypeCovered == dnswire.TypeDNSKEY {
				signatures = append(signatures, record)
			}
		}
	}

	keys := make([]dnswire.ResourceRecord, 0, len(verificationKeys))
	for _, record := range verificationKeys {
		if record.Type == dnswire.TypeDNSKEY {
			keys = append(keys, record)
		}
	}

	out := make([]SignatureValidation, 0, len(signatures))
	for _, record := range signatures {
		sig, err := ParseRRSIG(record)
		if err != nil {
			out = append(out, SignatureValidation{Status: SignatureInvalid, Error: err.Error()})
			continue
		}
		item := SignatureValidation{
			TypeCovered: sig.TypeCovered,
			Algorithm:   sig.Algorithm,
			KeyTag:      sig.KeyTag,
			SignerName:  sig.SignerName,
		}
		if status, err := signatureTimeStatus(sig.Inception, sig.Expiration, now); status != SignatureValid {
			item.Status = status
			if err != nil {
				item.Error = err.Error()
			}
			out = append(out, item)
			continue
		}

		signed, err := signedDNSKEYData(zone, sig, rrset)
		if err != nil {
			item.Status = SignatureInvalid
			item.Error = err.Error()
			out = append(out, item)
			continue
		}

		matched := false
		supported := false
		valid := false
		var verifyErr error
		for i := range keys {
			parsed, parseErr := ParseDNSKEY(keys[i])
			if parseErr != nil ||
				parsed.KeyTag != sig.KeyTag ||
				parsed.Algorithm != sig.Algorithm ||
				parsed.Protocol != 3 ||
				parsed.Flags&0x0100 == 0 {
				continue
			}
			matched = true
			candidateSupported, candidateValid, candidateErr := verifySignature(
				sig.Algorithm,
				keys[i].RawData,
				signed,
				sig.rawSignature)
			supported = supported || candidateSupported
			if candidateValid {
				valid = true
				verifyErr = nil
				break
			}
			if candidateErr != nil {
				verifyErr = candidateErr
			}
		}

		switch {
		case !matched:
			item.Status = SignatureNoKey
		case valid:
			item.Status = SignatureValid
		case !supported:
			item.Status = SignatureUnsupported
		default:
			item.Status = SignatureInvalid
			if verifyErr != nil {
				item.Error = verifyErr.Error()
			}
		}
		out = append(out, item)
	}
	return out
}

const serialHalfRange uint32 = 1 << 31

// signatureTimeStatus applies RFC 1982 serial-number arithmetic to the 32-bit
// RRSIG inception/expiration fields as required by RFC 4034 section 3.1.5.
func signatureTimeStatus(inception, expiration uint32, now time.Time) (string, error) {
	if inception != expiration {
		forward, defined := serialLess(inception, expiration)
		if !defined || !forward {
			return SignatureInvalid, fmt.Errorf("RRSIG validity interval exceeds the 32-bit serial half-range")
		}
	}

	current := uint32(now.Unix())
	beforeInception, defined := serialLess(current, inception)
	if !defined {
		return SignatureInvalid, fmt.Errorf("RRSIG inception comparison is undefined in 32-bit serial arithmetic")
	}
	if beforeInception {
		return SignatureNotYetValid, nil
	}

	afterExpiration, defined := serialLess(expiration, current)
	if !defined {
		return SignatureInvalid, fmt.Errorf("RRSIG expiration comparison is undefined in 32-bit serial arithmetic")
	}
	if afterExpiration {
		return SignatureExpired, nil
	}
	return SignatureValid, nil
}

// serialLess compares 32-bit DNS serial values. The pair exactly half a serial
// space apart is intentionally reported as undefined per RFC 1982.
func serialLess(left, right uint32) (less bool, defined bool) {
	if left == right {
		return false, true
	}
	delta := right - left
	if delta == serialHalfRange {
		return false, false
	}
	return delta < serialHalfRange, true
}

func signedDNSKEYData(zone string, sig RRSIG, rrset []dnswire.ResourceRecord) ([]byte, error) {
	signerWire, err := canonicalNameWire(sig.SignerName)
	if err != nil {
		return nil, err
	}
	prefix := append([]byte(nil), sig.rawPrefix...)
	prefix = append(prefix, signerWire...)

	owner := normalizeName(zone)
	labels := uint8(0)
	if owner != "" {
		labels = uint8(len(strings.Split(owner, ".")))
	}
	if sig.Labels > labels {
		return nil, fmt.Errorf("RRSIG labels %d exceeds owner labels %d", sig.Labels, labels)
	}
	if sig.Labels < labels {
		parts := strings.Split(owner, ".")
		owner = "*." + strings.Join(parts[len(parts)-int(sig.Labels):], ".")
	}
	ownerWire, err := canonicalNameWire(owner)
	if err != nil {
		return nil, err
	}

	var canonical [][]byte
	for _, record := range rrset {
		if record.Type != dnswire.TypeDNSKEY {
			continue
		}
		rr := append([]byte(nil), ownerWire...)
		rr = binary.BigEndian.AppendUint16(rr, dnswire.TypeDNSKEY)
		rr = binary.BigEndian.AppendUint16(rr, dnswire.ClassIN)
		rr = binary.BigEndian.AppendUint32(rr, sig.OriginalTTL)
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(record.RawData)))
		rr = append(rr, record.RawData...)
		canonical = append(canonical, rr)
	}
	if len(canonical) == 0 {
		return nil, fmt.Errorf("DNSKEY RRset is empty")
	}
	sort.Slice(canonical, func(i, j int) bool { return bytes.Compare(canonical[i], canonical[j]) < 0 })
	out := prefix
	for _, rr := range canonical {
		out = append(out, rr...)
	}
	return out, nil
}

func verifySignature(algorithm uint8, dnskeyRData, signed, signature []byte) (bool, bool, error) {
	if len(dnskeyRData) < 4 {
		return true, false, fmt.Errorf("DNSKEY rdata too short")
	}
	keyData := dnskeyRData[4:]
	switch algorithm {
	case 8, 10:
		pub, err := parseRSAKey(keyData)
		if err != nil {
			return true, false, err
		}
		var hash crypto.Hash
		var digest []byte
		if algorithm == 8 {
			sum := sha256.Sum256(signed)
			digest = sum[:]
			hash = crypto.SHA256
		} else {
			sum := sha512.Sum512(signed)
			digest = sum[:]
			hash = crypto.SHA512
		}
		err = rsa.VerifyPKCS1v15(pub, hash, digest, signature)
		return true, err == nil, err
	case 13:
		if len(keyData) != 64 || len(signature) != 64 {
			return true, false, fmt.Errorf("invalid ECDSA P-256 key/signature length")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(keyData[:32]), Y: new(big.Int).SetBytes(keyData[32:])}
		sum := sha256.Sum256(signed)
		valid := ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
		return true, valid, nil
	case 14:
		if len(keyData) != 96 || len(signature) != 96 {
			return true, false, fmt.Errorf("invalid ECDSA P-384 key/signature length")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: new(big.Int).SetBytes(keyData[:48]), Y: new(big.Int).SetBytes(keyData[48:])}
		sum := sha512.Sum384(signed)
		valid := ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(signature[:48]), new(big.Int).SetBytes(signature[48:]))
		return true, valid, nil
	case 15:
		if len(keyData) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
			return true, false, fmt.Errorf("invalid Ed25519 key/signature length")
		}
		return true, ed25519.Verify(ed25519.PublicKey(keyData), signed, signature), nil
	default:
		return false, false, nil
	}
}

func parseRSAKey(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("RSA DNSKEY too short")
	}
	offset := 1
	exponentLength := int(data[0])
	if exponentLength == 0 {
		if len(data) < 3 {
			return nil, fmt.Errorf("RSA DNSKEY exponent length truncated")
		}
		exponentLength = int(binary.BigEndian.Uint16(data[1:3]))
		offset = 3
	}
	if exponentLength <= 0 || offset+exponentLength >= len(data) {
		return nil, fmt.Errorf("invalid RSA DNSKEY exponent length")
	}
	exponent := new(big.Int).SetBytes(data[offset : offset+exponentLength])
	if !exponent.IsInt64() || exponent.Int64() <= 1 || exponent.Int64() > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	modulus := new(big.Int).SetBytes(data[offset+exponentLength:])
	if modulus.Sign() <= 0 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

func parseUncompressedName(data []byte, offset int) (string, int, error) {
	var labels []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("truncated DNS name")
		}
		length := int(data[offset])
		offset++
		if length == 0 {
			return strings.Join(labels, "."), offset, nil
		}
		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("compressed RRSIG signer name is not supported")
		}
		if length > 63 || offset+length > len(data) {
			return "", 0, fmt.Errorf("invalid DNS label in RRSIG")
		}
		labels = append(labels, strings.ToLower(string(data[offset:offset+length])))
		offset += length
	}
}
