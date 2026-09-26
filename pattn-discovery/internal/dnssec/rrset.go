package dnssec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"

	"pattn-discovery/internal/dnswire"
)

func ValidateRRSet(owner string, rrType uint16, records, trustedKeys []dnswire.ResourceRecord, now time.Time) []SignatureValidation {
	owner = normalizeName(owner)
	var rrset []dnswire.ResourceRecord
	var signatures []dnswire.ResourceRecord
	for _, record := range records {
		if normalizeName(record.Name) != owner {
			continue
		}
		switch record.Type {
		case rrType:
			rrset = append(rrset, record)
		case dnswire.TypeRRSIG:
			signature, err := ParseRRSIG(record)
			if err == nil && signature.TypeCovered == rrType {
				signatures = append(signatures, record)
			}
		}
	}
	out := make([]SignatureValidation, 0, len(signatures))
	for _, record := range signatures {
		sig, err := ParseRRSIG(record)
		if err != nil {
			out = append(out, SignatureValidation{TypeCovered: rrType, Status: SignatureInvalid, Error: err.Error()})
			continue
		}
		item := SignatureValidation{
			TypeCovered: sig.TypeCovered,
			Algorithm: sig.Algorithm,
			KeyTag: sig.KeyTag,
			SignerName: sig.SignerName,
		}
		if status, err := signatureTimeStatus(sig.Inception, sig.Expiration, now); status != SignatureValid {
			item.Status = status
			if err != nil {
				item.Error = err.Error()
			}
			out = append(out, item)
			continue
		}
		signed, err := signedRRSetData(owner, rrType, sig, rrset)
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
		for i := range trustedKeys {
			key, parseErr := ParseDNSKEY(trustedKeys[i])
			if parseErr != nil ||
				normalizeName(trustedKeys[i].Name) != normalizeName(sig.SignerName) ||
				key.KeyTag != sig.KeyTag ||
				key.Algorithm != sig.Algorithm ||
				key.Protocol != 3 ||
				key.Flags&0x0100 == 0 {
				continue
			}
			matched = true
			candidateSupported, candidateValid, candidateErr := verifySignature(
				sig.Algorithm,
				trustedKeys[i].RawData,
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

func signedRRSetData(owner string, rrType uint16, sig RRSIG, rrset []dnswire.ResourceRecord) ([]byte, error) {
	signerWire, err := canonicalNameWire(sig.SignerName)
	if err != nil {
		return nil, err
	}
	prefix := append([]byte(nil), sig.rawPrefix...)
	prefix = append(prefix, signerWire...)

	canonicalOwner, err := wildcardOwner(owner, sig.Labels)
	if err != nil {
		return nil, err
	}
	ownerWire, err := canonicalNameWire(canonicalOwner)
	if err != nil {
		return nil, err
	}

	var canonical [][]byte
	for _, record := range rrset {
		if record.Type != rrType || normalizeName(record.Name) != normalizeName(owner) {
			continue
		}
		rdata := record.CanonicalRData
		if rdata == nil {
			rdata = record.RawData
		}
		if len(rdata) > 65535 {
			return nil, fmt.Errorf("canonical rdata too large")
		}
		class := record.Class
		if class == 0 {
			class = dnswire.ClassIN
		}
		rr := append([]byte(nil), ownerWire...)
		rr = binary.BigEndian.AppendUint16(rr, rrType)
		rr = binary.BigEndian.AppendUint16(rr, class)
		rr = binary.BigEndian.AppendUint32(rr, sig.OriginalTTL)
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
		rr = append(rr, rdata...)
		canonical = append(canonical, rr)
	}
	if len(canonical) == 0 {
		return nil, fmt.Errorf("RRset type %d is empty", rrType)
	}
	sort.Slice(canonical, func(i, j int) bool { return bytes.Compare(canonical[i], canonical[j]) < 0 })
	out := prefix
	for _, rr := range canonical {
		out = append(out, rr...)
	}
	return out, nil
}

func wildcardOwner(owner string, labels uint8) (string, error) {
	owner = normalizeName(owner)
	if owner == "" {
		if labels != 0 {
			return "", fmt.Errorf("RRSIG labels %d exceeds root owner", labels)
		}
		return "", nil
	}
	parts := strings.Split(owner, ".")
	if int(labels) > len(parts) {
		return "", fmt.Errorf("RRSIG labels %d exceeds owner labels %d", labels, len(parts))
	}
	if int(labels) == len(parts) {
		return owner, nil
	}
	if labels == 0 {
		return "*", nil
	}
	return "*." + strings.Join(parts[len(parts)-int(labels):], "."), nil
}

func AnyValidSignature(values []SignatureValidation) bool {
	for _, value := range values {
		if value.Status == SignatureValid {
			return true
		}
	}
	return false
}
