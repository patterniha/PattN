package dnssec

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"pattn-discovery/internal/dnswire"
)

type DS struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
	Digest     string `json:"digest"`
}

type DNSKEY struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	KeyTag    uint16 `json:"keyTag"`
}

type Match struct {
	DS     DS     `json:"ds"`
	DNSKEY DNSKEY `json:"dnskey"`
}

type DelegationValidation struct {
	Zone              string  `json:"zone"`
	DSCount           int     `json:"dsCount"`
	DNSKEYCount       int     `json:"dnskeyCount"`
	SupportedDSCount  int     `json:"supportedDsCount"`
	Matches           []Match `json:"matches,omitempty"`
	UnsupportedDigest []uint8 `json:"unsupportedDigestTypes,omitempty"`
	Status            string  `json:"status"`
}

const (
	StatusMatch          = "ds-key-match"
	StatusUnsigned       = "unsigned-no-ds"
	StatusMissingDNSKEY  = "ds-without-dnskey"
	StatusMismatch       = "ds-key-mismatch"
	StatusIndeterminate  = "indeterminate"
)

func ParseDS(record dnswire.ResourceRecord) (DS, error) {
	if record.Type != dnswire.TypeDS {
		return DS{}, fmt.Errorf("record type %d is not DS", record.Type)
	}
	if len(record.RawData) < 4 {
		return DS{}, fmt.Errorf("DS rdata too short: %d", len(record.RawData))
	}
	return DS{
		KeyTag: binary.BigEndian.Uint16(record.RawData[0:2]),
		Algorithm: record.RawData[2],
		DigestType: record.RawData[3],
		Digest: hex.EncodeToString(record.RawData[4:]),
	}, nil
}

func ParseDNSKEY(record dnswire.ResourceRecord) (DNSKEY, error) {
	if record.Type != dnswire.TypeDNSKEY {
		return DNSKEY{}, fmt.Errorf("record type %d is not DNSKEY", record.Type)
	}
	if len(record.RawData) < 4 {
		return DNSKEY{}, fmt.Errorf("DNSKEY rdata too short: %d", len(record.RawData))
	}
	return DNSKEY{
		Flags: binary.BigEndian.Uint16(record.RawData[0:2]),
		Protocol: record.RawData[2],
		Algorithm: record.RawData[3],
		PublicKey: base64.StdEncoding.EncodeToString(record.RawData[4:]),
		KeyTag: keyTag(record.RawData),
	}, nil
}

func ValidateDelegation(zone string, dsRecords, keyRecords []dnswire.ResourceRecord) DelegationValidation {
	result := DelegationValidation{Zone: normalizeName(zone), Status: StatusIndeterminate}
	var dsValues []DS
	for _, record := range dsRecords {
		if record.Type != dnswire.TypeDS {
			continue
		}
		ds, err := ParseDS(record)
		if err == nil {
			dsValues = append(dsValues, ds)
		}
	}
	var keys []struct {
		parsed DNSKEY
		raw    dnswire.ResourceRecord
	}
	for _, record := range keyRecords {
		if record.Type != dnswire.TypeDNSKEY {
			continue
		}
		key, err := ParseDNSKEY(record)
		if err == nil {
			keys = append(keys, struct {
				parsed DNSKEY
				raw    dnswire.ResourceRecord
			}{key, record})
		}
	}
	result.DSCount = len(dsValues)
	result.DNSKEYCount = len(keys)
	if result.DSCount == 0 {
		result.Status = StatusUnsigned
		return result
	}
	if result.DNSKEYCount == 0 {
		result.Status = StatusMissingDNSKEY
		return result
	}

	unsupported := map[uint8]struct{}{}
	for _, ds := range dsValues {
		supported := digestSupported(ds.DigestType)
		if !supported {
			unsupported[ds.DigestType] = struct{}{}
			continue
		}
		result.SupportedDSCount++
		for _, key := range keys {
			if key.parsed.KeyTag != ds.KeyTag || key.parsed.Algorithm != ds.Algorithm {
				continue
			}
			digest, err := DNSKEYDigest(result.Zone, key.raw.RawData, ds.DigestType)
			if err != nil {
				continue
			}
			want, err := hex.DecodeString(ds.Digest)
			if err == nil && bytes.Equal(digest, want) {
				result.Matches = append(result.Matches, Match{DS: ds, DNSKEY: key.parsed})
			}
		}
	}
	for digestType := range unsupported {
		result.UnsupportedDigest = append(result.UnsupportedDigest, digestType)
	}
	if len(result.Matches) > 0 {
		result.Status = StatusMatch
	} else if result.SupportedDSCount > 0 {
		result.Status = StatusMismatch
	}
	return result
}

func DNSKEYDigest(owner string, dnskeyRData []byte, digestType uint8) ([]byte, error) {
	ownerWire, err := canonicalNameWire(owner)
	if err != nil {
		return nil, err
	}
	input := append(ownerWire, dnskeyRData...)
	switch digestType {
	case 1:
		sum := sha1.Sum(input)
		return sum[:], nil
	case 2:
		sum := sha256.Sum256(input)
		return sum[:], nil
	case 4:
		sum := sha512.Sum384(input)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unsupported DS digest type %d", digestType)
	}
}

func digestSupported(value uint8) bool {
	return value == 1 || value == 2 || value == 4
}

func canonicalNameWire(name string) ([]byte, error) {
	name = normalizeName(name)
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS owner name %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, strings.ToLower(label)...)
	}
	return append(out, 0), nil
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

func keyTag(rdata []byte) uint16 {
	var accumulator uint32
	for i, value := range rdata {
		if i&1 == 0 {
			accumulator += uint32(value) << 8
		} else {
			accumulator += uint32(value)
		}
	}
	accumulator += (accumulator >> 16) & 0xffff
	return uint16(accumulator & 0xffff)
}


// MatchedKeyRecords returns only DNSKEY records whose raw RDATA still matches
// one of the DS digests that authenticated the delegation. Key tag + algorithm
// are only lookup hints and are not unique key identities.
func MatchedKeyRecords(validation DelegationValidation, records []dnswire.ResourceRecord) []dnswire.ResourceRecord {
	var out []dnswire.ResourceRecord
	for _, record := range records {
		if record.Type != dnswire.TypeDNSKEY {
			continue
		}
		key, err := ParseDNSKEY(record)
		if err != nil {
			continue
		}
		for _, match := range validation.Matches {
			if key.KeyTag != match.DNSKEY.KeyTag || key.Algorithm != match.DNSKEY.Algorithm {
				continue
			}
			digest, err := DNSKEYDigest(validation.Zone, record.RawData, match.DS.DigestType)
			if err != nil {
				continue
			}
			want, err := hex.DecodeString(match.DS.Digest)
			if err != nil || !bytes.Equal(digest, want) {
				continue
			}
			out = append(out, record)
			break
		}
	}
	return out
}
