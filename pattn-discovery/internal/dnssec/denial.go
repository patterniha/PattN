package dnssec

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"pattn-discovery/internal/dnswire"
)

type NSEC struct {
	Owner      string   `json:"owner"`
	NextDomain string   `json:"nextDomain"`
	Types      []uint16 `json:"types"`
}

type NSEC3 struct {
	OwnerHash      string   `json:"ownerHash"`
	Zone           string   `json:"zone"`
	HashAlgorithm  uint8    `json:"hashAlgorithm"`
	Flags          uint8    `json:"flags"`
	Iterations     uint16   `json:"iterations"`
	Salt           string   `json:"salt"`
	NextHash       string   `json:"nextHash"`
	Types          []uint16 `json:"types"`
}

type DenialEvidence struct {
	Mechanism    string `json:"mechanism"`
	Owner        string `json:"owner,omitempty"`
	Next         string `json:"next,omitempty"`
	QueryName    string `json:"queryName"`
	QueryType    uint16 `json:"queryType"`
	ExactName    bool   `json:"exactName"`
	NameCovered  bool   `json:"nameCovered"`
	TypeAbsent   bool   `json:"typeAbsent"`
	CNAMEAbsent  bool   `json:"cnameAbsent"`
	OptOut       bool   `json:"optOut,omitempty"`
	Status       string `json:"status"`
}

const (
	DenialNODATA       = "nodata-evidence"
	DenialNameCovered  = "name-nonexistence-evidence"
	DenialNotApplicable = "not-applicable"
	DenialUnsupported  = "unsupported"
)

func ParseNSEC(record dnswire.ResourceRecord) (NSEC, error) {
	if record.Type != dnswire.TypeNSEC {
		return NSEC{}, fmt.Errorf("record type %d is not NSEC", record.Type)
	}
	data := record.CanonicalRData
	if len(data) == 0 {
		data = record.RawData
	}
	next, offset, err := parseCanonicalWireName(data, 0)
	if err != nil {
		return NSEC{}, err
	}
	types, err := parseTypeBitmaps(data[offset:])
	if err != nil {
		return NSEC{}, err
	}
	return NSEC{Owner: normalizeName(record.Name), NextDomain: normalizeName(next), Types: types}, nil
}

func ParseNSEC3(record dnswire.ResourceRecord) (NSEC3, error) {
	if record.Type != dnswire.TypeNSEC3 {
		return NSEC3{}, fmt.Errorf("record type %d is not NSEC3", record.Type)
	}
	data := record.RawData
	if len(data) < 5 {
		return NSEC3{}, fmt.Errorf("NSEC3 rdata too short")
	}
	saltLength := int(data[4])
	if 5+saltLength >= len(data) {
		return NSEC3{}, fmt.Errorf("truncated NSEC3 salt")
	}
	offset := 5 + saltLength
	hashLength := int(data[offset])
	offset++
	if hashLength == 0 || offset+hashLength > len(data) {
		return NSEC3{}, fmt.Errorf("truncated NSEC3 next hash")
	}
	nextHash := data[offset : offset+hashLength]
	offset += hashLength
	types, err := parseTypeBitmaps(data[offset:])
	if err != nil {
		return NSEC3{}, err
	}
	owner := normalizeName(record.Name)
	parts := strings.Split(owner, ".")
	if len(parts) < 2 {
		return NSEC3{}, fmt.Errorf("NSEC3 owner lacks zone suffix")
	}
	return NSEC3{
		OwnerHash: strings.ToUpper(parts[0]),
		Zone: strings.Join(parts[1:], "."),
		HashAlgorithm: data[0],
		Flags: data[1],
		Iterations: uint16(data[2])<<8 | uint16(data[3]),
		Salt: hex.EncodeToString(data[5 : 5+saltLength]),
		NextHash: strings.ToUpper(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(nextHash)),
		Types: types,
	}, nil
}

func EvaluateNSEC(queryName string, queryType uint16, value NSEC) DenialEvidence {
	queryName = normalizeName(queryName)
	exact := queryName == value.Owner
	hasType := containsType(value.Types, queryType)
	hasCNAME := containsType(value.Types, dnswire.TypeCNAME)
	covered := !exact && canonicalNameIntervalContains(value.Owner, value.NextDomain, queryName)
	status := DenialNotApplicable
	if exact && !hasType && !hasCNAME {
		status = DenialNODATA
	} else if covered {
		status = DenialNameCovered
	}
	return DenialEvidence{
		Mechanism: "nsec", Owner: value.Owner, Next: value.NextDomain,
		QueryName: queryName, QueryType: queryType, ExactName: exact,
		NameCovered: covered, TypeAbsent: !hasType, CNAMEAbsent: !hasCNAME, Status: status,
	}
}

func EvaluateNSEC3(queryName string, queryType uint16, value NSEC3) DenialEvidence {
	evidence := DenialEvidence{
		Mechanism: "nsec3", Owner: value.OwnerHash, Next: value.NextHash,
		QueryName: normalizeName(queryName), QueryType: queryType,
		OptOut: value.Flags&0x01 != 0, Status: DenialUnsupported,
	}
	hash, err := NSEC3Hash(queryName, value.HashAlgorithm, value.Iterations, value.Salt)
	if err != nil {
		return evidence
	}
	exact := strings.EqualFold(hash, value.OwnerHash)
	hasType := containsType(value.Types, queryType)
	hasCNAME := containsType(value.Types, dnswire.TypeCNAME)
	covered := !exact && hashIntervalContains(value.OwnerHash, value.NextHash, hash)
	status := DenialNotApplicable
	if exact && !hasType && !hasCNAME {
		status = DenialNODATA
	} else if covered {
		status = DenialNameCovered
	}
	evidence.ExactName = exact
	evidence.NameCovered = covered
	evidence.TypeAbsent = !hasType
	evidence.CNAMEAbsent = !hasCNAME
	evidence.Status = status
	return evidence
}

func NSEC3Hash(name string, algorithm uint8, iterations uint16, saltHex string) (string, error) {
	if algorithm != 1 {
		return "", fmt.Errorf("unsupported NSEC3 hash algorithm %d", algorithm)
	}
	wire, err := canonicalNameWire(name)
	if err != nil {
		return "", err
	}
	var salt []byte
	if saltHex != "" && saltHex != "-" {
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			return "", fmt.Errorf("invalid NSEC3 salt: %w", err)
		}
	}
	input := append(append([]byte(nil), wire...), salt...)
	sum := sha1.Sum(input)
	digest := sum[:]
	for i := uint16(0); i < iterations; i++ {
		round := append(append([]byte(nil), digest...), salt...)
		next := sha1.Sum(round)
		digest = next[:]
	}
	return strings.ToUpper(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(digest)), nil
}

func parseTypeBitmaps(data []byte) ([]uint16, error) {
	var types []uint16
	for offset := 0; offset < len(data); {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated type bitmap window")
		}
		window := int(data[offset])
		length := int(data[offset+1])
		offset += 2
		if length == 0 || length > 32 || offset+length > len(data) {
			return nil, fmt.Errorf("invalid type bitmap window length %d", length)
		}
		for octet := 0; octet < length; octet++ {
			value := data[offset+octet]
			for bit := 0; bit < 8; bit++ {
				if value&(1<<uint(7-bit)) != 0 {
					types = append(types, uint16(window*256+octet*8+bit))
				}
			}
		}
		offset += length
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types, nil
}

func parseCanonicalWireName(data []byte, offset int) (string, int, error) {
	var labels []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("truncated canonical DNS name")
		}
		length := int(data[offset])
		offset++
		if length == 0 {
			return strings.Join(labels, "."), offset, nil
		}
		if length > 63 || offset+length > len(data) {
			return "", 0, fmt.Errorf("invalid canonical DNS label")
		}
		labels = append(labels, strings.ToLower(string(data[offset:offset+length])))
		offset += length
	}
}

func containsType(types []uint16, value uint16) bool {
	i := sort.Search(len(types), func(i int) bool { return types[i] >= value })
	return i < len(types) && types[i] == value
}

func canonicalNameIntervalContains(owner, next, query string) bool {
	cmpOwnerNext := canonicalNameCompare(owner, next)
	cmpOwnerQuery := canonicalNameCompare(owner, query)
	cmpQueryNext := canonicalNameCompare(query, next)
	if cmpOwnerNext < 0 {
		return cmpOwnerQuery < 0 && cmpQueryNext < 0
	}
	if cmpOwnerNext > 0 {
		return cmpOwnerQuery < 0 || cmpQueryNext < 0
	}
	return false
}

func canonicalNameCompare(left, right string) int {
	a := strings.Split(normalizeName(left), ".")
	b := strings.Split(normalizeName(right), ".")
	for i, j := len(a)-1, len(b)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if cmp := bytes.Compare([]byte(a[i]), []byte(b[j])); cmp != 0 {
			return cmp
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func hashIntervalContains(owner, next, query string) bool {
	owner = strings.ToUpper(owner)
	next = strings.ToUpper(next)
	query = strings.ToUpper(query)
	if owner < next {
		return owner < query && query < next
	}
	if owner > next {
		return owner < query || query < next
	}
	return false
}
