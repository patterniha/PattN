package dnssec

import (
	"sort"
	"strings"

	"pattn-discovery/internal/dnswire"
)

type DenialProof struct {
	Mechanism          string `json:"mechanism"`
	QueryName          string `json:"queryName"`
	QueryType          uint16 `json:"queryType"`
	RCode              uint8  `json:"rcode"`
	ClosestEncloser    string `json:"closestEncloser,omitempty"`
	NextCloser         string `json:"nextCloser,omitempty"`
	WildcardName       string `json:"wildcardName,omitempty"`
	ClosestEncloserOK  bool   `json:"closestEncloserProven"`
	NextCloserOK       bool   `json:"nextCloserProven"`
	WildcardOK         bool   `json:"wildcardNonexistenceProven"`
	ExactNameOK        bool   `json:"exactNameProven"`
	TypeAbsent         bool   `json:"typeAbsent"`
	CNAMEAbsent        bool   `json:"cnameAbsent"`
	OptOut             bool   `json:"optOut"`
	InsecureDelegation bool   `json:"insecureDelegation"`
	Complete           bool   `json:"complete"`
	Status             string `json:"status"`
}

const (
	ProofNXDOMAIN           = "nxdomain-proven"
	ProofNODATA             = "nodata-proven"
	ProofInsecureDelegation = "insecure-delegation-optout"
	ProofIncomplete         = "incomplete-proof"
	ProofUnsupported        = "unsupported-proof"
)

func ComposeNSECProof(queryName string, queryType uint16, rcode uint8, values []NSEC) DenialProof {
	queryName = normalizeName(queryName)
	proof := DenialProof{Mechanism: "nsec", QueryName: queryName, QueryType: queryType, RCode: rcode, Status: ProofIncomplete}

	for _, value := range values {
		if value.Owner != queryName {
			continue
		}
		proof.ExactNameOK = true
		proof.TypeAbsent = !containsType(value.Types, queryType)
		proof.CNAMEAbsent = !containsType(value.Types, dnswire.TypeCNAME)
		if rcode == 0 && proof.TypeAbsent && proof.CNAMEAbsent {
			proof.Complete = true
			if queryType == dnswire.TypeDS &&
				containsType(value.Types, dnswire.TypeNS) &&
				!containsType(value.Types, dnswire.TypeSOA) {
				proof.InsecureDelegation = true
				proof.Status = ProofInsecureDelegation
			} else {
				proof.Status = ProofNODATA
			}
		}
		return proof
	}
	if rcode != 3 {
		return proof
	}

	owners := make(map[string]struct{}, len(values))
	for _, value := range values {
		owners[value.Owner] = struct{}{}
	}
	closest := closestExistingAncestor(queryName, owners)
	if closest == "" {
		return proof
	}
	proof.ClosestEncloser = closest
	proof.ClosestEncloserOK = true
	proof.NextCloser = nextCloserName(queryName, closest)
	proof.WildcardName = wildcardName(closest)

	for _, value := range values {
		if canonicalNameIntervalContains(value.Owner, value.NextDomain, proof.NextCloser) {
			proof.NextCloserOK = true
		}
		if canonicalNameIntervalContains(value.Owner, value.NextDomain, proof.WildcardName) {
			proof.WildcardOK = true
		}
	}
	proof.Complete = proof.ClosestEncloserOK && proof.NextCloserOK && proof.WildcardOK
	if proof.Complete {
		proof.Status = ProofNXDOMAIN
	}
	return proof
}

func ComposeNSEC3Proof(queryName string, queryType uint16, rcode uint8, values []NSEC3) DenialProof {
	queryName = normalizeName(queryName)
	proof := DenialProof{Mechanism: "nsec3", QueryName: queryName, QueryType: queryType, RCode: rcode, Status: ProofIncomplete}
	if len(values) == 0 {
		return proof
	}
	base := values[0]
	for _, value := range values[1:] {
		if value.Zone != base.Zone || value.HashAlgorithm != base.HashAlgorithm ||
			value.Iterations != base.Iterations || !strings.EqualFold(value.Salt, base.Salt) {
			proof.Status = ProofUnsupported
			return proof
		}
	}
	queryHash, err := NSEC3Hash(queryName, base.HashAlgorithm, base.Iterations, base.Salt)
	if err != nil {
		proof.Status = ProofUnsupported
		return proof
	}
	for _, value := range values {
		if !strings.EqualFold(value.OwnerHash, queryHash) {
			continue
		}
		proof.ExactNameOK = true
		proof.TypeAbsent = !containsType(value.Types, queryType)
		proof.CNAMEAbsent = !containsType(value.Types, dnswire.TypeCNAME)
		if rcode == 0 && proof.TypeAbsent && proof.CNAMEAbsent {
			proof.Complete = true
			if queryType == dnswire.TypeDS &&
				containsType(value.Types, dnswire.TypeNS) &&
				!containsType(value.Types, dnswire.TypeSOA) {
				proof.InsecureDelegation = true
				proof.OptOut = value.Flags&0x01 != 0
				proof.Status = ProofInsecureDelegation
			} else {
				proof.Status = ProofNODATA
			}
		}
		return proof
	}

	// RFC 5155 section 8.6: for DS NODATA in an Opt-Out zone, the
	// delegation may have no exact NSEC3 owner. A closest-provable-encloser
	// proof plus an Opt-Out NSEC3 covering the next-closer name authenticates
	// that the child is an insecure delegation. This is a NOERROR/NODATA
	// response, not NXDOMAIN.
	if queryType == dnswire.TypeDS && rcode == 0 {
		closest := closestNSEC3Ancestor(queryName, values, base)
		if closest == "" {
			return proof
		}
		proof.ClosestEncloser = closest
		proof.ClosestEncloserOK = true
		proof.NextCloser = nextCloserName(queryName, closest)
		nextHash, err := NSEC3Hash(proof.NextCloser, base.HashAlgorithm, base.Iterations, base.Salt)
		if err != nil {
			proof.Status = ProofUnsupported
			return proof
		}
		for _, value := range values {
			if hashIntervalContains(value.OwnerHash, value.NextHash, nextHash) {
				proof.NextCloserOK = true
				if value.Flags&0x01 != 0 {
					proof.OptOut = true
				}
			}
		}
		if proof.ClosestEncloserOK && proof.NextCloserOK && proof.OptOut {
			proof.InsecureDelegation = true
			proof.Complete = true
			proof.Status = ProofInsecureDelegation
		}
		return proof
	}

	if rcode != 3 {
		return proof
	}

	closest := closestNSEC3Ancestor(queryName, values, base)
	if closest == "" {
		return proof
	}
	proof.ClosestEncloser = closest
	proof.ClosestEncloserOK = true
	proof.NextCloser = nextCloserName(queryName, closest)
	proof.WildcardName = wildcardName(closest)

	nextHash, err := NSEC3Hash(proof.NextCloser, base.HashAlgorithm, base.Iterations, base.Salt)
	if err != nil {
		proof.Status = ProofUnsupported
		return proof
	}
	wildcardHash, err := NSEC3Hash(proof.WildcardName, base.HashAlgorithm, base.Iterations, base.Salt)
	if err != nil {
		proof.Status = ProofUnsupported
		return proof
	}

	for _, value := range values {
		if hashIntervalContains(value.OwnerHash, value.NextHash, nextHash) {
			proof.NextCloserOK = true
			if value.Flags&0x01 != 0 {
				proof.OptOut = true
			}
		}
		if hashIntervalContains(value.OwnerHash, value.NextHash, wildcardHash) {
			proof.WildcardOK = true
		}
	}
	if proof.OptOut && queryType == dnswire.TypeDS && proof.ClosestEncloserOK && proof.NextCloserOK {
		proof.InsecureDelegation = true
		proof.Complete = true
		proof.Status = ProofInsecureDelegation
		return proof
	}
	proof.Complete = proof.ClosestEncloserOK && proof.NextCloserOK && proof.WildcardOK && !proof.OptOut
	if proof.Complete {
		proof.Status = ProofNXDOMAIN
	}
	return proof
}

func closestExistingAncestor(queryName string, owners map[string]struct{}) string {
	for _, candidate := range ancestors(queryName) {
		if _, ok := owners[candidate]; ok {
			return candidate
		}
	}
	return ""
}

func closestNSEC3Ancestor(queryName string, values []NSEC3, base NSEC3) string {
	owners := make(map[string]struct{}, len(values))
	for _, value := range values {
		owners[strings.ToUpper(value.OwnerHash)] = struct{}{}
	}
	for _, candidate := range ancestors(queryName) {
		hash, err := NSEC3Hash(candidate, base.HashAlgorithm, base.Iterations, base.Salt)
		if err != nil {
			return ""
		}
		if _, ok := owners[hash]; ok {
			return candidate
		}
	}
	return ""
}

func ancestors(name string) []string {
	name = normalizeName(name)
	if name == "" {
		return nil
	}
	labels := strings.Split(name, ".")
	out := make([]string, 0, len(labels))
	for i := 0; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(strings.Split(out[i], ".")) > len(strings.Split(out[j], "."))
	})
	return out
}

func nextCloserName(queryName, closest string) string {
	queryName = normalizeName(queryName)
	closest = normalizeName(closest)
	if queryName == closest {
		return queryName
	}
	q := strings.Split(queryName, ".")
	c := strings.Split(closest, ".")
	if len(q) <= len(c) {
		return queryName
	}
	return strings.Join(q[len(q)-len(c)-1:], ".")
}

func wildcardName(closest string) string {
	closest = normalizeName(closest)
	if closest == "" {
		return "*"
	}
	return "*." + closest
}
