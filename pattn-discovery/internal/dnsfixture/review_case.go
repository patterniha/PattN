package dnsfixture

import (
	"fmt"
	"strings"

	"pattn-discovery/internal/dnswire"
)

// ValidateReviewCase rejects capture candidates whose parsed DNS message does
// not demonstrate the semantics claimed by the human-review case label. It is
// intentionally stricter than mere packet/replay validity: candidate
// generation must not present a parseable but irrelevant response as review
// evidence for a DNSSEC case.
func ValidateReviewCase(caseName string, fixture Fixture) error {
	message, err := fixture.Replay()
	if err != nil {
		return fmt.Errorf("replay captured fixture: %w", err)
	}
	return validateReviewCaseMessage(caseName, fixture.QueryType, message)
}

func validateReviewCaseMessage(caseName string, queryType uint16, message dnswire.Message) error {
	caseName = strings.ToLower(strings.TrimSpace(caseName))
	if !message.Header.AD {
		return fmt.Errorf("%s candidate is not authenticated (AD bit is clear)", caseName)
	}

	hasAnswer := func(recordType uint16) bool {
		for _, record := range message.Answers {
			if record.Type == recordType {
				return true
			}
		}
		return false
	}
	hasAuthority := func(recordType uint16) bool {
		for _, record := range message.Authorities {
			if record.Type == recordType {
				return true
			}
		}
		return false
	}
	hasDenial := hasAuthority(dnswire.TypeNSEC) || hasAuthority(dnswire.TypeNSEC3)
	hasAuthoritySignature := hasAuthority(dnswire.TypeRRSIG)

	switch caseName {
	case "a":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeA) || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("A candidate requires NOERROR with A and RRSIG answers")
		}
	case "aaaa":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeAAAA) || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("AAAA candidate requires NOERROR with AAAA and RRSIG answers")
		}
	case "cname":
		if message.Header.RCode != 0 ||
			!hasAnswer(dnswire.TypeCNAME) ||
			!hasAnswer(dnswire.TypeRRSIG) ||
			(!hasAnswer(dnswire.TypeA) && !hasAnswer(dnswire.TypeAAAA)) {
			return fmt.Errorf("CNAME candidate requires NOERROR with CNAME, RRSIG, and a terminal A/AAAA answer")
		}
	case "dname":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeDNAME) || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("DNAME candidate requires NOERROR with DNAME and RRSIG answers")
		}
	case "nxdomain":
		if message.Header.RCode != 3 || !hasDenial || !hasAuthoritySignature {
			return fmt.Errorf("NXDOMAIN candidate requires authenticated NSEC/NSEC3 denial evidence and an authority RRSIG")
		}
	case "nodata":
		if message.Header.RCode != 0 || hasAnswer(queryType) || !hasDenial || !hasAuthoritySignature {
			return fmt.Errorf("NODATA candidate requires NOERROR, no answer for the queried type, and signed NSEC/NSEC3 denial evidence")
		}
	case "nsec":
		if !hasAuthority(dnswire.TypeNSEC) || !hasAuthoritySignature {
			return fmt.Errorf("NSEC candidate requires NSEC and RRSIG authority records")
		}
	case "nsec3":
		if !hasAuthority(dnswire.TypeNSEC3) || !hasAuthoritySignature {
			return fmt.Errorf("NSEC3 candidate requires NSEC3 and RRSIG authority records")
		}
	case "ds":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeDS) || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("DS candidate requires NOERROR with DS and RRSIG answers")
		}
	case "dnskey":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeDNSKEY) || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("DNSKEY candidate requires NOERROR with DNSKEY and RRSIG answers")
		}
	case "rrsig":
		if message.Header.RCode != 0 || !hasAnswer(dnswire.TypeRRSIG) {
			return fmt.Errorf("RRSIG candidate requires NOERROR with an RRSIG answer")
		}
	default:
		return fmt.Errorf("unsupported review case %q", caseName)
	}
	return nil
}
