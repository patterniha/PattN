package dnssecdiag

import (
	"testing"

	"pattn-discovery/internal/dnssec"
)

func TestTrustedSignatureValidRequiresDsMatchedSigningKey(t *testing.T) {
	delegation := dnssec.DelegationValidation{
		Matches: []dnssec.Match{{
			DNSKEY: dnssec.DNSKEY{KeyTag: 1234, Algorithm: 15},
		}},
	}
	if !trustedSignatureValid(delegation, []dnssec.SignatureValidation{{
		KeyTag: 1234, Algorithm: 15, Status: dnssec.SignatureValid,
	}}) {
		t.Fatal("expected DS-matched signing key to authenticate DNSKEY RRset")
	}
	if trustedSignatureValid(delegation, []dnssec.SignatureValidation{{
		KeyTag: 9999, Algorithm: 15, Status: dnssec.SignatureValid,
	}}) {
		t.Fatal("untrusted DNSKEY must not authenticate the RRset")
	}
}
