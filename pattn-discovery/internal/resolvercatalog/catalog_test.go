package resolvercatalog

import (
	"testing"
	"time"
)

func TestBuiltinCatalogSeparatesFilteringFromNeutralReferences(t *testing.T) {
	values := Builtin()
	if len(values) != 3 {
		t.Fatalf("values=%+v", values)
	}
	refs := ReferenceEligible()
	if len(refs) != 2 {
		t.Fatalf("refs=%+v", refs)
	}
	quad9, ok := Find("quad9-secure")
	if !ok || quad9.Policy != PolicySecurityFiltering || quad9.ReferenceEligible {
		t.Fatalf("quad9=%+v ok=%v", quad9, ok)
	}
}

func TestBuiltinCatalogCarriesEncryptedDnsIdentity(t *testing.T) {
	for _, value := range Builtin() {
		if len(value.IPv4) == 0 || value.Port != 53 || value.DoTServerName == "" || value.DoTPort != 853 || value.DoHURL == "" {
			t.Fatalf("incomplete identity=%+v", value)
		}
	}
}


func TestBuiltinCatalogPassesStructuralValidation(t *testing.T) {
	if err := Validate(Builtin()); err != nil {
		t.Fatal(err)
	}
}


func TestAuditReportsFreshAndStaleEntriesDeterministically(t *testing.T) {
	fresh := Audit(time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), 30*24*time.Hour)
	if !fresh.Valid || fresh.StaleCount != 0 || len(fresh.Entries) != 3 {
		t.Fatalf("fresh=%+v", fresh)
	}

	stale := Audit(time.Date(2027, 1, 23, 12, 0, 0, 0, time.UTC), 30*24*time.Hour)
	if !stale.Valid || stale.StaleCount != 3 {
		t.Fatalf("stale=%+v", stale)
	}
}
