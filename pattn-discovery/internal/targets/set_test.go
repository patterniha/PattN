package targets

import (
	"math/big"
	"testing"
)

func TestNormalizeSetMergesOverlapAndAdjacencyWithoutEnumeration(t *testing.T) {
	set, invalid := NormalizeSet(SourceMetadata{ID: "test", Kind: SourceUser, Scope: ScopeUserDefined}, []string{
		"10.0.0.0/25",
		"10.0.0.128/25",
		"10.0.0.64-10.0.1.10",
		"2001:db8::/64",
		"2001:db8:0:0:ffff:ffff:ffff:ffff",
		"not-an-ip",
	})
	if len(invalid) != 1 || invalid[0] != "not-an-ip" {
		t.Fatalf("invalid=%v", invalid)
	}
	got := set.Strings()
	if len(got) != 2 {
		t.Fatalf("normalized=%v", got)
	}
	if got[0] != "10.0.0.0-10.0.1.10" {
		t.Fatalf("ipv4=%s", got[0])
	}
	if got[1] != "2001:db8::-2001:db8::ffff:ffff:ffff:ffff" {
		t.Fatalf("ipv6=%s", got[1])
	}

	want := new(big.Int).Add(big.NewInt(267), new(big.Int).Lsh(big.NewInt(1), 64))
	if set.Count().Cmp(want) != 0 {
		t.Fatalf("count=%s want=%s", set.Count(), want)
	}
}

func TestNormalizeRangesKeepsAddressFamiliesSeparate(t *testing.T) {
	ranges, invalid := ParseMany([]string{"::ffff:192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"})
	if len(invalid) != 0 {
		t.Fatal(invalid)
	}
	got := NormalizeRanges(ranges)
	if len(got) != 2 {
		t.Fatalf("got=%v", got)
	}
	if got[0].String() != "192.0.2.1-192.0.2.2" || got[1].String() != "2001:db8::1-2001:db8::2" {
		t.Fatalf("got=%v", got)
	}
}

func TestFilterFamily(t *testing.T) {
	ranges, _ := ParseMany([]string{"192.0.2.0/24", "2001:db8::/126"})
	ranges = NormalizeRanges(ranges)
	if got := FilterFamily(ranges, true, false); len(got) != 1 || !got[0].Start.Is4() {
		t.Fatalf("ipv4=%v", got)
	}
	if got := FilterFamily(ranges, false, true); len(got) != 1 || !got[0].Start.Is6() {
		t.Fatalf("ipv6=%v", got)
	}
}

func TestValidateSourceRejectsUnknownKinds(t *testing.T) {
	if err := ValidateSource(SourceMetadata{ID: "x", Kind: SourceKind("mystery")}); err == nil {
		t.Fatal("expected unknown kind error")
	}
}
