package dnschain

import "testing"

func TestZonePathBuildsRootToSignerOrder(t *testing.T) {
	got := zonePath("www.sub.example.com.")
	want := []string{"com", "example.com", "sub.example.com", "www.sub.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got=%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
}

func TestNormalizeZonePreservesRoot(t *testing.T) {
	if got := normalizeZone("."); got != "." {
		t.Fatalf("got=%q", got)
	}
}
