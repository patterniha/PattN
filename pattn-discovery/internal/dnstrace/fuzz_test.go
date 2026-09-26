package dnstrace

import (
	"strings"
	"testing"
)

func FuzzDnameSynthesis(f *testing.F) {
	f.Add("www.sub.example.com", "example.com", "example.net")
	f.Add("a.example", "example", "target")
	f.Add("www.example.com", "example.com", ".")
	f.Add("example.com", "example.com", "example.net")

	f.Fuzz(func(t *testing.T, queryName, owner, target string) {
		if len(queryName)+len(owner)+len(target) > 4096 {
			t.Skip()
		}
		result, err := synthesizeDNAME(queryName, owner, target)
		if err != nil {
			return
		}
		if result == "" {
			t.Fatal("successful DNAME synthesis returned an empty name")
		}
		if result != "." {
			wireLength := 1
			for _, label := range strings.Split(result, ".") {
				if label == "" || len(label) > 63 {
					t.Fatalf("invalid synthesized label %q in %q", label, result)
				}
				wireLength += 1 + len(label)
			}
			if wireLength > 255 {
				t.Fatalf("successful synthesis exceeded wire limit: %d bytes", wireLength)
			}
		}
	})
}
