package targets

import (
	"context"
	"net/netip"
	"testing"
)

func BenchmarkStreamIPv6PrefixBounded(b *testing.B) {
	r, err := Parse("2001:db8::/64")
	if err != nil {
		b.Fatal(err)
	}
	ranges := []Range{r}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var count int64
		err := Stream(context.Background(), ranges, 10000, func(_ interfaceAddr) error {
			count++
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if count != 10000 {
			b.Fatalf("count=%d", count)
		}
	}
}

// interfaceAddr aliases netip.Addr at compile time without changing the
// production Stream signature; keeping the benchmark callback explicit makes
// allocation regressions visible in benchmem output.
type interfaceAddr = netip.Addr
