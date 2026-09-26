package targets

import (
	"context"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Range is an inclusive IP target interval. It is intentionally lazy: country/ASN
// datasets can describe billions of addresses without materializing them in memory.
type Range struct {
	Start netip.Addr
	End   netip.Addr
}

func (r Range) Count() *big.Int {
	if !r.Start.IsValid() || !r.End.IsValid() || r.Start.BitLen() != r.End.BitLen() || r.Start.Compare(r.End) > 0 {
		return new(big.Int)
	}
	start := addrInt(r.Start)
	end := addrInt(r.End)
	return new(big.Int).Add(new(big.Int).Sub(end, start), big.NewInt(1))
}

func (r Range) String() string {
	if r.Start == r.End {
		return r.Start.String()
	}
	return r.Start.String() + "-" + r.End.String()
}

// Parse accepts a single IP, CIDR, or inclusive IP-IP range.
func Parse(value string) (Range, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Range{}, fmt.Errorf("empty target")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return Range{}, fmt.Errorf("parse CIDR %q: %w", value, err)
		}
		prefix = prefix.Masked()
		return Range{Start: prefix.Addr(), End: prefixLast(prefix)}, nil
	}
	if i := strings.Index(value, "-"); i > 0 {
		start, err := netip.ParseAddr(strings.TrimSpace(value[:i]))
		if err != nil {
			return Range{}, fmt.Errorf("parse range start %q: %w", value[:i], err)
		}
		end, err := netip.ParseAddr(strings.TrimSpace(value[i+1:]))
		if err != nil {
			return Range{}, fmt.Errorf("parse range end %q: %w", value[i+1:], err)
		}
		start = start.Unmap()
		end = end.Unmap()
		if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
			return Range{}, fmt.Errorf("invalid target range %q", value)
		}
		return Range{Start: start, End: end}, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return Range{}, fmt.Errorf("parse IP %q: %w", value, err)
	}
	addr = addr.Unmap()
	return Range{Start: addr, End: addr}, nil
}

func ParseMany(values []string) (valid []Range, invalid []string) {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		r, err := Parse(value)
		if err != nil {
			invalid = append(invalid, value)
			continue
		}
		valid = append(valid, r)
	}
	return valid, invalid
}

// Stream walks ranges without building an address slice. limit <= 0 means unlimited.
func Stream(ctx context.Context, ranges []Range, limit int64, fn func(netip.Addr) error) error {
	var emitted int64
	for _, r := range ranges {
		if !r.Start.IsValid() || !r.End.IsValid() || r.Start.BitLen() != r.End.BitLen() || r.Start.Compare(r.End) > 0 {
			continue
		}
		for current := r.Start; ; current = current.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if limit > 0 && emitted >= limit {
				return nil
			}
			if err := fn(current); err != nil {
				return err
			}
			emitted++
			if current == r.End {
				break
			}
			next := current.Next()
			if !next.IsValid() || next.Compare(current) <= 0 {
				return fmt.Errorf("target range overflow at %s", current)
			}
		}
	}
	return nil
}

func prefixLast(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if addr.Is4() {
		b := addr.As4()
		for bit := bits; bit < 32; bit++ {
			b[bit/8] |= 1 << uint(7-bit%8)
		}
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	for bit := bits; bit < 128; bit++ {
		b[bit/8] |= 1 << uint(7-bit%8)
	}
	return netip.AddrFrom16(b)
}

func addrInt(addr netip.Addr) *big.Int {
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := addr.As16()
	return new(big.Int).SetBytes(b[:])
}
