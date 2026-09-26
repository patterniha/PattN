package dnssec

import (
	"testing"

	"pattn-discovery/internal/dnswire"
)

func FuzzParseDNSSECRData(f *testing.F) {
	f.Add(uint16(dnswire.TypeDS), []byte{0x4f, 0x66, 0x08, 0x02})
	f.Add(uint16(dnswire.TypeDNSKEY), []byte{0x01, 0x01, 0x03, 0x08})
	f.Add(uint16(dnswire.TypeRRSIG), make([]byte, 19))
	f.Add(uint16(dnswire.TypeNSEC), []byte{0})
	f.Add(uint16(dnswire.TypeNSEC3), []byte{1, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, rrType uint16, raw []byte) {
		if len(raw) > 128*1024 {
			t.Skip()
		}

		record := dnswire.ResourceRecord{
			Name:    "example.com",
			Type:    rrType,
			Class:   dnswire.ClassIN,
			RawData: append([]byte(nil), raw...),
		}

		switch rrType {
		case dnswire.TypeDS:
			_, _ = ParseDS(record)
		case dnswire.TypeDNSKEY:
			_, _ = ParseDNSKEY(record)
		case dnswire.TypeRRSIG:
			_, _ = ParseRRSIG(record)
		case dnswire.TypeNSEC:
			_, _ = ParseNSEC(record)
		case dnswire.TypeNSEC3:
			_, _ = ParseNSEC3(record)
		default:
			_, _ = ParseDS(record)
			_, _ = ParseDNSKEY(record)
			_, _ = ParseRRSIG(record)
			_, _ = ParseNSEC(record)
			_, _ = ParseNSEC3(record)
		}
	})
}
