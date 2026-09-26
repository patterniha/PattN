package dnswire

import (
	"encoding/binary"
	"testing"
)

func TestBuildQueryWithOptionsAddsEdnsDoBit(t *testing.T) {
	packet, _, err := BuildQueryWithOptions("example.com", TypeDNSKEY, QueryOptions{
		RecursionDesired: false,
		EDNS: true,
		UDPSize: 1232,
		DNSSECOK: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(packet[10:12]) != 1 {
		t.Fatalf("arcount=%d", binary.BigEndian.Uint16(packet[10:12]))
	}
	offset := 12
	_, offset, err = readName(packet, offset)
	if err != nil {
		t.Fatal(err)
	}
	offset += 4
	if packet[offset] != 0 || binary.BigEndian.Uint16(packet[offset+1:offset+3]) != TypeOPT {
		t.Fatalf("missing OPT at %d", offset)
	}
	if got := binary.BigEndian.Uint16(packet[offset+3:offset+5]); got != 1232 {
		t.Fatalf("udp size=%d", got)
	}
	if binary.BigEndian.Uint32(packet[offset+5:offset+9])&0x8000 == 0 {
		t.Fatal("DO bit not set")
	}
}


func TestBuildQueryWithOptionsSupportsRootName(t *testing.T) {
	packet, _, err := BuildQueryWithOptions(".", TypeDNSKEY, QueryOptions{EDNS: true, DNSSECOK: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < 17 {
		t.Fatalf("packet too short: %d", len(packet))
	}
	if packet[12] != 0 {
		t.Fatalf("root qname not encoded as zero label: %v", packet[12:])
	}
	if binary.BigEndian.Uint16(packet[13:15]) != TypeDNSKEY {
		t.Fatalf("qtype=%d", binary.BigEndian.Uint16(packet[13:15]))
	}
}
