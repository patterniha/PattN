package dnswire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeNS     uint16 = 2
	TypeCNAME  uint16 = 5
	TypeSOA    uint16 = 6
	TypePTR    uint16 = 12
	TypeMX     uint16 = 15
	TypeTXT    uint16 = 16
	TypeSRV    uint16 = 33
	TypeDNAME  uint16 = 39
	TypeDS     uint16 = 43
	TypeRRSIG  uint16 = 46
	TypeNSEC   uint16 = 47
	TypeDNSKEY uint16 = 48
	TypeNSEC3  uint16 = 50
	TypeSVCB   uint16 = 64
	TypeHTTPS  uint16 = 65
	TypeCAA    uint16 = 257
)

type ResourceRecord struct {
	Name           string
	Type           uint16
	Class          uint16
	TTL            uint32
	Address        netip.Addr
	Target         string
	RawData        []byte
	CanonicalRData []byte
}

type Message struct {
	Header      Header
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

func BuildQueryWithRecursion(domain string, qtype uint16, recursionDesired bool) ([]byte, uint16, error) {
	return BuildQueryWithOptions(domain, qtype, QueryOptions{RecursionDesired: recursionDesired})
}

func ParseMessage(packet []byte, wantID uint16, wantName string, wantType uint16) (Message, error) {
	header, err := parseHeader(packet)
	if err != nil {
		return Message{}, err
	}
	if !header.QR {
		return Message{}, fmt.Errorf("not a dns response")
	}
	if header.ID != wantID {
		return Message{}, fmt.Errorf("dns transaction id mismatch")
	}
	if header.QDCount != 1 {
		return Message{}, fmt.Errorf("expected one dns question, got %d", header.QDCount)
	}

	offset := 12
	questionName, next, err := readName(packet, offset)
	if err != nil {
		return Message{}, err
	}
	offset = next
	if offset+4 > len(packet) {
		return Message{}, fmt.Errorf("truncated dns question")
	}
	qtype := binary.BigEndian.Uint16(packet[offset : offset+2])
	qclass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	offset += 4
	if !equalName(questionName, wantName) || qtype != wantType || qclass != ClassIN {
		return Message{}, fmt.Errorf("dns question mismatch")
	}

	message := Message{Header: header}
	message.Answers, offset, err = parseRecords(packet, offset, int(header.ANCount))
	if err != nil {
		return Message{}, err
	}
	message.Authorities, offset, err = parseRecords(packet, offset, int(header.NSCount))
	if err != nil {
		return Message{}, err
	}
	message.Additionals, offset, err = parseRecords(packet, offset, int(header.ARCount))
	if err != nil {
		return Message{}, err
	}
	if offset > len(packet) {
		return Message{}, fmt.Errorf("dns message overflow")
	}
	return message, nil
}

func parseRecords(packet []byte, offset, count int) ([]ResourceRecord, int, error) {
	records := make([]ResourceRecord, 0, count)
	for i := 0; i < count; i++ {
		name, next, err := readName(packet, offset)
		if err != nil {
			return nil, offset, err
		}
		offset = next
		if offset+10 > len(packet) {
			return nil, offset, fmt.Errorf("truncated dns resource record")
		}
		rrType := binary.BigEndian.Uint16(packet[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		rdataOffset := offset
		if offset+rdLength > len(packet) {
			return nil, offset, fmt.Errorf("truncated dns rdata")
		}
		raw := append([]byte(nil), packet[offset:offset+rdLength]...)
		record := ResourceRecord{
			Name:           strings.TrimSuffix(name, "."),
			Type:           rrType,
			Class:          rrClass,
			TTL:            ttl,
			RawData:        raw,
			CanonicalRData: append([]byte(nil), raw...),
		}
		switch rrType {
		case TypeA:
			if rdLength == 4 {
				var value [4]byte
				copy(value[:], packet[offset:offset+4])
				record.Address = netip.AddrFrom4(value)
			}
		case TypeAAAA:
			if rdLength == 16 {
				var value [16]byte
				copy(value[:], packet[offset:offset+16])
				record.Address = netip.AddrFrom16(value)
			}
		case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
			target, afterName, err := readName(packet, rdataOffset)
			if err != nil {
				return nil, offset, fmt.Errorf("decode dns name rdata: %w", err)
			}
			if afterName != rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid dns name rdata length")
			}
			record.Target = strings.TrimSuffix(target, ".")
			record.CanonicalRData, err = encodeCanonicalName(target)
			if err != nil {
				return nil, offset, err
			}
		case TypeMX:
			if rdLength < 3 {
				return nil, offset, fmt.Errorf("truncated MX rdata")
			}
			target, afterName, err := readName(packet, rdataOffset+2)
			if err != nil {
				return nil, offset, fmt.Errorf("decode MX exchange: %w", err)
			}
			if afterName != rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid MX rdata length")
			}
			record.Target = strings.TrimSuffix(target, ".")
			nameWire, err := encodeCanonicalName(target)
			if err != nil {
				return nil, offset, err
			}
			record.CanonicalRData = append([]byte(nil), packet[rdataOffset:rdataOffset+2]...)
			record.CanonicalRData = append(record.CanonicalRData, nameWire...)
		case TypeSOA:
			mname, afterMName, err := readName(packet, rdataOffset)
			if err != nil {
				return nil, offset, fmt.Errorf("decode SOA mname: %w", err)
			}
			rname, afterRName, err := readName(packet, afterMName)
			if err != nil {
				return nil, offset, fmt.Errorf("decode SOA rname: %w", err)
			}
			if afterRName < rdataOffset || afterRName+20 != rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid SOA rdata length")
			}
			mWire, _ := encodeCanonicalName(mname)
			rWire, _ := encodeCanonicalName(rname)
			record.CanonicalRData = append(mWire, rWire...)
			record.CanonicalRData = append(record.CanonicalRData, packet[afterRName:afterRName+20]...)
		case TypeSRV:
			if rdLength < 7 {
				return nil, offset, fmt.Errorf("truncated SRV rdata")
			}
			target, afterName, err := readName(packet, rdataOffset+6)
			if err != nil {
				return nil, offset, fmt.Errorf("decode SRV target: %w", err)
			}
			if afterName != rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid SRV rdata length")
			}
			record.Target = strings.TrimSuffix(target, ".")
			nameWire, _ := encodeCanonicalName(target)
			record.CanonicalRData = append([]byte(nil), packet[rdataOffset:rdataOffset+6]...)
			record.CanonicalRData = append(record.CanonicalRData, nameWire...)
		case TypeNSEC:
			nextName, afterName, err := readName(packet, rdataOffset)
			if err != nil {
				return nil, offset, fmt.Errorf("decode NSEC next domain: %w", err)
			}
			if afterName < rdataOffset || afterName > rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid NSEC next-domain encoding")
			}
			record.Target = strings.TrimSuffix(nextName, ".")
			nameWire, _ := encodeCanonicalName(nextName)
			record.CanonicalRData = append(nameWire, packet[afterName:rdataOffset+rdLength]...)
		case TypeSVCB, TypeHTTPS:
			if rdLength < 3 {
				return nil, offset, fmt.Errorf("truncated SVCB/HTTPS rdata")
			}
			target, afterName, err := readName(packet, rdataOffset+2)
			if err != nil {
				return nil, offset, fmt.Errorf("decode SVCB/HTTPS target: %w", err)
			}
			if afterName < rdataOffset+2 || afterName > rdataOffset+rdLength {
				return nil, offset, fmt.Errorf("invalid SVCB/HTTPS target encoding")
			}
			record.Target = strings.TrimSuffix(target, ".")
			nameWire, _ := encodeCanonicalName(target)
			record.CanonicalRData = append([]byte(nil), packet[rdataOffset:rdataOffset+2]...)
			record.CanonicalRData = append(record.CanonicalRData, nameWire...)
			record.CanonicalRData = append(record.CanonicalRData, packet[afterName:rdataOffset+rdLength]...)
		}
		records = append(records, record)
		offset += rdLength
	}
	return records, offset, nil
}


func encodeCanonicalName(name string) ([]byte, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return []byte{0}, nil
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid canonical dns label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}
