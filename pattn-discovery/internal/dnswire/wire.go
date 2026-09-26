// Package dnswire contains the minimal DNS wire primitives shared by resolver discovery and qualification.
// It deliberately uses only the Go standard library so pattn-discovery remains a single static helper binary.
package dnswire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeA    uint16 = 1
	TypeAAAA uint16 = 28
	ClassIN  uint16 = 1
)

type Header struct {
	ID      uint16 `json:"id"`
	QR      bool   `json:"qr"`
	Opcode  uint8  `json:"opcode"`
	AA      bool   `json:"aa"`
	TC      bool   `json:"tc"`
	RD      bool   `json:"rd"`
	RA      bool   `json:"ra"`
	AD      bool   `json:"ad"`
	RCode   uint8  `json:"rcode"`
	QDCount uint16 `json:"qdCount"`
	ANCount uint16 `json:"anCount"`
	NSCount uint16 `json:"nsCount"`
	ARCount uint16 `json:"arCount"`
}

type Response struct {
	Header    Header       `json:"header"`
	AnswerIPs []netip.Addr `json:"-"`
}

func BuildQuery(domain string, qtype uint16) ([]byte, uint16, error) {
	encoded, err := encodeName(domain)
	if err != nil {
		return nil, 0, err
	}
	if qtype == 0 {
		return nil, 0, fmt.Errorf("qtype is required")
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, fmt.Errorf("dns txid: %w", err)
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	packet := make([]byte, 12, 12+len(encoded)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, encoded...)
	packet = binary.BigEndian.AppendUint16(packet, qtype)
	packet = binary.BigEndian.AppendUint16(packet, ClassIN)
	return packet, id, nil
}

func ParseResponse(packet []byte, wantID uint16, wantName string, wantType uint16) (Response, error) {
	message, err := ParseMessage(packet, wantID, wantName, wantType)
	if err != nil {
		return Response{}, err
	}
	result := Response{Header: message.Header}
	for _, record := range message.Answers {
		if record.Address.IsValid() {
			result.AnswerIPs = append(result.AnswerIPs, record.Address.Unmap())
		}
	}
	return result, nil
}
func parseHeader(packet []byte) (Header, error) {
	if len(packet) < 12 {
		return Header{}, fmt.Errorf("dns packet too short: %d", len(packet))
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return Header{
		ID:      binary.BigEndian.Uint16(packet[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  uint8((flags >> 11) & 0x0f),
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		AD:      flags&0x0020 != 0,
		RCode:   uint8(flags & 0x0f),
		QDCount: binary.BigEndian.Uint16(packet[4:6]),
		ANCount: binary.BigEndian.Uint16(packet[6:8]),
		NSCount: binary.BigEndian.Uint16(packet[8:10]),
		ARCount: binary.BigEndian.Uint16(packet[10:12]),
	}, nil
}

func encodeName(domain string) ([]byte, error) {
	domain = strings.TrimSpace(domain)
	if domain == "." {
		return []byte{0}, nil
	}
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return nil, fmt.Errorf("domain too long")
	}
	out := make([]byte, 0, len(domain)+2)
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

func readName(packet []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 8)
	next := -1
	hops := 0
	// Expanded DNS names are limited to 255 wire octets including label lengths and the root terminator.
	expandedWireLength := 1
	seenPointers := make(map[int]struct{})
	for {
		if offset < 0 || offset >= len(packet) || hops > len(packet) {
			return "", -1, fmt.Errorf("malformed dns name")
		}
		hops++
		length := int(packet[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", -1, fmt.Errorf("truncated dns compression pointer")
			}
			if next < 0 {
				next = offset + 2
			}
			pointer := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3fff)
			if _, exists := seenPointers[pointer]; exists {
				return "", -1, fmt.Errorf("dns compression pointer loop")
			}
			seenPointers[pointer] = struct{}{}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(packet) {
			return "", -1, fmt.Errorf("invalid dns label")
		}
		offset++
		if length == 0 {
			if next < 0 {
				next = offset
			}
			return strings.Join(labels, "."), next, nil
		}
		expandedWireLength += 1 + length
		if expandedWireLength > 255 {
			return "", -1, fmt.Errorf("expanded dns name exceeds 255 octets")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
}

func skipName(packet []byte, offset int) (int, error) {
	for {
		if offset < 0 || offset >= len(packet) {
			return -1, fmt.Errorf("malformed dns name")
		}
		length := int(packet[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return -1, fmt.Errorf("truncated dns compression pointer")
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(packet) {
			return -1, fmt.Errorf("invalid dns label")
		}
		offset += 1 + length
		if length == 0 {
			return offset, nil
		}
	}
}

func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(strings.TrimSpace(b), "."))
}
