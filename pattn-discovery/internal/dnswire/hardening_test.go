package dnswire

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadNameRejectsCompressionPointerLoop(t *testing.T) {
	if _, _, err := readName([]byte{0xc0, 0x00}, 0); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("expected compression loop error, got %v", err)
	}
}

func TestReadNameRejectsExpandedNameOver255Octets(t *testing.T) {
	packet := make([]byte, 0, 257)
	for i := 0; i < 4; i++ {
		packet = append(packet, 63)
		packet = append(packet, make([]byte, 63)...)
	}
	packet = append(packet, 0)

	if _, _, err := readName(packet, 0); err == nil || !strings.Contains(err.Error(), "255") {
		t.Fatalf("expected expanded-name length error, got %v", err)
	}
}

func TestParseMessageRejectsNameRdataEscapingDeclaredLength(t *testing.T) {
	query, id, err := BuildQueryWithRecursion("example.com", TypeNS, false)
	if err != nil {
		t.Fatal(err)
	}

	response := make([]byte, 12, len(query)+32)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8400) // QR + AA
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)

	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, TypeNS)
	response = binary.BigEndian.AppendUint16(response, ClassIN)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = append(response, 0xc0) // pointer's second byte is deliberately outside RDLENGTH
	response = append(response, 0x0c)

	if _, err := ParseMessage(response, id, "example.com", TypeNS); err == nil {
		t.Fatal("expected malformed RDATA boundary to be rejected")
	}
}

func TestParseResponseSharesFullMessageValidation(t *testing.T) {
	query, id, err := BuildQuery("example.com", TypeNS)
	if err != nil {
		t.Fatal(err)
	}

	response := make([]byte, 12, len(query)+32)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, TypeNS)
	response = binary.BigEndian.AppendUint16(response, ClassIN)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = append(response, 0xc0, 0x0c)

	if _, err := ParseResponse(response, id, "example.com", TypeNS); err == nil {
		t.Fatal("expected ParseResponse to reject malformed resource-record RDATA")
	}
}
