package dnswire

import (
	"encoding/binary"
	"testing"
)

func TestBuildAndParseAResponse(t *testing.T) {
	query, id, err := BuildQuery("Example.COM.", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	response := makeAResponse(query, id, [4]byte{203, 0, 113, 9})
	got, err := ParseResponse(response, id, "example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Header.QR || !got.Header.RA || got.Header.RCode != 0 || len(got.AnswerIPs) != 1 || got.AnswerIPs[0].String() != "203.0.113.9" {
		t.Fatalf("response=%+v answers=%v", got.Header, got.AnswerIPs)
	}
}

func TestParseResponseExposesAuthenticatedDataBit(t *testing.T) {
	query, id, err := BuildQuery("example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	response := makeAResponse(query, id, [4]byte{203, 0, 113, 9})
	flags := binary.BigEndian.Uint16(response[2:4])
	binary.BigEndian.PutUint16(response[2:4], flags|0x0020) // AD

	got, err := ParseResponse(response, id, "example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Header.AD {
		t.Fatalf("expected AD bit, header=%+v", got.Header)
	}
}

func TestParseResponseRejectsSpoofedTransactionID(t *testing.T) {
	query, id, err := BuildQuery("example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	response := makeAResponse(query, id+1, [4]byte{203, 0, 113, 9})
	if _, err := ParseResponse(response, id, "example.com", TypeA); err == nil {
		t.Fatal("expected transaction mismatch")
	}
}

func TestBuildQueryRejectsOversizedLabel(t *testing.T) {
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, _, err := BuildQuery(label+".example", TypeA); err == nil {
		t.Fatal("expected invalid label")
	}
}

func makeAResponse(query []byte, id uint16, ip [4]byte) []byte {
	response := make([]byte, 12, len(query)+16)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8180) // QR + RD + RA
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)
	response = append(response, 0xc0, 0x0c) // name pointer to question
	response = binary.BigEndian.AppendUint16(response, TypeA)
	response = binary.BigEndian.AppendUint16(response, ClassIN)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 4)
	response = append(response, ip[:]...)
	return response
}
