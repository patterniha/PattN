package dnswire

import (
	"encoding/binary"
	"testing"
)

func TestBuildQueryWithRecursionCanDisableRD(t *testing.T) {
	query, _, err := BuildQueryWithRecursion("example.com", TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(query[2:4])&0x0100 != 0 {
		t.Fatal("RD unexpectedly set")
	}
	query, _, err = BuildQueryWithRecursion("example.com", TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(query[2:4])&0x0100 == 0 {
		t.Fatal("RD not set")
	}
}

func TestParseMessagePreservesReferralAndGlue(t *testing.T) {
	query, id, err := BuildQueryWithRecursion("www.example.com", TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	response := makeReferralResponse(query, id)
	got, err := ParseMessage(response, id, "www.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Authorities) != 1 || got.Authorities[0].Type != TypeNS || got.Authorities[0].Target != "ns1.example.com" {
		t.Fatalf("authorities=%+v", got.Authorities)
	}
	if len(got.Additionals) != 1 || got.Additionals[0].Address.String() != "192.0.2.53" {
		t.Fatalf("additionals=%+v", got.Additionals)
	}
}

func TestParseRecordsDecodesDnameTargetAndCanonicalData(t *testing.T) {
	owner, err := encodeCanonicalName("alias.example.com")
	if err != nil {
		t.Fatal(err)
	}
	target, err := encodeCanonicalName("target.example.net")
	if err != nil {
		t.Fatal(err)
	}
	packet := append([]byte(nil), owner...)
	packet = binary.BigEndian.AppendUint16(packet, TypeDNAME)
	packet = binary.BigEndian.AppendUint16(packet, ClassIN)
	packet = binary.BigEndian.AppendUint32(packet, 300)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(target)))
	packet = append(packet, target...)

	records, offset, err := parseRecords(packet, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if offset != len(packet) || len(records) != 1 {
		t.Fatalf("offset=%d len=%d records=%+v", offset, len(packet), records)
	}
	if records[0].Type != TypeDNAME || records[0].Target != "target.example.net" {
		t.Fatalf("record=%+v", records[0])
	}
	if string(records[0].CanonicalRData) != string(target) {
		t.Fatalf("canonical=%x want=%x", records[0].CanonicalRData, target)
	}
}

func makeReferralResponse(query []byte, id uint16) []byte {
	response := make([]byte, 12, len(query)+64)
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8000)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[8:10], 1)
	binary.BigEndian.PutUint16(response[10:12], 1)
	response = append(response, query[12:]...)

	response = append(response, 0x07)
	response = append(response, []byte("example")...)
	response = append(response, 0x03)
	response = append(response, []byte("com")...)
	response = append(response, 0x00)
	response = binary.BigEndian.AppendUint16(response, TypeNS)
	response = binary.BigEndian.AppendUint16(response, ClassIN)
	response = binary.BigEndian.AppendUint32(response, 60)
	ns := []byte{0x03, 'n', 's', '1', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0}
	response = binary.BigEndian.AppendUint16(response, uint16(len(ns)))
	response = append(response, ns...)

	response = append(response, ns...)
	response = binary.BigEndian.AppendUint16(response, TypeA)
	response = binary.BigEndian.AppendUint16(response, ClassIN)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, 4)
	response = append(response, 192, 0, 2, 53)
	return response
}
