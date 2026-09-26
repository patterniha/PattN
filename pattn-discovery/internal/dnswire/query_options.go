package dnswire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const TypeOPT uint16 = 41

type QueryOptions struct {
	RecursionDesired bool
	EDNS              bool
	UDPSize           uint16
	DNSSECOK          bool
}

func BuildQueryWithOptions(domain string, qtype uint16, opts QueryOptions) ([]byte, uint16, error) {
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
	packet := make([]byte, 12, 12+len(encoded)+15)
	binary.BigEndian.PutUint16(packet[0:2], id)
	if opts.RecursionDesired {
		binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	}
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, encoded...)
	packet = binary.BigEndian.AppendUint16(packet, qtype)
	packet = binary.BigEndian.AppendUint16(packet, ClassIN)

	if opts.EDNS || opts.DNSSECOK {
		udpSize := opts.UDPSize
		if udpSize == 0 {
			udpSize = 1232
		}
		binary.BigEndian.PutUint16(packet[10:12], 1)
		packet = append(packet, 0)
		packet = binary.BigEndian.AppendUint16(packet, TypeOPT)
		packet = binary.BigEndian.AppendUint16(packet, udpSize)
		var ttl uint32
		if opts.DNSSECOK {
			ttl = 0x00008000
		}
		packet = binary.BigEndian.AppendUint32(packet, ttl)
		packet = binary.BigEndian.AppendUint16(packet, 0)
	}
	return packet, id, nil
}
