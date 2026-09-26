package dnsrr

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"pattn-discovery/internal/dnswire"
)

func CanonicalKey(record dnswire.ResourceRecord) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Name), "."))
	var value string
	switch {
	case record.Address.IsValid():
		value = record.Address.Unmap().String()
	case strings.TrimSpace(record.Target) != "":
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Target), "."))
	default:
		value = hex.EncodeToString(record.RawData)
	}
	return fmt.Sprintf("%s|%d|%d|%s", name, record.Type, record.Class, value)
}

func AnswerSignature(rcode uint8, records []dnswire.ResourceRecord, qtype uint16) string {
	keys := make([]string, 0, len(records))
	for _, record := range records {
		if record.Type != qtype && record.Type != dnswire.TypeCNAME {
			continue
		}
		keys = append(keys, CanonicalKey(record))
	}
	sort.Strings(keys)
	return fmt.Sprintf("rcode=%d;%s", rcode, strings.Join(keys, ";"))
}

func EquivalentAnswers(leftRCode uint8, left []dnswire.ResourceRecord, rightRCode uint8, right []dnswire.ResourceRecord, qtype uint16) bool {
	return AnswerSignature(leftRCode, left, qtype) == AnswerSignature(rightRCode, right, qtype)
}
