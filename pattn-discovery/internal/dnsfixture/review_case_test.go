package dnsfixture

import (
	"strings"
	"testing"

	"pattn-discovery/internal/dnswire"
)

func TestValidateReviewCaseMessageAcceptsAuthenticatedPositiveAndDenialCases(t *testing.T) {
	tests := []struct {
		name      string
		caseName  string
		queryType uint16
		message   dnswire.Message
	}{
		{
			name: "A",
			caseName: "a",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 0},
				Answers: []dnswire.ResourceRecord{{Type: dnswire.TypeA}, {Type: dnswire.TypeRRSIG}},
			},
		},
		{
			name: "CNAME",
			caseName: "cname",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 0},
				Answers: []dnswire.ResourceRecord{
					{Type: dnswire.TypeCNAME},
					{Type: dnswire.TypeRRSIG},
					{Type: dnswire.TypeA},
				},
			},
		},
		{
			name: "NODATA",
			caseName: "nodata",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 0},
				Authorities: []dnswire.ResourceRecord{
					{Type: dnswire.TypeNSEC},
					{Type: dnswire.TypeRRSIG},
				},
			},
		},
		{
			name: "NXDOMAIN NSEC3",
			caseName: "nxdomain",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 3},
				Authorities: []dnswire.ResourceRecord{
					{Type: dnswire.TypeNSEC3},
					{Type: dnswire.TypeRRSIG},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateReviewCaseMessage(tt.caseName, tt.queryType, tt.message); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateReviewCaseMessageRejectsParseableButWrongEvidence(t *testing.T) {
	tests := []struct {
		name      string
		caseName  string
		queryType uint16
		message   dnswire.Message
		contains  string
	}{
		{
			name: "DNAME without signature",
			caseName: "dname",
			queryType: dnswire.TypeDNAME,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 0},
				Answers: []dnswire.ResourceRecord{{Type: dnswire.TypeDNAME}},
			},
			contains: "DNAME",
		},
		{
			name: "NXDOMAIN without denial",
			caseName: "nxdomain",
			queryType: dnswire.TypeA,
			message: dnswire.Message{Header: dnswire.Header{AD: true, RCode: 3}},
			contains: "denial",
		},
		{
			name: "NODATA actually has answer",
			caseName: "nodata",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{AD: true, RCode: 0},
				Answers: []dnswire.ResourceRecord{{Type: dnswire.TypeA}},
				Authorities: []dnswire.ResourceRecord{
					{Type: dnswire.TypeNSEC},
					{Type: dnswire.TypeRRSIG},
				},
			},
			contains: "NODATA",
		},
		{
			name: "unsigned recursive result",
			caseName: "a",
			queryType: dnswire.TypeA,
			message: dnswire.Message{
				Header: dnswire.Header{RCode: 0},
				Answers: []dnswire.ResourceRecord{{Type: dnswire.TypeA}, {Type: dnswire.TypeRRSIG}},
			},
			contains: "authenticated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReviewCaseMessage(tt.caseName, tt.queryType, tt.message)
			if err == nil || !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
