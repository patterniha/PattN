package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pattn-discovery/internal/dnsfixture"
)

type singleSummary struct {
	Name                string   `json:"name"`
	CaptureKind         string   `json:"captureKind"`
	Source              string   `json:"source"`
	QueryName           string   `json:"queryName"`
	QueryType           uint16   `json:"queryType"`
	RCode               uint8    `json:"rcode"`
	AnswerCount         int      `json:"answerCount"`
	AnswerTypes         []uint16 `json:"answerTypes,omitempty"`
	DenialStatuses      []string `json:"denialStatuses,omitempty"`
	AuthenticationScope string   `json:"authenticationScope"`
}

func main() {
	fixturePath := flag.String("fixture", "", "path to one DNS wire fixture JSON")
	manifestPath := flag.String("manifest", "", "path to a DNS fixture manifest JSON")
	flag.Parse()

	if (*fixturePath == "" && *manifestPath == "") || (*fixturePath != "" && *manifestPath != "") {
		fmt.Fprintln(os.Stderr, "exactly one of -fixture or -manifest is required")
		os.Exit(2)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if *manifestPath != "" {
		results, err := dnsfixture.ReplayManifest(*manifestPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		summaries := make([]singleSummary, 0, len(results))
		for _, result := range results {
			summaries = append(summaries, summarize(result))
		}
		if err := encoder.Encode(summaries); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	fixture, err := dnsfixture.Load(*fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, err := dnsfixture.ReplaySemantics(fixture)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := encoder.Encode(summarize(result)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func summarize(result dnsfixture.SemanticReplay) singleSummary {
	statuses := make([]string, 0, len(result.DenialEvidence))
	for _, denial := range result.DenialEvidence {
		statuses = append(statuses, denial.Mechanism+":"+denial.Status)
	}
	return singleSummary{
		Name: result.Fixture.Name,
		CaptureKind: result.Fixture.CaptureKind,
		Source: result.Fixture.Source,
		QueryName: result.Fixture.QueryName,
		QueryType: result.Fixture.QueryType,
		RCode: result.RCode,
		AnswerCount: result.AnswerCount,
		AnswerTypes: result.AnswerTypes,
		DenialStatuses: statuses,
		AuthenticationScope: result.AuthenticationScope,
	}
}
