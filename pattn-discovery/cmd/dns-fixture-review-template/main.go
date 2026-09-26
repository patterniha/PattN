package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"pattn-discovery/internal/dnsfixture"
)

func main() {
	fixturePath := flag.String("fixture", "", "captured fixture JSON path")
	caseName := flag.String("case", "", "review case: A/AAAA/CNAME/DNAME/NXDOMAIN/NODATA/NSEC/NSEC3/DS/DNSKEY/RRSIG")
	expectation := flag.String("expectation", "", "candidate replay expectation; human reviewer must confirm it")
	flag.Parse()

	if strings.TrimSpace(*fixturePath) == "" || strings.TrimSpace(*caseName) == "" {
		fmt.Fprintln(os.Stderr, "-fixture and -case are required")
		os.Exit(2)
	}
	fixture, err := dnsfixture.Load(*fixturePath)
	if err != nil {
		fail(err)
	}
	if fixture.CaptureKind != dnsfixture.CaptureKindCaptured {
		fail(fmt.Errorf("review templates are only for captured fixtures"))
	}
	if err := dnsfixture.ValidateReviewCase(*caseName, fixture); err != nil {
		fail(fmt.Errorf("candidate does not satisfy %s review semantics: %w", strings.ToLower(strings.TrimSpace(*caseName)), err))
	}

	entry := dnsfixture.ManifestEntry{
		Path: "REPLACE_WITH_PROMOTED_FIXTURE_PATH.json",
		Tags: []string{"captured", strings.ToLower(strings.TrimSpace(*caseName))},
		Review: &dnsfixture.ManifestReview{
			Reviewer: "REPLACE_WITH_HUMAN_REVIEWER",
			ReviewedAt: "REPLACE_WITH_RFC3339_REVIEW_TIME",
			Case: strings.ToLower(strings.TrimSpace(*caseName)),
			FixtureSHA256: fixture.SHA256,
			ReplayExpectation: func() string {
				if strings.TrimSpace(*expectation) != "" {
					return "REVIEW_AND_CONFIRM: " + strings.TrimSpace(*expectation)
				}
				return "REPLACE_WITH_REVIEWED_SEMANTIC_EXPECTATION"
			}(),
		},
	}
	raw, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(raw))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
