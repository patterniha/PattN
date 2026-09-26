package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"pattn-discovery/internal/dnssec"
)

func main() {
	maxAgeDays := flag.Int(
		"max-age-days",
		dnssec.DefaultTrustAnchorMaxAgeDays,
		"maximum age of the locally reviewed IANA root trust-anchor snapshot",
	)
	flag.Parse()
	if *maxAgeDays < 1 || *maxAgeDays > 3650 {
		fmt.Fprintln(os.Stderr, "max-age-days must be between 1 and 3650")
		os.Exit(2)
	}

	audit := dnssec.AuditIANARootTrustAnchors(
		time.Now(),
		time.Duration(*maxAgeDays)*24*time.Hour,
	)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(audit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if audit.ReviewRequired {
		os.Exit(1)
	}
}
