package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pattn-discovery/internal/dnsfixture"
)

func main() {
	root := flag.String("root", "", "root directory containing DNS fixture JSON documents")
	failOnOrphans := flag.Bool("fail-on-orphans", false, "exit non-zero when packet fixtures are not referenced by a manifest or bundle")
	flag.Parse()

	if *root == "" {
		fmt.Fprintln(os.Stderr, "-root is required")
		os.Exit(2)
	}

	audit := dnsfixture.AuditDirectory(*root)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(audit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(audit.Errors) > 0 || (*failOnOrphans && len(audit.OrphanFixtures) > 0) {
		os.Exit(1)
	}
}
