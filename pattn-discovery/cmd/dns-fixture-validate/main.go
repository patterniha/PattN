package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"pattn-discovery/internal/dnsfixture"
	"pattn-discovery/internal/dnswire"
)

func main() {
	bundle := flag.String("bundle", "", "path to a scripted DNS exchange bundle")
	target := flag.String("name", "", "DNS name to validate")
	qtype := flag.Uint("type", uint(dnswire.TypeA), "numeric DNS query type")
	flag.Parse()

	if *bundle == "" || *target == "" || *qtype == 0 || *qtype > 65535 {
		fmt.Fprintln(os.Stderr, "-bundle and -name are required; -type must be 1..65535")
		os.Exit(2)
	}

	result, err := dnsfixture.ValidateDNSSECBundle(
		context.Background(),
		*bundle,
		*target,
		uint16(*qtype),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
