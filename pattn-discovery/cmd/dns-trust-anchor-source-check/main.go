package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"pattn-discovery/internal/dnssec"
)

const maximumSourceBytes = 1 << 20

func main() {
	source := flag.String(
		"source",
		dnssec.IANARootTrustAnchorSourceURL,
		"IANA root trust-anchor XML URL")
	sourceFile := flag.String(
		"source-file",
		"",
		"local IANA root trust-anchor XML file; when set, compare these exact bytes instead of fetching")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTPS source timeout")
	flag.Parse()

	if *timeout <= 0 || *timeout > time.Minute {
		fmt.Fprintln(os.Stderr, "timeout must be greater than zero and at most one minute")
		os.Exit(2)
	}

	var body []byte
	var err error
	if *sourceFile != "" {
		body, err = os.ReadFile(*sourceFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(body) > maximumSourceBytes {
			fmt.Fprintln(os.Stderr, "IANA trust-anchor XML exceeds size limit")
			os.Exit(1)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, *source, nil)
		if requestErr != nil {
			fmt.Fprintln(os.Stderr, requestErr)
			os.Exit(2)
		}
		if request.URL.Scheme != "https" {
			fmt.Fprintln(os.Stderr, "trust-anchor source must use HTTPS")
			os.Exit(2)
		}

		client := &http.Client{
			Timeout: *timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("cross-authority or non-HTTPS redirect refused")
				}
				return nil
			},
		}

		response, fetchErr := client.Do(request)
		if fetchErr != nil {
			fmt.Fprintln(os.Stderr, fetchErr)
			os.Exit(1)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "IANA trust-anchor fetch returned HTTP %d\n", response.StatusCode)
			os.Exit(1)
		}

		body, err = io.ReadAll(io.LimitReader(response.Body, maximumSourceBytes+1))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(body) > maximumSourceBytes {
			fmt.Fprintln(os.Stderr, "IANA trust-anchor XML exceeds size limit")
			os.Exit(1)
		}
	}

	comparison, err := dnssec.CompareIANARootTrustAnchorXML(body, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(comparison); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !comparison.MatchesEmbedded {
		os.Exit(1)
	}
}
