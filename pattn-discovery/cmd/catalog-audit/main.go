package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"pattn-discovery/internal/resolvercatalog"
)

func main() {
	os.Exit(run(os.Args[1:], time.Now(), os.Stdout, os.Stderr))
}

func run(args []string, now time.Time, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("catalog-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	maxAgeDays := flags.Int("max-age-days", 120, "maximum permitted age of resolver identity verification metadata")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *maxAgeDays < 1 || *maxAgeDays > 3650 {
		fmt.Fprintln(stderr, "max-age-days must be between 1 and 3650")
		return 2
	}

	result := resolvercatalog.Audit(now, time.Duration(*maxAgeDays)*24*time.Hour)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if !result.Valid || result.StaleCount > 0 {
		return 1
	}
	return 0
}
