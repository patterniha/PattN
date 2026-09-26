# DNS / DNSSEC fuzz corpus lifecycle

Normal PR CI keeps short fuzz smoke runs. The `DNS fuzz corpus campaign` workflow performs longer coverage-guided runs on a schedule and on demand.

Go minimizes a reproducible fuzz failure before writing it under `testdata/fuzz/<FuzzTarget>/...`. The workflow always uploads those files, the Go fuzz cache, run/runner provenance, and git status. After fixing a failure, commit the **minimized** failing input under the target's `testdata/fuzz` directory. Ordinary `go test ./...` then replays it forever as a regression seed.

Do not bulk-commit coverage-only cache entries: they are useful campaign artifacts, but durable repository corpus entries are reserved for minimized regressions or deliberately reviewed boundary seeds. `fuzz-corpus-audit` rejects malformed, duplicate, or oversized committed corpus entries.
