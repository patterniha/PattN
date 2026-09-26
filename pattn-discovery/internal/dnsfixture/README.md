# DNS wire fixtures

Fixtures are immutable raw DNS response packets plus enough query metadata to replay them through PattN's parser.

Rules:

- `captureKind: captured` means the packet came from an actual network response and **must** include an RFC3339 `capturedAt` and concrete source.
- `captureKind: synthetic` means the packet was generated solely for deterministic testing.
- Every fixture includes the exact raw packet as hex and a SHA-256 digest. Replay rejects digest mismatches.
- Do not edit packet bytes in-place. Add a new fixture with new provenance instead.
- CI only replays committed fixtures; it never depends on live DNS.

Create an actual capture manually:

```bash
go run ./cmd/dns-fixture-capture \
  -server 1.1.1.1:53 \
  -name example.com \
  -type 1 \
  -transport auto \
  -out internal/dnsfixture/testdata/example.capture.json
```

Replay it offline:

```bash
go run ./cmd/dns-fixture-replay -fixture internal/dnsfixture/testdata/example.capture.json
```

The capture command uses UDP first by default and automatically retries a response with the DNS TC bit over TCP. It refuses to save a still-truncated packet. This matters for DNSKEY/RRSIG and other DNSSEC-heavy responses where an apparently successful UDP capture can be semantically incomplete.

The checked-in `example-a.synthetic.json` is intentionally synthetic and exists only to validate the harness.


## Manifests

A manifest groups immutable fixtures and declares the semantic outcomes expected from replay.

The checked-in `testdata/manifest.json` currently verifies:

- a positive A response;
- a synthetic exact-name NSEC NODATA response.

Replay validates parser output and denial semantics such as `nsec:nodata-evidence`.

Single-packet semantic replay deliberately reports:

```
authenticationScope: not-evaluated-single-packet
```

That is not a root-anchored DNSSEC authentication result. Signature and chain authentication require a scripted multi-exchange bundle.

Replay the whole manifest:

```bash
go run ./cmd/dns-fixture-replay \
  -manifest internal/dnsfixture/testdata/manifest.json
```

## Scripted exchange bundles

Exchange bundles map exact DNS exchange tuples to committed fixture packets:

- resolver/name-server address;
- port;
- query name;
- query type;
- UDP/TCP transport;
- recursion-desired state.

A bundle can be injected directly into `dnstrace.Options.Exchange`, allowing iterative trace and, with a sufficiently complete packet corpus, DNSSEC chain validation to run without network access.

The checked-in one-hop bundle is intentionally synthetic and verifies that `dnstrace` can run entirely from committed packets. Missing exchange tuples fail closed as `nameserver_unreachable`; replay never falls through to live DNS.

Future real DNSSEC corpora should capture all root/TLD/authoritative DS, DNSKEY, answer and denial exchanges needed by the validator, preserve their original packet provenance, and then reference those fixtures from a bundle rather than embedding reconstructed records.


## Offline dnsvalidate runner

A scripted exchange bundle can be passed directly into the existing high-level DNS validator:

```bash
go run ./cmd/dns-fixture-validate \
  -bundle internal/dnsfixture/testdata/trace-one-hop.bundle.json \
  -name example.com \
  -type 1
```

The command calls the production `dnsvalidate.Validate` path with the bundle-provided exchange function. It never falls back to network I/O.

The current one-hop synthetic bundle intentionally produces an unanchored / indeterminate validation result because its response contains no DNSSEC signer material. That is expected. A root-anchored result requires a complete bundle containing the DS/DNSKEY/RRSIG exchanges used by the normal chain validator.

The purpose of the command is to keep the validator path unchanged while making its network dependency replaceable with immutable packet evidence.
