# External VEX Ingestion POC (kubescape/kubevuln#387)

A personal proof of concept for the External VEX Ingestion LFX proposal
(2026 Term 3). It covers three pieces of the project and does not attempt the rest.

## The project's 5 deliverables

### 1. A new namespaced `VEXSource` CRD (feed URL, format, image scope, refresh interval)

- `pkg/vexsource/v1beta1/types.go` defines the type: feed URL, format (openvex or
  csaf), which images it applies to, and how often to refresh.
- `Validate()` checks a bad feed URL, a bad format, an empty image list, or a
  zero/negative refresh interval in plain Go code.
- `pkg/vexsource/crds/kubescape.io_vexsources.yaml` is a generated CRD manifest,
  using the same group name (`kubescape.io`) this project already uses for
  `SecurityException`.
- 10 tests in `pkg/vexsource/v1beta1/types_test.go`.

### 2. A controller that fetches, validates, and persists external VEX documents

- **Fetches**: `adapters/v1/vexsource_fetch.go` downloads the document from the feed
  URL through `internal/safefetch`.
- **Validates**: checks the downloaded document's `@context` matches OpenVEX before
  parsing it.
- **Persists**: saves the document's statements into an
  `OpenVulnerabilityExchangeContainer`.
- **Not included**: nothing here watches for a new or changed `VEXSource`, or runs on
  a timer. That needs watch/scheduling machinery in a different repository
  (`kubescape/operator`).

5 tests in `adapters/v1/vexsource_fetch_test.go`.

### 3. A join step that suppresses matching findings and records why

Not included.

This POC does include a separate test of an assumption the project description
states: that grype can consume CSAF via `--vex`. `adapters/v1/csaf_gap_repro_test.go`
runs a real, downloaded Red Hat CSAF advisory through grype's own `vex.Processor` and
checks whether it suppresses a finding the advisory marks `known_not_affected`. On
this advisory, it does not. A second test, using a modified copy of the same document
with a purl added by hand, confirms the same code path does suppress a match when a
purl is present.

2 tests in `adapters/v1/csaf_gap_repro_test.go`.

### 4. Deduplication across feeds mentioning the same CVE/image

Not included.

### 5. End-to-end tests against at least one real feed

Tests run against a real, downloaded Red Hat CSAF advisory and a self-made OpenVEX
document served by a local test server. No test makes a live call to a vendor's
website.

## Not included

- Automatic controller/watcher (deliverable #2's remaining part)
- Join/suppression logic (deliverable #3)
- Cross-feed deduplication (deliverable #4)
- CSAF-to-OpenVEX translation
- A live call to a real vendor feed during testing
- Automatic matching of a fetched statement to a specific scanned image -
  `PersistExternalStatement` takes the target container name as a parameter

## Running it

    go vet ./adapters/v1/... ./pkg/vexsource/...
    go test ./adapters/v1/... ./pkg/vexsource/... -run \
      "TestVEXSourceSpec_Validate|TestFetchVEXStatements|TestPersistExternalStatement|TestGrypeCSAF" -v

Note: `adapters/v1/domain_to_syft.go` currently has an undefined function reference
(`deduplicateErrors`) on `main`, unrelated to this POC, that blocks a full
`go build ./...`/`go vet ./...` of the package. The commands above, scoped to the
tests listed, still run.
