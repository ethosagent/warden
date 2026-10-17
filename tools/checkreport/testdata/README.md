# checkreport golden inputs

Every `*.json` / `*.txt` here is **real output captured from the pinned tool
versions**, never hand-written, so a tool upgrade that changes a format fails
the parser's golden test loudly:

| File | Captured with |
|---|---|
| `gotest_*.json`, `gotest_benchpanic.json` | `go test -json` (go1.26.9), run on small broken modules |
| `vet.json` | `go vet -json` |
| `build.json` | `go build -json` |
| `lint.json` | `golangci-lint v2.12.2 run --output.json.path=…` (the huge `Report.Linters` list is emptied) |
| `govulncheck.json` | `govulncheck v1.5.0 -format json` against a module requiring `golang.org/x/net v0.20.0`; only the `osv` entries the findings reference are kept |
| `roadmap_*.json` | `go run docs/roadmap/gen.go check -json` on a stale / invalid copy |
| `gofmt_*.txt` | `gofmt -l` stdout and stderr |
| `coverage.out.txt`, `coverage_func.txt` | `go test -coverprofile` and `go tool cover -func` on the same module |
| `checksh/*.golden` | the **pre-change** `scripts/check.sh` run against stub `go`/`gofmt` (see `checksh_test.go`) |

The captures ran in `/tmp/fx` (`/tmp/bp` for the benchmark panic), so their
absolute paths start there; the tests pass that as the repo root.

`fixtures/` are tiny modules, one per broken stage. Sources end in `.txt` so
gofmt, vet and lint ignore the deliberate breakage; `mock-*.json` replay a real
golangci-lint / govulncheck run on that fixture (both are too slow and need the
network to run in unit tests). Refresh a golden file by rerunning the tool at
the pinned version on the fixture.
