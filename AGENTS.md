# AGENTS.md

## Cursor Cloud specific instructions

This repo is **HashiCorp Vault OSS**: a Go secrets-management server + CLI (root module) with an Ember.js admin UI in `ui/`. Standard commands live in `README.md`, `CONTRIBUTING.md`, `Makefile`, and `ui/README.md`; the notes below only capture non-obvious caveats for this environment.

### Toolchain / PATH
- Go and Node are preinstalled; the update script downloads Go modules, installs the `enumer` code generator, and installs UI deps.
- `enumer` (and other `go install`ed tools) land in `$(go env GOPATH)/bin` (i.e. `~/go/bin`). Make sure that dir is on `PATH` before building — `make dev`/`make bootstrap` run `go generate` (`prep`) which invokes `enumer`, and it will fail with `exec: "enumer": ... not found` otherwise. `export PATH="$PATH:$(go env GOPATH)/bin"`.

### Build & run (core server + CLI)
- `make dev` builds `bin/vault` (~5 min; the `go generate` step needs `enumer` on PATH).
- Run the dev server: `./bin/vault server -dev -dev-root-token-id=root`. Then in another shell `export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root` and use `./bin/vault ...` (e.g. `vault kv put secret/foo k=v`).

### Tests
- The canonical way to run Go tests is via the **root module** (`make test TEST=<pkg>` or `go test -tags=testonly <import-path>`). The root `go.mod` has `replace` directives pointing `api/` and `sdk/` at the local dirs.
- Do **not** run `go test` from inside `sdk/` (or `api/`) directly: those are separate modules whose `go.mod` pins `google.golang.org/grpc v1.60.1`, but their committed generated code needs v1.64 (`grpc.SupportPackageIsVersion8`), so a standalone build fails. Building/testing through the root module uses the correct grpc version and works.
- Full `make test` requires **Docker** (many unit/integration tests spin up containers). Docker is **not** installed in this environment, so only pure-Go packages that don't need containers will pass; expect Docker-dependent tests to error out.

### Lint / vet
- There is no `.golangci.yml` and `golangci-lint` is not part of CI here; the canonical lightweight Go static analysis is `go vet` (`make vet`) plus the custom `tools/codechecker`. `make vet` treats vet output as advisory (non-fatal). Note `helper/random` has pre-existing `copylocks` vet warnings unrelated to your changes.

### UI (`ui/`)
- From `ui/`, `yarn` resolves to the repo-bundled Yarn 3.5.0 (`.yarn/releases/`). `package.json` declares `engines.node: 20`; the VM has a newer Node, but the dev build still works (it emits non-fatal license-header "slicing source" and webpack warnings).
- The UI needs a running Vault first. `yarn start` launches the Ember dev server on `http://localhost:4200/ui/` and proxies API calls to Vault on `:8200`. `yarn vault` / `yarn vault:cluster` can start a suitable dev server (see `ui/README.md`).
