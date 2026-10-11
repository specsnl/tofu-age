# tofu-age

- **Binary:** `tofu-age`
- **Module:** `github.com/specsnl/tofu-age`

An [OpenTofu external encryption method](https://opentofu.org/docs/language/state/encryption/#external-encryption-method)
built on [age](https://github.com/FiloSottile/age): a small static Go binary that translates between
OpenTofu's protocol and `filippo.io/age`. Structure and conventions deliberately mirror
[`specsnl/labelsync`](https://github.com/specsnl/labelsync), which itself mirrors
[`specsnl/specs-cli`](https://github.com/specsnl/specs-cli).

## Commands

**Every command runs through [Task](https://taskfile.dev).** Never invoke `docker compose`, `go`,
or `npx` directly — the Taskfile wraps Docker Compose services that pin the Go, golangci-lint,
hadolint, and Node versions, and set the shared build caches. Running the underlying tool directly
uses whatever happens to be installed locally, which is not what CI runs.

The `volume-init` service creates the cache directories in the shared volume and hands them to the
host user. Task runs it before any other service, with `docker compose run --rm` and at most once
per invocation, so a run leaves no stopped containers behind.

Run `task --list` for the full set. The ones used most:

| Command                | What it does                                                                                |
|------------------------|---------------------------------------------------------------------------------------------|
| `task checkall`        | The full check sequence: `tidy:check`, `lint`, `lint:docker`, `test`, `md:check`            |
| `task tidy:check`      | `go mod tidy -diff` — fails if `go.mod`/`go.sum` are untidy                                 |
| `task tidy`            | `go mod tidy`                                                                               |
| `task lint`            | `golangci-lint run`                                                                         |
| `task lint:fix`        | `golangci-lint run --fix`                                                                   |
| `task lint:docker`     | `hadolint Dockerfile`                                                                       |
| `task test`            | `go test -race ./...`                                                                       |
| `task md:check`        | markdownlint over every Markdown file                                                       |
| `task md:fix`          | Align Markdown tables, then apply autofixable rules                                         |
| `task schemas:update`  | Download OpenTofu's protocol schemas into `internal/protocol/testdata`                      |
| `task schemas:check`   | Check those schemas against the pinned and the latest OpenTofu release                      |
| `task build`           | Build the binary into the working directory                                                 |
| `task release:dry-run` | Build a snapshot release — the linux and darwin archives and `checksums.txt` — into `dist/` |
| `task dc:shell`        | Shell into the `go-builder` service                                                         |

### Local check sequence

Before opening a pull request, run:

```sh
task checkall
```

That is exactly `task tidy:check`, then `task lint`, then `task lint:docker`, then `task test`, then
`task md:check`, in that order — run them individually while iterating, and `checkall` before
pushing.

Every step of the sequence reports; none of them writes. `tidy:check` runs `go mod tidy -diff`, so
an untidy `go.mod`/`go.sum` fails the check with the diff it would have applied rather than quietly
rewriting the tree mid-check. Run `task tidy` to apply it. CI runs the same check in the `Unit
tests` job, and `lint:docker` — the task itself, so the hadolint version stays pinned once, in
`compose.yml` — in the `Dockerfile lint` job.

`schemas:check` needs the network, so it is not part of `checkall`: the `OpenTofu schemas` workflow runs it monthly,
and on pull requests that touch the schemas. Both `schemas:` tasks run `scripts/opentofu-schemas.sh` on the host
rather than in a container — it is `curl` and `diff`, with no toolchain to pin.

`task build` runs `task lint` first, so a green build implies a green lint — but it does not run the
tests or the Markdown checks.

## Workflow

- **Always work on a branch off `main`.** Implementing an issue starts with
  `git checkout -b <type>/<short-slug> main` — never commit to `main` directly, even for a
  one-line docs fix. Changes reach `main` through a pull request.
- **One issue, one branch, one pull request.** Reference the issue in the PR description so it
  closes on merge.
- **Run `task checkall` before pushing.**
- **Close the loop against the issue.** Before opening the PR, re-read the issue and check the work
  against its Scope and Done-when sections. Tick the checkboxes that the change actually satisfies,
  and say plainly in the PR what is left unticked and why.

## Conventions

- **stdout belongs to the OpenTofu protocol.** `encrypt` and `decrypt` write the header line and
  the response object there, and nothing else — a stray line corrupts the response OpenTofu parses.
  Diagnostics and errors go to stderr. This is also why there is no lipgloss, huh, or any other
  terminal UI library: nothing here is interactive, and nothing may decorate stdout.
- **`main` is the only place that calls `os.Exit`, and the only place that prints an error.**
  Commands return errors. The root sets `SilenceUsage` and `SilenceErrors`, so Cobra prints neither
  a usage block nor its own copy of the error.
- **Sentinel errors are always wrapped with `%w`**, so `errors.Is` keeps matching through every
  layer that adds context:

  ```go
  return fmt.Errorf("decrypt: %w", errNoIdentity)
  ```

- **Code changes require tests and docs.** Add or update `*_test.go` files covering the changed
  behaviour, and update [docs/design.md](./docs/design.md) when the change affects a documented
  design decision. Update the README only when what tofu-age *is*, or how it is installed, changes.
- **Tests default to stdlib `testing`.** No test framework dependency. Prefer table-driven tests,
  and drive commands through `cmd.NewRootCmd()` with `SetOut`/`SetErr` pointed at buffers, so a test
  asserts on exactly what reaches each stream.
- **`Version` stays at `internal/cmd.Version`.** The Dockerfile injects it by that path with
  `-ldflags -X`, and a test asserts that it still does.

## Package layout

```text
tofu-age/
├── main.go          # cmd.Execute(), the single error print, os.Exit
└── internal/
    ├── cmd/         # one file per Cobra command: check, encrypt, decrypt, version
    └── protocol/    # the OpenTofu external encryption method protocol; no crypto
```

## Documentation

| File                               | Description                                                     |
|------------------------------------|-----------------------------------------------------------------|
| [docs/design.md](./docs/design.md) | The design: protocol, key management, configuration, operations |
