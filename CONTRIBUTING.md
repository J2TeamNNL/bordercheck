# Contributing

## Reporting a problem or a false positive

Open an issue at [github.com/ptrinh/bordercheck/issues](https://github.com/ptrinh/bordercheck/issues). Say which
OS and version, the bordercheck version (`bordercheck -version`), and what you expected.

For a check that is wrong about your machine, include its result:

```sh
bordercheck -json -only <check-id>
```

Secret values are never in that output, but evidence is: file paths, ports, process, container and variable
names. Edit out anything you don't want public. If the check reads a command's output or a file, the relevant
part of it (with addresses and names changed) lets us add it as a test sample.

## Build and test

Go (the version in `go.mod`), from the repository root:

```sh
go vet ./...
go test ./...
go run . -json                     # run every check on this machine
scripts/build-all.sh v0.0.0-test   # cross-compile dist/ for macOS, Linux and Windows, arm64 and amd64
```

`scripts/build-all.sh` is also the cross-compile check: per-OS files only compile for their own OS, so a change
that builds on your Mac can still break the Linux or Windows build. It writes `dist/SHA256SUMS` too, and signs it
only when `BORDERCHECK_SIGNING_KEY` is set.

The install scripts:

```sh
shellcheck -s sh install.sh scripts/*.sh
```

The receiver (`receiver/`, TypeScript on Cloudflare Workers):

```sh
cd receiver
npm install
npm test                 # vitest in the Workers runtime, with D1 and migrations
npm run typecheck
```

CI (`.github/workflows/ci.yml`) runs `go vet` and `go test` on macOS, Windows and Linux, shellcheck on Linux,
parses `install.ps1` on Windows, does a smoke run of `go run . -json` on each OS (exit `1` for a failing check on
the runner is fine; a crash is not), and builds every target.

## Conventions

These are how the code already works; please keep to them.

- **Go standard library only.** `go.mod` has no dependencies. Plists, TOML, SSH key formats and the like are
  parsed by hand.
- **Gather per OS, judge portably.** A check gathers raw OS output (command output, files) in build-tagged files
  (`*_darwin.go`, `*_linux.go`, `*_windows.go`, and `*_other.go` for the rest) and hands it to a pure `eval…`
  function in a file without a build tag. The `eval` and parse functions are unit-tested on every platform with
  sample output; samples captured from a real machine are marked as such, with addresses and names changed, and
  larger ones go in `internal/checks/testdata/`.
- **A plain run only reads.** It changes nothing on the machine, sends nothing, never needs root, never triggers
  a permission (TCC) prompt or other dialog, and never goes online. Where root would show more, the check says
  what it could not see (or skips) and the docs say what `sudo` adds. Shell out through `internal/sysx`, with a
  context, so a hung command cannot hold up the run.
- **A secret's value never appears** in a result, the evidence, a log, a notification or a report. Show the
  kind, the file and line, the variable name; at most the last 4 characters of a long random provider token.
  The secrets tests assert that no finding contains the value; do the same for a new rule.
- **Results say what to do.** Every `fail` or `warn` has a severity, a one-line summary and a fix the person can
  follow on their OS. Existing checks use `fail` with `high` for serious exposure and `warn` with `medium` or
  `low` for lesser problems; `skip` when the thing does not apply, `error` when the check could not tell.
- **Policy fields are strict.** Unknown fields are errors, so a typo cannot turn a rule off. A new field goes in
  the struct in `internal/policy/policy.go`, its default in `Default()`, its limits in `validate()`, its value in
  `policies.example.json`, and its documentation in [docs/policies.md](docs/policies.md).
- **The receiver** has no framework and no build step beyond Wrangler. Everything from a report is
  attacker-controlled: escape it in HTML and alerts, keep it in `untrusted` fields in MCP results.

## Adding a check

1. Pick an ID (lower case, hyphens) and a title that states the good state ("Disk is encrypted").
2. Add its options to `internal/policy/policy.go`: a struct embedding `Common` (or `Common` alone when it has no
   options), a field in `Checks` with the ID as its JSON name, defaults in `Default()`, limits in `validate()`,
   and the ID in the `on_problem` map there. Waivers pick the ID up from `Checks` by themselves.
3. Write the check in `internal/checks/<name>.go`: the `eval…` function that turns gathered facts into a
   `check.Result`, and per-OS gathering in build-tagged files. Return `unsupported()` where an OS has no
   implementation yet.
4. Register it in `All()` in `internal/checks/checks.go`; the order there is the report order.
5. Test the `eval` and parse functions with sample output for each OS, including the "not installed" and "can't
   tell" cases.
6. Run it for real: `go run . -only <id>` and `go run . -json -only <id>`.
7. Add it to `policies.example.json` and `receiver/src/sample-policy.json` (a test checks that the latter still
   parses), to `POLICY_CHECKS` in `receiver/src/roles.ts` (the portal only offers waivers for checks listed
   there), to the check table in [README.md](README.md#what-it-checks) and to [docs/policies.md](docs/policies.md#checks).

## Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`: build → sign and notarize the macOS binaries →
`SHA256SUMS` and its signature (after code signing, which changes the files) → check the release against the key
built into bordercheck → GitHub release with the binaries, `SHA256SUMS`, `SHA256SUMS.sig` and a rendered
Homebrew formula `bordercheck.rb`.

Installed copies only update to releases whose `SHA256SUMS` is signed with the release key, and the install
scripts refuse an unsigned one. `go run ./scripts/sign -keygen` makes a key pair: the private half goes in the
`BORDERCHECK_SIGNING_KEY` repo secret (never in a file), the public half in `internal/update.OfficialKey` and
`OFFICIAL_KEY` in `install.sh` and `install.ps1` (a test checks they match). A fork uses its own pair, and its
users set `update.public_key` or install with `--key`.

Repo secrets:

| Secret | |
|---|---|
| `BORDERCHECK_SIGNING_KEY` | required; the ed25519 key from `go run ./scripts/sign -keygen` |
| `MACOS_CERTIFICATE_P12`, `MACOS_CERTIFICATE_PASSWORD` | optional; base64 of a `.p12` with the *Developer ID Application* certificate and key, and its password |
| `MACOS_SIGNING_IDENTITY` | optional, e.g. `Developer ID Application: Acme Ltd (ABCDE12345)` |
| `APPLE_NOTARY_KEY_P8`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | optional; an App Store Connect API key for `notarytool` |

The macOS secrets put the Developer ID key on GitHub. Releases of this repository are instead signed on the
maintainer's Mac, before the tag is pushed:

```sh
SIGN_ID="Developer ID Application: Acme Ltd (ABCDE12345)" NOTARY_PROFILE=my-notary scripts/sign-macos-release.sh v1.2.3
git tag v1.2.3 && git push origin v1.2.3
```

`NOTARY_PROFILE` is a `notarytool` keychain profile (`xcrun notarytool store-credentials`). The script builds the
two macOS binaries from the commit you are on (it refuses a dirty tree), signs and notarizes them, and leaves them
in a draft release. The workflow then uses them instead of its own, after checking that they were built from
exactly the tagged commit with nothing uncommitted, signs `SHA256SUMS` over everything and publishes the draft.
With neither the secrets nor a draft, the release goes out with unsigned macOS binaries and a warning on the run.
A bare binary cannot be stapled, so Gatekeeper looks its notarization up online. Windows binaries are not
Authenticode-signed.

Homebrew (not published yet): copy `bordercheck.rb` from the release to `Formula/bordercheck.rb` in the tap repo
(`ptrinh/homebrew-tap`) and push. `scripts/homebrew-formula.sh vX.Y.Z dist/SHA256SUMS` renders it locally.
