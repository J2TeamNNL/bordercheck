# bordercheck

**Checks your work laptop for open doors, and tells your IT team how it's doing.**

Firewalls stop strangers on the internet. They don't stop a dev server listening on every network, a
Tailscale peer that got hacked, a container with your home folder mounted, or an API key sitting in
`.zshrc`. bordercheck looks for those on macOS and Windows and says how to close each one. Installed, it
reports to your organisation's endpoint on a schedule.

## What it checks

| Check | macOS | Windows |
|---|---|---|
| `firewall` | Application Firewall + stealth mode | Windows Firewall, every profile |
| `disk-encryption` | FileVault | BitLocker (system drive) |
| `listeners` | Ports reachable beyond localhost | same |
| `tailscale` | "Allow incoming connections" is off (shields up) | same |
| `docker` | Ports on 0.0.0.0, host network, privileged, mounts of `/`, home, `~/.ssh`, the Docker socket | same |
| `secrets` | Keys in shell files, shell history, `~/.aws`, `~/.npmrc`, `.env` files, private key files | same, plus PowerShell history |

## Use

```sh
bordercheck                    # check and print a report
bordercheck -json              # the same report as JSON
bordercheck -only secrets,tailscale
bordercheck -list
```

Exit status: `0` no failures (waived ones do not count), `1` at least one failure, `2` error. `sudo bordercheck` also shows ports held
by system services on macOS. A plain run only reads; it changes nothing and sends nothing.

## For organisations: policies.json

Each organisation sets its own rules in `policies.json`, kept **beside the binary**. Start from
[`policies.example.json`](policies.example.json) or `bordercheck -print-policy`. A policy only needs the
fields it changes; lists replace the default list. Unknown fields are errors, so a typo can't silently turn a
rule off. bordercheck looks for the policy in `-policy`, then `$BORDERCHECK_POLICY`, then `policies.json`
beside the binary, else uses the built-in one.

```jsonc
{
  "name": "Acme",
  "report": {
    "url": "https://bordercheck.acme.com/report",   // HTTPS POST of the JSON report
    "headers": { "Authorization": "Bearer …" },     // a token that can only submit reports
    "interval": "24h",                              // how often each machine reports
    "include_evidence": false,                      // true also sends file paths, ports, names
    "email_domains": ["acme.com"]                   // emails people may install with
  },
  "update": {
    "binary": true,                                 // install newer signed releases
    "policy_url": "https://bordercheck.acme.com/policies.json",  // refresh this file every hour
    "interval": "24h",                              // how often to look for a newer binary
    "repo": "ptrinh/bordercheck",                   // pinned at install, see below
    "public_key": ""                                // "" = the official release key
  },
  "notify": {
    "enabled": true,                                // desktop notifications for the person at the machine
    "statuses": ["fail"],                           // "fail" and/or "warn"
    "severities": ["high", "medium"],               // a result without a severity counts as medium
    "remind_every": "24h"                           // re-announce a problem still there; "0" = never
  },
  "waivers": [
    { "check": "listeners", "email": "an@acme.com", "until": "2026-12-01",
      "reason": "Postgres on 5432 for the data migration" }
  ],
  "checks": {
    "listeners": { "on_problem": "fail", "allow": [{ "process": "rapportd" }] },
    "firewall":  { "require_stealth": false },
    "docker":    { "allow_containers": ["devdb"], "allow_mounts": ["~/projects"] },
    "secrets":   { "ignore_paths": ["~/**/test-fixtures/**"],
                   "production_keywords": ["prod", "production", "live"],
                   "extra_patterns": [{ "kind": "Acme token", "regex": "\\bacme_[A-Za-z0-9]{32}\\b", "high": true }] },
    "tailscale": { "enabled": false }
  }
}
```

Every check takes `enabled` and `on_problem` (`"fail"` or `"warn"`, to override how strict it is).

### Waivers

A waiver exempts one machine from one check for a while, without loosening the rule for everyone:

| Field | |
|---|---|
| `check` | the check ID (`bordercheck -list`) |
| `email`, `install_id`, `hostname` | which machine; at least one, and every one given must match. `email` is the one bordercheck was installed with, `install_id` is in its reports, `hostname` is the report's `host.hostname` (case and a trailing `.local` are ignored). Hostnames are set by the user, so prefer `email` or `install_id`. |
| `until` | required, `YYYY-MM-DD`: the last day it applies, by the machine's local date. At most a year ahead; a waiver without an end is rejected. |
| `reason` | required; shown to the person and sent in the report |

While a waiver applies, a `fail` or `warn` from that check reports as `waived`: it keeps its severity, summary and
fix, gains `"waived": {"until": "2026-12-01", "reason": "…"}` in the JSON, counts under `counts.waived`, does not
make bordercheck exit 1 and does not notify. A pass stays a pass. The text report shows waived results as `WAIV`,
says when a waiver ends within 14 days, and says when a waiver for a failing check has ended; an ended waiver
changes nothing else.

The installed service matches on its email, install ID and hostname. A plain `bordercheck` run uses the same
identity when this user has installed bordercheck (it reads `config.json` in the install folder, writes nothing),
so what you see matches what IT sees. Without an install there is no email or install ID, so only waivers that name
nothing but a `hostname` apply.

## Install as a service

Host your `policies.json` at an HTTPS URL and have people run:

```sh
./bordercheck install https://bordercheck.acme.com/policies.json   # asks for their work email
```

Or hand them a zip with `bordercheck` and `policies.json` side by side and they run `./bordercheck install`.
`-email you@acme.com` skips the question (for scripted rollouts).

That copies both files to `~/Library/Application Support/bordercheck` (macOS) or
`%LOCALAPPDATA%\bordercheck` (Windows), registers an hourly per-user service (launchd LaunchAgent / Task
Scheduler; no admin rights), and sends a first report straight away. The service sends a report whenever
`report.interval` has passed since the last one that got through, so a failed send retries the next hour.

### Notifications

Each time the service checks the machine (when a report is due), it shows a desktop notification for problems that
are new since the last check: the check IDs and summaries, and "Run bordercheck in a terminal to see how to fix it".
It never shows evidence (paths, ports, variable names), let alone a secret. A problem still there is announced again
every `notify.remind_every`; a fixed problem is forgotten, so it counts as new if it comes back; waived results and
passing machines stay silent. What was announced is kept in `state.json`.

| OS | How | Needs |
|---|---|---|
| macOS | `osascript` `display notification` | nothing; listed as Script Editor in System Settings → Notifications |
| Windows | a toast through Windows PowerShell 5.1 | nothing; shown while the user is logged on |
| Linux | `notify-send`, else `gdbus` to the desktop's notification service | a desktop session |

A notification that cannot be shown is logged in `bordercheck.log` and tried at the next check; it never holds up a
report. `bordercheck send -force` (and the first report at install) is run by someone at a terminal, so it prints the
problems there instead and the next scheduled run does not repeat them. A plain `bordercheck` never notifies.

```sh
bordercheck status               # email, policy, service, last report, updates
bordercheck send -force          # send a report now
bordercheck update               # refresh the policy and install a newer release now
bordercheck uninstall
```

## Updates

**Policy.** With `update.policy_url`, every hourly run fetches `policies.json` from that URL and keeps the last
good copy if the fetch fails or the new file is invalid. Change rules, the report endpoint or the update settings
in one place; no reinstall.

**Binary.** With `update.binary`, once every `update.interval` the service reads
`github.com/<repo>/releases/latest/download/SHA256SUMS` (GitHub's CDN, not the rate-limited API) and installs the
newer binary for its OS and architecture only if:

1. `SHA256SUMS.sig` is a valid ed25519 signature by the trusted key,
2. the binary matches its line in `SHA256SUMS`,
3. its version is newer (never a downgrade), and
4. it runs and reports that version.

Otherwise it keeps the current binary and records why (`bordercheck status`). A failed update never stops a
report. Development builds (`dev`) never update themselves.

`update.repo` and `update.public_key` decide what code runs on every machine, so they are **pinned at install**:
a policy fetched from `policy_url` cannot change them, and whoever controls your policy server cannot push a
binary. Changing them needs a reinstall.

Releases are signed in CI: `go run ./scripts/sign -keygen` makes the key pair; the private half goes in the
`BORDERCHECK_SIGNING_KEY` repo secret (never in a file) and the public half in `internal/update.OfficialKey`.
Forks use their own pair and set `update.public_key`.

The report is the same JSON as `bordercheck -json`, plus `email` and `install_id`:

```json
{
  "tool": "bordercheck", "version": "v0.2.0", "policy": "Acme", "time": "2026-10-30T14:46:07Z",
  "host": { "os": "darwin", "arch": "arm64", "hostname": "ans-mbp" },
  "email": "an@acme.com", "install_id": "4f1c…",
  "counts": { "fail": 1, "error": 0, "warn": 1, "pass": 3, "skip": 1, "waived": 0 },
  "results": [ { "id": "firewall", "title": "Firewall is on", "status": "fail", "severity": "high",
                 "summary": "The macOS firewall is off.", "fix": "…" } ]
}
```

Reports are self-reported by the machine: they tell you who needs help, not proof of compliance.

## Privacy

- Secret values are never printed or sent. For long provider tokens (OpenAI, GitHub, AWS…) the report shows
  the last 4 characters, as the providers' own dashboards do, so people can tell which key to rotate.
  Passwords show nothing.
- Evidence (file paths, variable names, ports) leaves the machine only when the policy sets
  `include_evidence`.

## Fixing secrets

On a Mac, move keys into the Keychain behind Touch ID with [touchenv](https://github.com/ptrinh/touch-env):

```sh
touchenv set OPENAI_API_KEY        # paste it, then delete the line from .zshrc / .env
touchenv run OPENAI_API_KEY -- python report.py
```

On Windows, use Credential Manager or a password manager CLI such as 1Password's `op run`. Rotate any key that
sat in shell history or a synced folder.

## Download

Get the binary for your machine from [Releases](https://github.com/ptrinh/bordercheck/releases/latest) and
check it against `SHA256SUMS`. Signed binaries, Homebrew and winget are planned.

## Roadmap

- Code-signed and notarized binaries; Homebrew tap and winget
- SSH keys without a passphrase; Remote Login / Screen Sharing / RDP on
- AI agent configs: tokens in MCP config files, agents running without a sandbox
- Outdated OS, browsers and packages
- A reference report receiver (Cloudflare Worker) with a dashboard and alerts

## Build

```sh
go test ./...
scripts/build-all.sh v0.2.0      # dist/ for macOS and Windows, arm64 and amd64, plus SHA256SUMS
```

## License

MIT
