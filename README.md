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

Exit status: `0` no failures, `1` at least one failure, `2` error. `sudo bordercheck` also shows ports held
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

## Install as a service

Hand people a zip with `bordercheck` and your `policies.json`. They run:

```sh
./bordercheck install            # asks for their work email
```

That copies both files to `~/Library/Application Support/bordercheck` (macOS) or
`%LOCALAPPDATA%\bordercheck` (Windows), registers an hourly per-user service (launchd LaunchAgent / Task
Scheduler; no admin rights), and sends a first report straight away. The service sends a report whenever
`report.interval` has passed since the last one that got through, so a failed send retries the next hour.

`install -policy https://…/policies.json` instead fetches the policy from your server before every report,
keeping the last good copy if the fetch fails: change the policy centrally, no reinstall.

```sh
bordercheck status               # email, policy, service, last report, last error
bordercheck send -force          # send a report now
bordercheck uninstall
```

The report is the same JSON as `bordercheck -json`, plus `email` and `install_id`:

```json
{
  "tool": "bordercheck", "version": "v0.2.0", "policy": "Acme", "time": "2026-10-30T14:46:07Z",
  "host": { "os": "darwin", "arch": "arm64", "hostname": "ans-mbp" },
  "email": "an@acme.com", "install_id": "4f1c…",
  "counts": { "fail": 1, "error": 0, "warn": 1, "pass": 3, "skip": 1 },
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

- Signed and notarized binaries; Homebrew tap and winget
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
