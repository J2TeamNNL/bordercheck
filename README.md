# bordercheck

**Checks your work laptop for open doors, and tells your IT team how it's doing.**

Firewalls stop strangers on the internet. They don't stop a dev server listening on every network, a
Tailscale peer that got hacked, a container with your home folder mounted, or an API key sitting in
`.zshrc`. bordercheck looks for those on macOS, Linux and Windows and says how to close each one. Installed,
it reports to your organisation's endpoint on a schedule.

## What it checks

| Check | macOS | Linux | Windows |
|---|---|---|---|
| `firewall` | Application Firewall + stealth mode | ufw or firewalld on; nftables/iptables rules with `sudo`¹ | Windows Firewall, every profile |
| `disk-encryption` | FileVault | LUKS/dm-crypt under `/` and `/home`, or ZFS encryption | BitLocker (system drive) |
| `listeners` | Ports reachable beyond localhost | same (`ss`, else `/proc/net/tcp`) | same |
| `tailscale` | "Allow incoming connections" is off (shields up) | same | same |
| `docker` | Ports on 0.0.0.0, host network, privileged, mounts of `/`, home, `~/.ssh`, the Docker socket | same | same |
| `secrets` | Keys in shell files, shell history, `~/.aws`, `~/.npmrc`, `.env` files, private key files | same, plus fish history | same, plus PowerShell history |
| | Read format by format, each switchable in `locations`: Docker inline logins (not `credsStore`), kubeconfig inline tokens/keys (not exec plugins), `.netrc`, `.git-credentials` and `credential.helper=store`, gcloud ADC and credential DBs, Azure CLI plain-text token caches, `.pypirc`, `gh` `hosts.yml` tokens (not the keychain), Terraform `credentials.tfrc.json`, `.pgpass`, `.my.cnf` | same | same, `%APPDATA%` paths for gcloud, `gh`, Terraform, pgpass |
| `os-updates` | macOS version ≥ policy minimum; Software Update checks, downloads and installs Security Responses; no update left waiting too long; Chrome, Edge, Firefox, Brave not stale (Safari updates with macOS) | Distro release ≥ minimum (`/etc/os-release`); unattended-upgrades / dnf-automatic on; package database not stale; same browsers | Windows build ≥ minimum; Windows Update not disabled or paused; last check, last installed update, pending restart; same browsers |
| `screen-lock` | Password required right after sleep / screen saver; screen locks within `max_lock_minutes` | GNOME (`gsettings`) or KDE Plasma (`kscreenlockerrc`) locks within `max_lock_minutes`; other desktops are skipped | Sign-in required on wake; sleep, secure screen saver or inactivity limit within `max_lock_minutes` |
| `remote-access` | Remote Login (SSH), Screen Sharing, Remote Management, Remote Application Scripting, Guest User are off | SSH server, xrdp / GNOME Remote Desktop, VNC servers, LightDM guest session are off | Remote Desktop, WinRM, OpenSSH Server, Guest account are off |
| `ssh-keys` | Private keys in `~/.ssh` and named by `~/.ssh/config` without a passphrase or readable by others; `authorized_keys` entries (type, fingerprint, comment). Hardware (FIDO) keys pass | same | same, except file permissions (ACLs aren't read yet) |
| `tunnels` | ngrok, cloudflared (quick and named), `tailscale funnel` / `serve`, localtunnel, bore, frp, zrok, VS Code tunnels, devtunnel, `ssh -R`. Tool and port only; arguments are never shown | same | same |
| `ai-agents` | Plain-text tokens in MCP / agent configs (Claude Code, Claude Desktop, Cursor, Copilot, Windsurf, Codex, Gemini CLI, Continue, Zed) and settings that skip approvals or the sandbox | same, where the vendor documents a Linux path | same, where the vendor documents a Windows path |

¹ Without root Linux shows only firewall configuration, not live rules. bordercheck passes ufw when
`/etc/ufw/ufw.conf` enables it and firewalld when its service runs (and warns about zones such as
FedoraWorkstation that open ports 1025–65535). When only an nftables or iptables service loads the rules, a plain
run says it cannot tell and skips; `sudo bordercheck -only firewall` reads the rules.

`os-updates`, `screen-lock` and `remote-access` never go online: "out of date" means what the machine already
knows (the updates its OS has found, when it last checked, the version against your minimum, how long ago each
browser build landed on disk).

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
                   "extra_patterns": [{ "kind": "Acme token", "regex": "\\bacme_[A-Za-z0-9]{32}\\b", "high": true }],
                   "locations": { "gcloud": false } },            // each credential store switches off alone
    "tailscale": { "enabled": false },
    "os-updates": { "min_os_versions": { "macos": "15", "windows": "26100", "ubuntu": "22.04" }, // "" drops one
                    "require_auto_update": true,
                    "max_check_age_days": 14,       // the OS last looked for updates
                    "max_pending_days": 14,         // an update it found may wait this long
                    "max_days_since_update": 45,    // Windows and Linux: last OS update installed
                    "check_browsers": true, "max_browser_age_days": 60,
                    "min_browser_versions": { "chrome": "157.0.8103.39" } },   // e.g. after a zero-day
    "screen-lock": { "require_password": true, "max_lock_minutes": 10 },
    "remote-access": { "allow": ["ssh"] },   // ssh, screen-sharing, remote-management, remote-apple-events, rdp, winrm, guest
    "ssh-keys":  { "no_passphrase": true, "loose_permissions": true, "authorized_keys": false,
                   "allow_keys": ["~/.ssh/ci_deploy"] },
    "tunnels":   { "processes": true, "tailscale_funnel": true, "tailscale_serve": true,
                   "allow": [], "lower_severity": ["cloudflared"] }, // the tunnel you tell staff to use
    "ai-agents": { "tokens": true, "guardrails": true,
                   "extra_paths": ["~/.config/acme-agent/mcp.json"], "ignore_paths": [] }
  }
}
```

Day limits of `0` turn that rule off. `min_os_versions` keys are `macos`, `windows` (a build number: 26100 is
Windows 11 24H2) or a Linux `/etc/os-release` ID, and merge with the defaults. The defaults are a starting point;
set them to the oldest versions your vendors still patch.

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

Host your `policies.json` at an HTTPS URL and have people run one command.

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh | sh -s -- https://bordercheck.acme.com/policies.json
```

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/policies.json
```

The script picks the latest release for the OS and CPU, checks it (below), and runs
`bordercheck install <url>`, which asks for the person's work email on the terminal. For scripted rollouts add
`--email an@acme.com` (`-Email` in PowerShell). Other options: `--version v1.2.3`, `--dry-run` (verify, then
stop), and `--repo owner/name --key <base64>` for a fork.

Already have the binary? `./bordercheck install https://bordercheck.acme.com/policies.json` does the same, or
hand people a zip with `bordercheck` and `policies.json` side by side and they run `./bordercheck install`.
`-email you@acme.com` skips the question.

That copies both files to `~/Library/Application Support/bordercheck` (macOS), `~/.local/share/bordercheck`
(Linux, or `$XDG_DATA_HOME/bordercheck`) or `%LOCALAPPDATA%\bordercheck` (Windows), registers an hourly
per-user service (launchd LaunchAgent / systemd user timer / Task Scheduler; no admin rights), and sends a first
report straight away. The service sends a report whenever `report.interval` has passed since the last one that
got through, so a failed send retries the next hour.

On Linux the timer is `~/.config/systemd/user/bordercheck.timer` and runs while the person's systemd user
session is up, as the Mac LaunchAgent runs while they are logged in (`loginctl enable-linger` keeps it running
when they are not). A login with no systemd user session (no systemd, some SSH or WSL setups) gets a line in
the user's crontab instead; `bordercheck status` says which.

### What the install script proves

Before it runs anything it downloaded, the script checks that:

1. `SHA256SUMS.sig` is an ed25519 signature of `SHA256SUMS` by the release key written into the script
   (with OpenSSL 3, as on current Linux distributions), and
2. the binary matches its line in `SHA256SUMS`.

Stock macOS (LibreSSL) and Windows PowerShell cannot check ed25519, so there the downloaded binary checks the
signature itself (`bordercheck verify`) with the key from the script, after step 2 passed. Any mismatch stops
the install with a message and nothing installed.

What that does and does not prove:

- It catches a corrupted or truncated download, a binary swapped on the release without updating
  `SHA256SUMS`, and (with OpenSSL 3) a release whose `SHA256SUMS` was changed without the signing key.
- Without OpenSSL 3 the signature check runs inside the binary it is checking, so a binary planted by someone
  who can edit the release can simply say yes. The checksum still ties it to `SHA256SUMS`, but not
  `SHA256SUMS` to the key.
- `curl | sh` trusts whoever controls the script's URL. The script and the release both live on GitHub, so
  someone who takes over the GitHub account can change both. The signing key protects **updates** of installed
  copies (which trust only their built-in key) far better than it protects the first install. To close the
  gap, host `install.sh` yourself (next to `policies.json`) or pin it to a commit
  (`raw.githubusercontent.com/ptrinh/bordercheck/<commit>/install.sh`), and prefer Homebrew or signed binaries
  on Macs.

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
- SSH keys are judged by reading their file format; key material is never shown, only type, fingerprint and
  comment. Tunnel command lines can hold auth tokens, so only the tool name and local port are shown.

## Fixing secrets

On a Mac, move keys into the Keychain behind Touch ID with [touchenv](https://github.com/ptrinh/touch-env):

```sh
touchenv set OPENAI_API_KEY        # paste it, then delete the line from .zshrc / .env
touchenv run OPENAI_API_KEY -- python report.py
```

On Windows, use Credential Manager or a password manager CLI such as 1Password's `op run`. Rotate any key that
sat in shell history or a synced folder.

## Download

- **Script**: see [Install as a service](#install-as-a-service).
- **Homebrew** (macOS, Linux): `brew install ptrinh/tap/bordercheck`, then `bordercheck install <url>`. The
  service runs its own copy, which updates itself; `brew upgrade` updates the one on your PATH.
- **By hand**: get `bordercheck-<version>-<os>-<arch>` from
  [Releases](https://github.com/ptrinh/bordercheck/releases/latest) (macOS, Linux and Windows; arm64 and amd64)
  with `SHA256SUMS` and `SHA256SUMS.sig`. Compare `shasum -a 256 <file>` with its line in `SHA256SUMS`; then
  `./<file> verify SHA256SUMS SHA256SUMS.sig <file>` checks the signature (with the caveat above: a binary
  checking itself).

macOS release binaries are signed with a Developer ID and notarized once the signing secrets are set up (see
[Releasing](#releasing)); until then, a browser download is blocked by Gatekeeper, while `install.sh` and Homebrew
are not (they don't mark the file as downloaded). Windows binaries are not Authenticode-signed yet.

## Roadmap

- Authenticode-signed Windows binaries; winget
- Outdated packages (Homebrew, npm, pip)
- A reference report receiver (Cloudflare Worker) with a dashboard and alerts

## Build

```sh
go test ./...
scripts/build-all.sh v0.2.0      # dist/ for macOS, Linux and Windows, arm64 and amd64, plus SHA256SUMS
```

### Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`: build → sign and notarize the macOS binaries →
`SHA256SUMS` and its signature (after code signing, which changes the files) → check the release against the
key built into bordercheck → GitHub release with the binaries, `SHA256SUMS`, `SHA256SUMS.sig` and a rendered
Homebrew formula `bordercheck.rb`.

Repo secrets:

| Secret | |
|---|---|
| `BORDERCHECK_SIGNING_KEY` | required; the ed25519 key from `go run ./scripts/sign -keygen` |
| `MACOS_CERTIFICATE_P12`, `MACOS_CERTIFICATE_PASSWORD` | base64 of a `.p12` with the *Developer ID Application* certificate and key, and its password |
| `MACOS_SIGNING_IDENTITY` | optional, e.g. `Developer ID Application: Acme Ltd (ABCDE12345)` |
| `APPLE_NOTARY_KEY_P8`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | an App Store Connect API key for `notarytool` |

Without the macOS secrets the release still goes out, unsigned, with a warning on the run. The signing steps
have not run for real yet: on the first signed release, download a darwin binary with a browser and check
`codesign -dv --verbose=2` and that it opens without a Gatekeeper prompt. A bare binary cannot be stapled, so
Gatekeeper looks its notarization up online.

Homebrew: copy `bordercheck.rb` from the release to `Formula/bordercheck.rb` in the tap repo
(`ptrinh/homebrew-tap`) and push. `scripts/homebrew-formula.sh vX.Y.Z dist/SHA256SUMS` renders it locally.

## License

MIT
