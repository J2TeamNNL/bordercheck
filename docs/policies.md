# Policies

A policy is a JSON file that sets an organisation's rules: what each check judges, where reports go, how
installed copies update and when people are notified. This page lists every field.

## Where the policy comes from

| How bordercheck runs | Policy |
|---|---|
| A plain run | `-policy <file>`, else `$BORDERCHECK_POLICY`, else `policies.json` beside the binary (or beside the target of a symlink to it, as with Homebrew), else the built-in one |
| Installed from a `policies.json` URL | that file, refreshed from `update.policy_url` every hour |
| Installed with an invite link | the policy of the person's role, fetched from the portal with the install's token every hour |

`bordercheck -print-policy` prints the policy in effect, with every default filled in: the best starting point.
[`policies.example.json`](../policies.example.json) is a complete example. On a portal, a role's policy is the
same JSON (see [the portal guide](portal.md#3-create-a-role)).

Rules for writing one:

- A policy only needs the fields it changes; everything else keeps the default.
- A list replaces the default list; it is not added to it. Maps (`min_os_versions`) merge instead, see below.
- Unknown fields are errors, so a typo cannot silently turn a rule off. An invalid policy stops a plain run with
  exit status `2`; an installed copy keeps its last good policy and records why.
- Check a policy before you roll it out: `bordercheck -policy policies.json -print-policy`.

A small policy:

```json
{
  "name": "Acme",
  "report": { "url": "https://bordercheck.acme.com/report", "email_domains": ["acme.com"] },
  "update": { "binary": true, "policy_url": "https://bordercheck.acme.com/policies.json" },
  "checks": { "listeners": { "on_problem": "fail" }, "tailscale": { "enabled": false } }
}
```

## Top level

| Field | Default | |
|---|---|---|
| `name` | the file name | Shown in reports as `policy` |
| `report` | | Where and how often an installed copy reports; [below](#report) |
| `update` | | Policy refresh and self-update; [below](#update) |
| `notify` | | Desktop notifications; [below](#notify) |
| `waivers` | `[]` | Per-machine exemptions; [below](#waivers) |
| `checks` | | One object per check ID; [below](#checks) |

## report

Used only by an installed copy. A plain `bordercheck` never sends anything.

| Field | Default | |
|---|---|---|
| `url` | `""` | HTTPS endpoint that receives a `POST` of the JSON report (`http://localhost` and `http://127.0.0.1` are allowed for testing). `bordercheck install` refuses a policy without one. With an invite link the portal fills it in. |
| `headers` | `{}` | Extra request headers, e.g. `{"Authorization": "Bearer …"}` for your own endpoint: a token that can only submit reports. Not used with invite links: an enrolled install sends its own token, and the portal strips any `Authorization` header from a role. |
| `interval` | `"24h"` | Go duration between reports, at least `15m`. The service runs hourly and sends when this much time has passed since the last report that got through, so a failed send retries the next hour. |
| `include_evidence` | `false` | Also send evidence: file paths, ports, variable names, container names. Off, the report carries only status, severity, summary and fix. |
| `email_domains` | `[]` | With a static `policies.json`, the email typed at install must be in one of these domains. Empty = any. |
| `include_ips` | `false` | Also send `host.ips`: the addresses of the machine's own network interfaces that are up (IPv4 and IPv6, without loopback and link-local; at most 16), read locally. bordercheck never asks a "what is my IP" service. |
| `include_location` | `false` | Meant to send a device position. **It has no effect today**: no OS gives one without a permission prompt, admin rights or a lookup with a third party, so no location is sent. See [Location](#location). |

What a report contains, and what the receiver sees regardless of these switches, is in
[the agent guide](install.md#what-is-sent).

### Location

`report.include_location` would send a position only where the OS can supply one without a prompt, admin rights
or bordercheck contacting a third party. None can:

- macOS: Core Location needs an app bundle with a usage description and a Location Services prompt; a bare
  command-line binary run by launchd can't use it.
- Windows: since Windows 11 24H2 a desktop program reading the location API can trigger a "let this app access
  your location" prompt, and fixes usually come from Microsoft's Wi-Fi location service. Reading it only where a
  registry check proves no prompt can appear might be sound, but it is untested.
- Linux: GeoClue asks the desktop's agent, which prompts for programs not listed in `geoclue.conf`, and its Wi-Fi
  source looks nearby networks up with an online service.

A receiver can still estimate a rough location from the public IP address a report arrives from.

## update

| Field | Default | |
|---|---|---|
| `binary` | `false` | Install newer signed releases automatically. |
| `policy_url` | `""` | HTTPS URL this policy is refreshed from every hour. The last good copy is kept if a fetch fails or the new file is invalid. With an invite link the portal fills it in. |
| `interval` | `"24h"` | How often to look for a newer binary, at least `1h`. |
| `repo` | `"ptrinh/bordercheck"` | GitHub `owner/name` releases come from. **Pinned at install.** |
| `public_key` | `""` | Base64 ed25519 key that must sign `SHA256SUMS`; `""` = the official release key. **Pinned at install.** |

`repo` and `public_key` decide what code runs on every machine, so a policy fetched later cannot change them;
with an invite link the policy never sets them at all. How updates are checked:
[the agent guide](install.md#updates).

## notify

Desktop notifications for the person at the machine, shown by the installed service only. How they look on each
OS: [the agent guide](install.md#notifications).

| Field | Default | |
|---|---|---|
| `enabled` | `true` | |
| `statuses` | `["fail"]` | Which results notify: `"fail"` and/or `"warn"`. |
| `severities` | `["high", "medium"]` | And of which severity (`"low"`, `"medium"`, `"high"`). A result without a severity counts as medium. |
| `remind_every` | `"24h"` | Announce a problem that is still there again after this long; `"0"` = never; otherwise at least `1h`. |
| `open_report` | `true` | When a notification announces a high-severity problem and the receiver returned a link to the machine's report page, open it in the browser. |

With `enabled` true, `statuses` and `severities` must not be empty; set `enabled` to `false` to turn
notifications off.

## waivers

A waiver exempts one machine from one check for a while, without loosening the rule for everyone.

```json
"waivers": [
  { "check": "listeners", "email": "an@acme.com", "hostname": "an-mbp", "until": "2026-12-01",
    "reason": "Postgres on 5432 for the data migration; ticket IT-123" }
]
```

| Field | |
|---|---|
| `check` | Required. A check ID (`bordercheck -list`). |
| `email`, `install_id` | Which machine; at least one. `email` is the one bordercheck was installed with (or that IT set in the invite). `install_id` is in the machine's reports and in `bordercheck status`. A portal adds waivers keyed by `install_id` for enrolled machines. |
| `hostname` | Optional. Narrows the waiver to one of that person's machines: the report's `host.hostname`, ignoring case and a trailing `.local`. Never enough alone, since people set their own hostname. |
| `until` | Required, `YYYY-MM-DD`: the last day it applies, by the machine's local date. At most a year ahead; a waiver without an end is rejected. |
| `reason` | Required. Shown to the person and sent in the report. |

Every field given must match. While a waiver applies, a `fail` or `warn` from that check reports as `waived`:
it keeps its severity, summary and fix, gains `"waived": {"until": "2026-12-01", "reason": "…"}` in the JSON,
counts under `counts.waived`, does not make bordercheck exit `1` and does not notify. A pass stays a pass. If
several waivers match, the one ending last wins. The text report shows waived results as `WAIV`, says when a
waiver ends within 14 days, and says when a waiver for a failing check has ended; an ended waiver changes
nothing else.

The installed service matches on its email, install ID and hostname. A plain `bordercheck` run uses the same
identity when this user has installed bordercheck (it reads `config.json` in the install folder and writes
nothing), so what the person sees matches what IT sees. Without an install there is no email or install ID, so
no waiver applies.

## checks

Every check takes two common fields:

| Field | |
|---|---|
| `enabled` | `false` skips the check entirely. Default `true`. |
| `on_problem` | `"fail"` or `"warn"`: report every problem the check finds with that status, to make it stricter or more lenient. Default: the check's own judgement. |

On their own, checks report serious problems as `fail` with high severity and lesser ones as `warn` (medium or
low). `listeners` only ever warns, so set `"on_problem": "fail"` to make open ports block compliance.

The options of each check follow. Paths may start with `~`. "Globs" match the path as shown in the report
(`~/…`, with forward slashes): `*` and `?` stay within one folder, `**` matches any number of folders.

### firewall

| Field | Default | |
|---|---|---|
| `require_stealth` | `true` | macOS: warn (low) when stealth mode is off. |
| `suggest_outbound` | `true` | macOS: warn (low) when no outbound firewall app is installed, and suggest the free, open-source [LuLu](https://objective-see.org/products/lulu.html) from Objective-See. The built-in firewall only filters incoming connections; an outbound firewall asks before an app connects out. Recognised: LuLu, Little Snitch, Radio Silence and Vallum in `/Applications` or `~/Applications`. When the firewall itself is off, the result asks only for that. |

macOS: Application Firewall and stealth mode. Windows: Windows Firewall on for every profile. Linux: ufw or
firewalld on, or nftables/iptables rules. Without root Linux shows only firewall configuration, not live
rules: bordercheck passes ufw when `/etc/ufw/ufw.conf` enables it and firewalld when its service runs (and warns
about zones such as FedoraWorkstation that open ports 1025–65535). When only an nftables or iptables service
loads the rules, a plain run says it cannot tell and skips; `sudo bordercheck -only firewall` reads the rules.

### disk-encryption

No options. FileVault (macOS); LUKS/dm-crypt under `/` and `/home`, or ZFS encryption (Linux); BitLocker on the
system drive (Windows).

### listeners

Ports reachable beyond localhost (`lsof` on macOS, `ss` or else `/proc/net/tcp` on Linux). `sudo bordercheck`
also shows ports held by system services on macOS.

| Field | Default | |
|---|---|---|
| `allow` | `[{"process": "rapportd"}]` | Rules `{"process": "<name>", "port": "<port>"}` that may listen beyond localhost. `process` is required and compared without case; without `port`, any port. `rapportd` is Apple Handoff/Continuity. |

Example: `"allow": [{"process": "rapportd"}, {"process": "ControlCenter", "port": "7000"}]` (AirPlay Receiver).

### tailscale

No options. Passes when Tailscale's "Allow incoming connections" is off (shields up); fails high when it is on.

### docker

Running containers with ports published on `0.0.0.0`, host networking, `privileged`, or bind mounts of `/`, a
home folder, credential folders (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`, `~/.docker`, `~/.config`) or the
Docker socket.

| Field | Default | |
|---|---|---|
| `allow_containers` | `[]` | Container names exempt from every Docker rule. |
| `allow_mounts` | `[]` | Host paths that may be mounted, with everything below them. |

### secrets

Plain-text keys in shell files, shell history (plus fish history on Linux and PowerShell history on Windows),
`~/.aws`, `~/.npmrc`, `.env` files and private key files. A finding warns (medium); it fails (high) when it is a
private key, matches a `high` extra pattern, or is marked production. Values are never shown; see
[the agent guide](install.md#what-is-sent).

| Field | Default | |
|---|---|---|
| `extra_files` | `[]` | More files to scan. |
| `ignore_paths` | `[]` | Globs of findings to leave out, e.g. `"~/**/test-fixtures/**"`. |
| `production_keywords` | `["prod", "production", "live"]` | A finding whose file path or line contains one of these as a word (any case) is marked `[production]` and fails. Must not be empty. |
| `show_tail` | `true` | Show the last 4 characters of long provider tokens (OpenAI, GitHub, AWS…), as their own dashboards do, so people can tell which key to rotate. Passwords never show anything. |
| `walk_depth` | `5` | How many folders below home are searched for `.env` and key files, 0–20. |
| `extra_patterns` | `[]` | Your own token formats: `{"kind": "Acme token", "regex": "\\bacme_[A-Za-z0-9]{32}\\b", "high": true, "show_tail": true}`. `kind` and a valid Go regular expression are required; `high` makes a match fail; `show_tail` is safe only for long random tokens. They are tried before the built-in rules. |
| `locations` | all `true` | Credential stores read format by format; each switches off alone. |

`locations`:

| Key | Reads | Not flagged |
|---|---|---|
| `docker` | `~/.docker/config.json` inline logins | `credsStore` / `credHelpers` |
| `kube` | `~/.kube/config` inline tokens, passwords, `client-key-data` | exec plugins |
| `netrc` | `~/.netrc`, `~/_netrc` | |
| `git_credentials` | `~/.git-credentials`, and `credential.helper=store` | |
| `gcloud` | application default credentials, credential DBs | |
| `azure` | Azure CLI plain-text token caches | |
| `pypirc` | `~/.pypirc` passwords | |
| `gh` | `gh` `hosts.yml` tokens | a token in the OS keychain |
| `terraform` | `~/.terraform.d/credentials.tfrc.json` | |
| `pgpass` | `~/.pgpass` | |
| `mysql` | `~/.my.cnf` | |

On Windows gcloud, `gh`, Terraform and pgpass are read from their `%APPDATA%` paths.

### os-updates

Judged from what the machine already knows; it never goes online. "Out of date" means the updates the OS has
found, when it last checked, the version against your minimum, and how long ago each browser build landed on
disk.

- macOS: version at least the minimum; Software Update checks, downloads and installs Security Responses; no
  update left waiting too long. Safari updates with macOS.
- Linux: distribution release (`/etc/os-release`) at least the minimum; unattended-upgrades or dnf-automatic
  on; package database not stale.
- Windows: build at least the minimum; Windows Update not disabled or paused; last check, last installed
  update, pending restart.
- Every OS: Chrome, Edge, Firefox and Brave not stale.

| Field | Default | |
|---|---|---|
| `min_os_versions` | `{"macos": "15", "windows": "26100", "ubuntu": "22.04", "debian": "12", "fedora": "43"}` | Oldest version allowed. Keys: `macos`, `windows` (a build number: 26100 is Windows 11 24H2) or a Linux `/etc/os-release` ID. **Merges** with the defaults; `""` removes one. |
| `require_auto_update` | `true` | The OS checks for and installs security updates by itself. |
| `max_check_age_days` | `14` | Days since the OS last looked for updates. |
| `max_pending_days` | `14` | Days an update the OS has found may wait to be installed. |
| `max_days_since_update` | `45` | Windows and Linux: days since an OS update was last installed. |
| `check_browsers` | `true` | Check Chrome, Edge, Firefox and Brave. |
| `max_browser_age_days` | `60` | Days since the installed browser build landed on disk. |
| `min_browser_versions` | `{}` | `chrome`, `edge`, `firefox`, `brave` → oldest version allowed, e.g. `{"chrome": "157.0.8103.39"}` after a zero-day. |

Day limits are 0–3650; `0` turns that rule off. Versions are digits and dots. The defaults are a starting point:
set them to the oldest versions your vendors still patch.

### screen-lock

| Field | Default | |
|---|---|---|
| `require_password` | `true` | A password is needed after sleep or the screen saver (Windows: sign-in on wake). |
| `max_lock_minutes` | `10` | The screen must lock after at most this many idle minutes, 0–240; `0` = don't check. |

macOS: password right after sleep or screen saver, and lock time. Windows: sleep, secure screen saver or
inactivity limit. Linux: GNOME (`gsettings`) or KDE Plasma (`kscreenlockerrc`); other desktops are skipped.
Never goes online.

### remote-access

| Field | Default | |
|---|---|---|
| `allow` | `[]` | Services that may be on: `ssh`, `screen-sharing`, `remote-management`, `remote-apple-events`, `rdp`, `winrm`, `guest`. |

macOS: Remote Login (SSH), Screen Sharing, Remote Management, Remote Application Scripting, Guest User. Linux:
SSH server, xrdp / GNOME Remote Desktop, VNC servers, LightDM guest session. Windows: Remote Desktop, WinRM,
OpenSSH Server, Guest account. Never goes online.

### ssh-keys

Private keys in `~/.ssh` and those named by `~/.ssh/config`, judged by reading their file format. Key material
is never shown, only type, fingerprint and comment. Hardware (FIDO) keys pass.

| Field | Default | |
|---|---|---|
| `no_passphrase` | `true` | Flag private keys stored without a passphrase. |
| `loose_permissions` | `true` | Flag private keys other users can read (macOS and Linux; Windows ACLs aren't read yet). |
| `authorized_keys` | `true` | List the keys in `authorized_keys` that can log in to this machine. |
| `allow_keys` | `[]` | Globs of keys exempt from every rule, e.g. `"~/.ssh/ci_deploy"`. |

### tunnels

Software that publishes this machine by dialling out. Only the tool and local port are shown: tunnel command
lines can hold auth tokens, so arguments never are.

| Field | Default | |
|---|---|---|
| `processes` | `true` | Running tunnel clients: ngrok, cloudflared (quick and named tunnels), localtunnel, bore, frp, zrok, VS Code tunnels, devtunnel, `ssh -R`. |
| `tailscale_funnel` | `true` | `tailscale funnel`: open to the public internet. |
| `tailscale_serve` | `true` | `tailscale serve`: open to the tailnet. |
| `allow` | `[]` | Tools that may run. |
| `lower_severity` | `["cloudflared"]` | Tools you tell staff to use: low severity, medium if open to anyone. |

Tool names for `allow` and `lower_severity`: `tailscale-funnel`, `tailscale-serve`, `ngrok`, `cloudflared`,
`localtunnel`, `bore`, `frp`, `zrok`, `vscode-tunnel`, `devtunnel`, `ssh`.

### ai-agents

MCP and agent config files of Claude Code, Claude Desktop, Cursor, Copilot, Windsurf, Codex, Gemini CLI,
Continue and Zed, at the paths each vendor documents (on Linux and Windows only where the vendor documents one).

| Field | Default | |
|---|---|---|
| `tokens` | `true` | Plain-text tokens and API keys in MCP / agent configs. Uses the `secrets` patterns, including `extra_patterns`. |
| `guardrails` | `true` | Settings that skip approvals or the sandbox. |
| `extra_paths` | `[]` | More config files to scan for tokens. |
| `ignore_paths` | `[]` | Globs of files to leave out. |

### cracked-software

Traces that cracks of paid software leave behind. Cracked installers are a common way to spread malware,
information stealers above all, so any trace fails with high severity. The check never lists installed software
and never goes online.

| Looks for | Where |
|---|---|
| Adobe licensing and activation servers (`*.adobegenuine.com`; names under `adobe.com` and `adobe.io` that hold `activat`, `licens` or `genuine`, `3dns-…` and a few known ones such as `ic.adobe.io`) or Autodesk's (`activat`, `licens`, `genuine` under `autodesk.com`) sent to `0.0.0.0`, `::` or a loopback address in the hosts file | every OS (`/etc/hosts`; `%SystemRoot%\System32\drivers\etc\hosts`) |
| Windows or Microsoft Office set to activate against a KMS server on the machine itself (loopback or `localhost`), which only a KMS emulator such as KMSpico or KMS_VL_ALL answers. A company KMS server on the network passes. | Windows |
| KMSpico installed (`Program Files\KMSpico`) or its AutoKMS scheduler (`%SystemRoot%\AutoKMS`) | Windows |

| Field | Default | |
|---|---|---|
| `suggest_alternatives` | `true` | The fix names free, open-source replacements from [ArtCraft](https://getartcraft.com) for the products found: PhotoCraft, VectorCraft, FilmCraft, LightCraft, EffectCraft, DesignCraft and PdfCraft for Adobe; WordCraft, GridCraft and DeckCraft for Office; CADCraft for Autodesk. Set it to `false` if your organisation provides licences instead. |

The fix always says to remove the crack and its hosts entries, run a full malware scan, change the passwords and
tokens used on the machine, and ask IT for a licensed copy.

## A fuller example

```json
{
  "name": "Acme",
  "report": {
    "url": "https://bordercheck.acme.com/report",
    "headers": { "Authorization": "Bearer <submit-only token>" },
    "interval": "24h",
    "email_domains": ["acme.com"]
  },
  "update": { "binary": true, "policy_url": "https://bordercheck.acme.com/policies.json" },
  "notify": { "statuses": ["fail", "warn"], "severities": ["high"] },
  "checks": {
    "listeners":  { "on_problem": "fail", "allow": [{ "process": "rapportd" }] },
    "firewall":   { "require_stealth": false },
    "docker":     { "allow_containers": ["devdb"], "allow_mounts": ["~/projects"] },
    "secrets":    { "ignore_paths": ["~/**/test-fixtures/**"],
                    "extra_patterns": [{ "kind": "Acme token", "regex": "\\bacme_[A-Za-z0-9]{32}\\b", "high": true }],
                    "locations": { "gcloud": false } },
    "tailscale":  { "enabled": false },
    "os-updates": { "min_os_versions": { "macos": "26", "fedora": "" },
                    "min_browser_versions": { "chrome": "157.0.8103.39" } },
    "remote-access": { "allow": ["ssh"] },
    "ssh-keys":   { "authorized_keys": false, "allow_keys": ["~/.ssh/ci_deploy"] },
    "tunnels":    { "lower_severity": ["cloudflared"] },
    "ai-agents":  { "extra_paths": ["~/.config/acme-agent/mcp.json"] }
  }
}
```
