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
  "checks": { "listeners": { "on_problem": "fail" }, "mesh-vpn": { "enabled": false } }
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
| `interval` | `"24h"` | Go duration between reports, at least `15m`. The service wakes hourly and sends when this much time has passed since the last report that got through, so a failed send retries the next hour. |
| `check_interval` | `""` | Check the machine more often than it reports, e.g. `"24h"` with `"interval": "168h"`: the person at the machine is told about a new problem within a day, IT gets one report a week. At least `15m`, not longer than `interval`. `""` checks only when a report is due. Needs bordercheck v0.3.1 or later: an older one rejects a policy with this field. |
| `include_evidence` | `false` | Also send evidence: file paths, ports, variable names, container names. Off, the report carries only status, severity, summary and fix. |
| `email_domains` | `[]` | With a static `policies.json`, the email typed at install must be in one of these domains. Empty = any. |
| `include_ips` | `false` | Also send `host.ips`: the addresses of the machine's own network interfaces that are up (IPv4 and IPv6, without loopback and link-local; at most 16), read locally. bordercheck never asks a "what is my IP" service. |
| `include_location` | `false` | Meant to send a device position. **It has no effect today**: no OS gives one without a permission prompt, admin rights or a lookup with a third party, so no location is sent. See [Location](#location). |
| `fix_prompt` | `true` | Allow `bordercheck fix`, which prints this machine's findings with rules an AI coding assistant can follow to fix them together with its user, and let the portal's report page offer the one-line prompt that starts it. `false` turns both off. Needs bordercheck v0.5.0 or later on every machine of the role (older ones reject the unknown field). |
| `compromise_alert` | `true` | Mark a report **compromised** when a finding is a sign that hostile code is already on the machine (see [Signs of compromise](#signs-of-compromise)), and send it as soon as a check finds a new sign, or the signs clear, whatever `interval` says. `false`: no mark and no early report; those findings report as ordinary fails. Needs a bordercheck with this feature on every machine of the role: an older one rejects the unknown field and keeps its last good policy. |

### Signs of compromise

Most findings are open doors: something that makes an attack easier. A few are signs that the attack has
already happened. Those findings carry a **sign of compromise**, and only these, for now:

| Check | Sign | Why it counts |
|---|---|---|
| `startup-items` | An item that starts at login or on a schedule runs a command that downloads code and runs it (`curl … \| sh`, `powershell -enc …`, `iex (… DownloadString …)`, `mshta http…`, `certutil -urlcache`) | That is how droppers keep themselves on a machine. An item the policy's `allow` list matches is not checked. A program in an odd place, one anyone can change or one that is missing is an ordinary finding. |
| `extensions` | An installed extension (even disabled) matches the policy's `block` list | IT has declared it malicious or forbidden. An extension from outside a store, or one not on the `allow` list, is an ordinary finding. |
| `cracked-software` | A crack tool is installed (KMSpico, AutoKMS), or Windows or Office activates against a KMS server on the machine itself (a KMS emulator) | A program from the crack scene that runs with the system's rights, and the usual carrier of bundled malware. A hosts-file line that blocks Adobe's or Autodesk's licence servers is an ordinary finding: it runs nothing. |

This is a small set of strong signs that bordercheck already sees, not malware detection: bordercheck is not an
antivirus, and a machine without these signs is not proven clean. A sign counts only on a result that fails: a
waived result, a disabled check and a finding the person ignored with `bordercheck ignore` (which these checks do
not offer) never mark a report.

When a report carries a sign:

- **The report** has `"compromised": true` and `"compromise_checks"`; each result lists its signs under
  `compromise` (what it is; which item only when `include_evidence` is on). The flag and the check IDs go whatever
  `include_evidence` says.
- **It goes at once.** The service sends a report as soon as a scheduled check finds the signs changed (new, a
  different one, or gone), instead of waiting for `interval`, and tries again every hour until it gets through.
  The same signs are not sent again until the next ordinary report. A sign is noticed within about an hour
  whatever `check_interval` says: on every hourly wake the service runs just the checks that can show one
  (`startup-items`, `extensions`, `cracked-software`; under a second together), and when what they find differs
  from the last check, it runs every check and sends the report.
- **The person at the machine** sees it first in `bordercheck`, `bordercheck status` and the desktop notification:
  stop using the computer for work, tell IT, do not just delete the item. `bordercheck fix` tells the AI assistant
  to stop and send the person to IT instead of fixing anything; this is the one case where it advises changing
  passwords and rotating keys, after IT has looked.
- **The portal** shows the machine as Compromised and sends a webhook alert right away (see the
  [portal guide](portal.md#signs-of-compromise)).

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
| `open_report` | `true` | When a notification announces a high-severity problem for the first time and the receiver returned a link to the machine's report page, open it in the browser by itself. Reminders of the same problem do not open it again. Not needed, and so not done, on a Mac where bordercheck's own notifications are allowed: there every notification opens the page when clicked ([details](install.md#report-page)). Windows, Linux and Macs still on Script Editor notifications are unchanged. |

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

A waiver for `tailscale` (the check before it became part of `mesh-vpn`) is still accepted, and applies to a
`mesh-vpn` result whose only finding is Tailscale's; a finding of another tool there needs a `mesh-vpn` waiver.

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
| `suggest_outbound` | `true` | macOS and Windows: warn (low) when nothing controls which apps connect out, and suggest a free, open-source outbound firewall. See below. |

The built-in firewalls of macOS and, by default, Windows only filter incoming connections. An outbound firewall
decides which apps may connect out, which is how malware phones home and how data leaves. With
`suggest_outbound`, when none is found:

| OS | Counts as already having one | Suggested |
|---|---|---|
| macOS | LuLu, Little Snitch, Radio Silence or Vallum in `/Applications` or `~/Applications` | [LuLu](https://objective-see.org/products/lulu.html) from Objective-See |
| Windows | simplewall, Fort Firewall, Portmaster, TinyWall or Windows Firewall Control, found by an uninstall entry, a folder under Program Files or ProgramData, a running service or (simplewall, often portable) a running process; or Windows Firewall set to block outgoing connections by default, by Group Policy or locally, on the profile of every connected network | [simplewall](https://github.com/henrypp/simplewall); the fix warns that it blocks every app not yet allowed and asks the person to allow each one as it first connects |

When one is found, nothing is suggested and the summary names it. A passing firewall becomes a low-severity
`warn` when none is found, which changes neither the exit status nor, with the default `notify` settings, the
notifications. When the firewall itself is off, the result asks only to turn it on.

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

| `info_only` | `["ControlCenter", "DropboxFileProvider", "Dropbox", "Spotify"]` | Process names (compared without case) whose open ports are **listed for information, not as a problem**, when nothing else is exposed: AirPlay Receiver (`ControlCenter`), Dropbox LAN sync, Spotify Connect. The check then passes and its evidence names them. They are well-known services, low risk on an up-to-date system, though reachable by anyone on the same network (AirPlay Receiver has had remotely exploitable bugs, fixed in system updates). With any other port exposed the check warns as usual and lists them all. `[]` makes each of them a finding again. |

Example: `"allow": [{"process": "rapportd"}, {"process": "ControlCenter", "port": "7000"}]` (AirPlay Receiver).

### mesh-vpn

Private networks (mesh VPNs, overlay networks) put the laptop on a network whose other members can open
connections to it, often past the OS firewall. For each tool that is installed:

| Tool | Connected when | Blocks incoming connections when |
|---|---|---|
| Tailscale | (always judged, as the former `tailscale` check) | "Allow incoming connections" is off (shields up), from `tailscale debug prefs`. On: **fail, high**. |
| ZeroTier | `zerotier-one` runs and has joined a network (`networks.d/*.conf`; on Linux a `zt…` interface, on Windows a "ZeroTier One" one) | Never: only the network's flow rules, set by its admin. |
| NetBird | the `netbird service run` daemon runs (with the `wt0` interface on Linux) | "Block inbound connections" (`netbird up --block-inbound`, `BlockInbound` in `/etc/netbird/config.json` or `%ProgramData%\Netbird\config.json`). That file is usually readable by root only; then the check says it could not tell. |
| WireGuard | a tunnel is up: Linux interfaces of type `wireguard` (other than NetBird's `wt0`), the macOS app's connected tunnels (`scutil --nc list`) and `wg-quick`'s, the Windows app's `WireGuardTunnel$…` services | Never: WireGuard has no such switch. |
| Nebula | `nebula` runs | its config (`-config`, when readable) has no rules under `firewall.inbound`. |
| Hamachi | `hamachid` or the `Hamachi2Svc` service runs, with its `ham0` / "Hamachi" interface | Never. |

Connected and not blocking (or the tool cannot block): **warn, medium**, with the tool's own control or the
host firewall as the fix. Installed but not connected: pass, with a word. Where the state cannot be read without
admin rights, a note says so instead of guessing. Nothing installed: skipped. It only reads (process list,
interfaces, the tools' state files) and runs no tool's command except `tailscale debug prefs`. Consumer VPNs
(including Cloudflare WARP / 1.1.1.1) are outbound only and not judged; Twingate does not make the laptop
reachable. Tailscale Funnel and Serve are judged by `tunnels`.

| Field | Default | |
|---|---|---|
| `allow` | `[]` | Tools that may accept incoming connections: `tailscale`, `zerotier`, `netbird`, `wireguard`, `nebula`, `hamachi`. They are listed as allowed instead. |

`mesh-vpn` and its fields need a client that knows them (bordercheck v0.5.0 or later): an older one rejects a policy that sets
them, so roll the client out to every machine of a role before adding `mesh-vpn` to its policy.

**`checks.tailscale`** (clients up to v0.4 had a separate `tailscale` check) is still accepted and applies to
Tailscale only: `"enabled": false` leaves Tailscale out of `mesh-vpn` (the other tools are still judged unless
`mesh-vpn` itself is off); `on_problem` sets the status when Tailscale is `mesh-vpn`'s only finding, unless
`mesh-vpn` sets its own `on_problem`, which wins. `-print-policy` shows `tailscale` only when the policy sets it.
`bordercheck -only tailscale` runs `mesh-vpn`. A policy for a mix of old and new clients can keep
`"tailscale": {…}` and leave `mesh-vpn` out.

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
| `show_tail` | `true` | Show the last 4 characters of long provider tokens (OpenAI, GitHub, AWS…), as their own dashboards do, so people can tell which key it is. Passwords never show anything. |
| `walk_depth` | `5` | How many folders below home are searched for `.env` and key files, 0–20. Files and folders kept only in iCloud Drive or another cloud provider (placeholders, not on this disk) are not read, since reading one downloads it; apps, media libraries and disk-image bundles are skipped. |
| `extra_patterns` | `[]` | Your own token formats: `{"kind": "Acme token", "regex": "\\bacme_[A-Za-z0-9]{32}\\b", "high": true, "show_tail": true}`. `kind` and a valid Go regular expression are required; `high` makes a match fail; `show_tail` is safe only for long random tokens. They are tried before the built-in rules. |
| `locations` | all `true` | Credential stores read format by format; each switches off alone. |
| `user_ignore` | `true` | Let the person at the machine mark findings as not sensitive with `bordercheck ignore <path> [-name VAR] -reason "…"` ([how](install.md#secrets-that-are-not-sensitive)); `ai-agents` and `ssh-keys` have the same switch. Ignored findings stop counting toward this check, but every report lists them with the reason in the result's `user_ignored`, also when `include_evidence` is off; the portal shows them on the machine's page. A finding marked `[production]` can be ignored too, and is listed for IT as production. `false`: `bordercheck ignore` refuses and existing entries are not applied (the summary says so). Needs bordercheck v0.5.0 or later on every machine of the role when set (older ones reject the unknown field); leaving it out keeps the default on new clients and works with old ones. |
| `sample_rules` | `["git-tracked", "sdk", "sample-dir"]` | Which rules set a finding aside as a likely sample key ([what each does](install.md#sample-keys)): `git-tracked` (tracked by a git repository below the home folder and unchanged from what its index records; read without running git), `sdk` (files an SDK ships to every user, such as Tizen Studio's certificates), `sample-dir` (a folder named like `demo`, `samples`, `examples`, `fixtures`, `testdata`, `mocks`). A likely sample stops counting toward the check, and every report lists it in the result's `likely_samples` (path, name or kind, rule; never a value), also when `include_evidence` is off; the portal shows it on the machine's page. `[]` turns this off; an unknown rule is an error. Never set aside: findings marked `[production]`, files inside `.git`, and by `sample-dir` alone a live-looking provider token. Caveat: a real secret committed to a repository also matches `git-tracked`; that is why the list goes to IT and production-marked findings are excluded. Needs a client that knows the field on every machine of the role when set (older ones reject the unknown field); leaving it out keeps the default on new clients and works with old ones. |

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
| `git_remotes` | Passwords and tokens in git URLs: `url`/`pushurl` in the `.git/config` of repositories the walk above reaches (same `walk_depth`, `ignore_paths` and skipped folders), and `url.<base>.insteadOf` rules in `~/.gitconfig` | a plain user name (`git@`, `alice@`); `${VAR}` placeholders |

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
| `allow` | `["guest"]` | Services that may be on: `ssh`, `screen-sharing`, `remote-management`, `remote-apple-events`, `rdp`, `winrm`, `guest`, and the remote-control apps `teamviewer`, `anydesk`, `rustdesk`, `chrome-remote-desktop`, `splashtop`, `screenconnect`, `vnc` (e.g. your organisation's official tool). A guest account is accepted by default; `"allow": []` reports it too. Allowed ones are listed as "on but allowed by policy". |
| `third_party` | `true` | Also look for remote-control apps of other vendors (below). `false` judges the OS's own services only. |

macOS: Remote Login (SSH), Screen Sharing, Remote Management, Remote Application Scripting, Guest User. Linux:
SSH server, xrdp / GNOME Remote Desktop, VNC servers, LightDM guest session. Windows: Remote Desktop, WinRM,
OpenSSH Server, Guest account. Never goes online.

Remote-control apps: whoever has the app's ID and password, or takes over the vendor account it is linked to,
controls the whole machine. Per app:

- installed only (nothing running, nothing set to start): not a problem; the evidence lists it.
- running, or set to start by itself (a LaunchAgent/LaunchDaemon that runs at load or is kept alive, not an
  on-demand helper; a Windows service that runs or starts automatically; an enabled or active systemd unit):
  **warn, medium**.
- open to unattended access, where its files show it without admin rights: **fail, high**. AnyDesk: a password
  on a permission profile (`ad.security.permission_profiles.<profile>.pwd`, AnyDesk 7+) or the older
  `ad.anynet.pwd_hash`, in `system.conf`/`service.conf` (`/etc/anydesk`, `~/.anydesk`, `%ProgramData%\AnyDesk`,
  `%AppData%\AnyDesk`); only whether the value is empty is looked at. Chrome Remote Desktop: remote access turned
  on (`/Library/PrivilegedHelperTools/org.chromium.chromoting.me2me_enabled` on macOS,
  `~/.config/chrome-remote-desktop/host#….json` on Linux).

TeamViewer (permanent password, Easy Access), RustDesk and Splashtop keep their unattended settings where they
cannot be read reliably; a running copy gets a "could not tell" note. Apps recognised: TeamViewer, AnyDesk,
RustDesk, Chrome Remote Desktop (host), Splashtop Streamer (Windows and macOS), ConnectWise ScreenConnect access
agents, VNC servers (RealVNC, TigerVNC, TightVNC, UltraVNC, x11vnc). Viewers (VNC Viewer, Microsoft Remote
Desktop / Windows App) are not judged. Not recognised yet: Parsec, LogMeIn, NoMachine, Zoho Assist, GoToMyPC,
Jump Desktop Connect. Helpers registered through macOS's Background Task Management (`SMAppService`) are only
seen while they run. None of this counts as a sign of compromise: it is an open door.

`third_party` and the app names in `allow` need a client that knows them (bordercheck v0.5.0 or later); an older client
rejects a policy that sets them, so update every machine of a role first.

### ssh-keys

Private keys in `~/.ssh` and those named by `~/.ssh/config`, judged by reading their file format. Key material
is never shown, only type, fingerprint and comment. Hardware (FIDO) keys pass.

| Field | Default | |
|---|---|---|
| `no_passphrase` | `true` | Flag private keys stored without a passphrase. |
| `loose_permissions` | `true` | Flag private keys other users can read (macOS and Linux; Windows ACLs aren't read yet). |
| `authorized_keys` | `true` | List the keys in `authorized_keys` that can log in to this machine. |
| `allow_keys` | `[]` | Globs of keys exempt from every rule, e.g. `"~/.ssh/ci_deploy"`. |
| `client_config` | `true` | Read `~/.ssh/config` and the files it `Include`s under `~/.ssh` for `ForwardAgent` (other than `no`), `StrictHostKeyChecking no`/`off` and `UserKnownHostsFile /dev/null`. At the top level, under `Host *` (even with `!` exceptions) or `Match all`: warn medium; under other `Host`/`Match` lines: low. Evidence: file, line and the `Host` line. |
| `user_ignore` | `true` | Let the person at the machine mark a key without a passphrase as not sensitive (`bordercheck ignore ~/.ssh/aur -reason "…"`, [how](install.md#secrets-that-are-not-sensitive)); it stops counting but every report lists it with the reason. Only a key whose one problem is the missing passphrase: readable keys, `authorized_keys` and client settings cannot be ignored. `false` turns it off for this check. Needs a client that knows the field, like `secrets.user_ignore`. |

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
| `user_ignore` | `true` | Let the person at the machine mark a plain-text token as not sensitive (`bordercheck ignore ~/.claude.json -name Authorization -reason "…"`, [how](install.md#secrets-that-are-not-sensitive)); it stops counting but every report lists it with the reason. Guardrail findings cannot be ignored; a token marked production can, and is listed for IT as production. `false` turns it off for this check. Needs a client that knows the field, like `secrets.user_ignore`. |

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

### admin-rights

How much an attacker gets by running code as the person at the keyboard. Reads group membership, `sudo -n -l`
(never prompts: `-n` makes sudo fail rather than ask for a password or Touch ID), any sudoers file a normal user
may read, and on Windows the UAC registry values and the built-in Administrator account. Evidence holds group
and setting names only.

| Finding | Result |
|---|---|
| `sudo` runs every command without a password (`NOPASSWD: ALL`, `Defaults !authenticate`) | fail, high |
| `sudo` runs some commands without a password | warn, medium |
| Windows: UAC off (`EnableLUA = 0`) | fail, high |
| Windows: UAC elevates administrators without asking (`ConsentPromptBehaviorAdmin = 0`) | fail, high for an administrator; warn, medium otherwise |
| The account is an administrator (macOS `admin`; Linux `sudo`, `wheel` or `admin`; Windows Administrators) | warn, low (medium or high when another finding here applies) |
| Windows: the built-in Administrator account is enabled | warn, medium |

`sudo -n -l` lists rules without a password only when one of them is `NOPASSWD` (sudo's default
`listpw=any`) or a recent `sudo` is still cached; the check looks for the rule in the list, so a cached `sudo`
does not count.

| Field | Default | |
|---|---|---|
| `allow_admin` | `false` | Accept an administrator account. Passwordless `sudo` and UAC are still judged. |

### os-protections

The OS's own malware defences. XProtect's updates are judged by `os-updates` ("Install Security Responses and
system files").

| Looks for | OS | Result |
|---|---|---|
| System Integrity Protection off (`csrutil status`); partly off | macOS | fail, high; warn, medium |
| Gatekeeper off (`spctl --status`) | macOS | fail, high |
| Microsoft Defender real-time protection off (or Defender passive) and no other antivirus on in Security Center | Windows | fail, high |
| Defender tamper protection off, when Defender is the active antivirus | Windows | warn, medium |
| SmartScreen "Check apps and files" off (`SmartScreenEnabled`, or the `EnableSmartScreen` policy) | Windows | warn, medium |
| Secure Boot off (`UEFISecureBootEnabled` in the registry; the SecureBoot EFI variable or `mokutil --sb-state` on Linux). Legacy BIOS is noted, not judged. | Windows, Linux | warn, medium |
| Neither AppArmor nor SELinux active, or SELinux permissive | Linux | warn, medium |

Skipped under WSL.

| Field | Default | |
|---|---|---|
| `sip` | `true` | Judge System Integrity Protection. |
| `gatekeeper` | `true` | Judge Gatekeeper. |
| `antivirus` | `true` | Judge Defender (or another antivirus) and tamper protection. |
| `smartscreen` | `true` | Judge SmartScreen. |
| `secure_boot` | `true` | Judge Secure Boot. |
| `lsm` | `true` | Judge AppArmor / SELinux. |

### sharing

What the machine offers nearby devices and the local network, beyond what `remote-access` covers (remote
login, screen sharing, Remote Apple Events and guest accounts are there). Each setting is read as one key; share
names appear in the evidence, file contents never do.

| Service (`allow` name) | OS | Result when on |
|---|---|---|
| AirDrop discoverable by Everyone (`airdrop`) | macOS | warn, medium |
| File Sharing (`file-sharing`) | macOS | warn, medium |
| Printer Sharing (`printer-sharing`) | macOS, Linux (CUPS) | warn, medium on macOS; low on Linux |
| Internet Sharing (`internet-sharing`) | macOS | fail, high |
| Media Sharing (`media-sharing`) | macOS | warn, medium when shared with guests; low for Home Sharing |
| Bluetooth Sharing (`bluetooth-sharing`) | macOS | warn, medium |
| Content Caching (`content-caching`) | macOS | warn, low |
| Shared folders (`file-sharing`), excluding the hidden admin shares | Windows | warn, medium; fail, high when File and Printer Sharing is also allowed on public networks |
| Network discovery or File and Printer Sharing allowed on public networks (`network-discovery`) | Windows | warn, medium |
| Shared printers (`printer-sharing`) | Windows | warn, low |
| Nearby sharing set to Everyone nearby (`nearby-sharing`) | Windows | warn, medium |
| Samba (`file-sharing`) | Linux | warn, medium; fail, high when a share allows guests (`guest ok`/`public = yes`) |
| NFS server (`nfs`) | Linux | warn, medium; fail, high when `/etc/exports` exports to any host |
| GNOME File Sharing (`gnome-file-sharing`) | Linux | warn, medium |

| Field | Default | |
|---|---|---|
| `allow` | `[]` | Services that may be on, by the names above. |
### extensions

Browser and code-editor extensions. A malicious or hijacked extension sees everything you do in the browser or the
editor. The check reads each profile's own files and nothing else (an unpacked extension's folder is not opened),
and never goes online.

| Reads | Where |
|---|---|
| Chrome, Edge, Brave, Chromium, Vivaldi, Arc (macOS): `extensions.settings` in each profile's `Preferences` and `Secure Preferences` (install location, enabled state), and `Extensions/<id>/<version>/manifest.json` (name, version, update URL, permissions) | every OS |
| Firefox: each profile's `extensions.json` (location, signed state, source, granted origins); add-ons that ship with Firefox are skipped | every OS |
| VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium: `~/.vscode/extensions/extensions.json` and the equivalents (`publisher.name`, version, whether it was installed from a VSIX file) | every OS |

Safari is not covered: its data is in a container macOS guards with a privacy prompt. Extensions forced by the
browser's enterprise policy and those built into the browser are not counted.

| Finding | Result |
|---|---|
| On `block` (even when disabled) | fail, high |
| Not on `allow`, when `allow` is set | warn, medium |
| From outside a store: loaded unpacked or with `--load-extension`, installed from a file, put in place by another program with a non-store update URL; in Firefox loaded temporarily, unsigned or sideloaded; in an editor installed from a VSIX file | warn, medium |
| Can read and change every website (`<all_urls>`, `*://*/*`…) | counted in the summary; warn, medium with `warn_all_sites` |

| Field | Default | |
|---|---|---|
| `browsers` | `true` | Check browser extensions. |
| `editors` | `true` | Check editor extensions. |
| `block` | `[]` | Extensions that fail the check: a browser extension ID (Chrome's 32-letter ID, Firefox's add-on ID) or `publisher.name` for editors. `*` matches any characters; case does not matter. |
| `allow` | `[]` | When not empty, every enabled extension not on it warns (allowlist mode). Same syntax as `block`. |
| `warn_all_sites` | `false` | Warn on extensions that can read and change every website. |
| `allow_unpacked` | `[]` | Extensions that may come from outside a store, e.g. your own internal ones. |

### browser-passwords

Passwords saved in the browser's own password manager: information stealers take them first. The check counts
saved logins without reading one: in Chromium's `Login Data` and `Login Data For Account` (SQLite files) it reads
the schema and the page headers of the `logins` table and adds up the rows, never decoding a row; from Firefox's
`logins.json` only the number of entries is kept. No site, user name or password is ever read into the result.
A database it cannot count (an unexpected layout) falls back to its size: larger than an empty one (40 KB) is
taken as holding saved logins, which can be wrong both ways.

| Reads | |
|---|---|
| Chromium browsers | `credentials_enable_service` in `Preferences` ("Offer to save passwords", on unless false); the number of rows in the login databases |
| Firefox | `signon.rememberSignons` in `prefs.js` ("Ask to save passwords"); the number of entries in `logins.json` |

A profile with fewer saved logins than `pass_below` is not a finding (a handful are rarely someone's main
passwords; the summary still says so). From there up to `medium_above` in every profile the check warns with low
severity; more than that in any profile warns with medium. Saving on with nothing saved passes with a note. A setting forced by
the browser's enterprise policy is not read. Whether Firefox has a primary password is not checked: that needs
`key4.db`, which the check does not open.

| Field | Default | |
|---|---|---|
| `allow_browsers` | `[]` | Browsers whose password manager you use on purpose: `chrome`, `edge`, `brave`, `chromium`, `vivaldi`, `arc`, `firefox`. |
| `pass_below` | `10` | A profile with fewer saved logins than this is not counted. `0` = any saved login is a finding. |
| `medium_above` | `20` | Up to this many saved logins in every profile is a low warning; more in any profile, or a profile whose logins could not be counted, is medium. `0` = no low tier. |

### trust-store

Root certificates added to the trust store, and a proxy. Whoever holds an added root's key can read this machine's
HTTPS traffic that passes through them, and a proxy sees every site visited. Company TLS inspection and developer
tools (mkcert, mitmproxy, Charles, Fiddler, Burp) add them too, so the default is a warning that says so, naming the
tool when the certificate's name matches.

| Reads | |
|---|---|
| macOS | `security dump-trust-settings` for the user and admin domains (Apple's roots are not listed), `security find-certificate` for the fingerprint and expiry, `scutil --proxy`. None of these shows a dialog. Certificates trusted for one host name only (for example a remote desktop's) are counted in a note, not flagged. |
| Windows | The current user's own Root store (`HKCU\Software\Microsoft\SystemCertificates\Root`; Windows asks before a root is added there), and `ProxyEnable`, `ProxyServer`, `AutoConfigURL` under Internet Settings |
| Linux | `/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`, `/etc/ca-certificates/trust-source/anchors`; GNOME's proxy settings (`gsettings`). Browsers' own NSS databases are not read. |
| Every OS | `http_proxy`, `https_proxy`, `all_proxy` (either case) in bordercheck's environment |

A proxy on the machine itself (`127.0.0.1`, `localhost`) is usually a local tool such as a VPN client and is only
noted. Evidence shows the certificate's common name, SHA-256 fingerprint and expiry, and the proxy's host and port
(or the PAC URL without user name, password or query).

| Field | Default | |
|---|---|---|
| `cas` | `true` | Check added root certificates. |
| `proxies` | `true` | Check the proxy settings. |
| `allow_cas` | `[]` | Certificates that may be trusted: a SHA-256 fingerprint (hex, colons optional) or a glob on the subject common name (`Acme Corp *`). |
| `allow_proxies` | `[]` | Globs on the proxy or PAC host (`*.acme.example`). |
| `ca_severity` | `"medium"` | `low`, `medium` or `high` for an added root; `high` makes it fail. |
### package-managers

How the package managers on the machine are configured to fetch packages. Only tools that are installed (their
command is found, or they have a config file) are judged, and the check skips when there are none. It reads
config files only: it never runs the tools, never reads `node_modules` and never goes online. Evidence shows the
file, line, setting and at most a host name, never a whole URL (URLs can hold tokens).

| Tool | Files | Flagged |
|---|---|---|
| npm | `~/.npmrc` | `registry` or `@scope:registry` over `http://` and `strict-ssl=false` (fail, medium); `ignore-scripts` not `true` on npm 11 and older (warn, low; npm 12 runs dependencies' install scripts only once approved, so there only `dangerously-allow-all-scripts=true` is flagged); with `require_release_age`, no `min-release-age` (low) |
| pnpm | `config.yaml` and the older `rc` in `~/Library/Preferences/pnpm`, `~/.config/pnpm`, `%LOCALAPPDATA%\pnpm\config` | `dangerouslyAllowAllBuilds: true` (low); `minimumReleaseAge: 0` (low; pnpm 11 waits a day by default); `registry` over http, `strictSsl: false` (fail) |
| Yarn (Berry) | `~/.yarnrc.yml` | `enableScripts: true` (low); `npmMinimalAgeGate: 0` (low); `npmRegistryServer` over http, `enableStrictSsl: false` (fail) |
| Bun | `~/.bunfig.toml` (or `$XDG_CONFIG_HOME/.bunfig.toml`) | `[install]` `registry` or scoped registries over http (fail); with `require_release_age`, no `minimumReleaseAge` (low). Bun runs only trusted dependencies' scripts by default. |
| pip | `pip.conf` / `pip.ini` (user, legacy `~/.pip`, and site-wide) | `index-url`, `extra-index-url`, `find-links` over http; `trusted-host` (fail, medium) |
| uv | `uv.toml` (user and `/etc/uv`) | `index-url`, `extra-index-url`, `[[index]] url` over http; `allow-insecure-host` (fail, medium) |
| Go | the `go env -w` file (`go env GOENV`) | `GOINSECURE` and `GOPROXY` over http (fail, medium); `GOSUMDB=off`, `GONOSUMDB=*` or `GOPRIVATE=*` (warn, medium) |
| Cargo | `$CARGO_HOME/config.toml` (`~/.cargo`) | a registry `index` or source `registry` over `http://` or `sparse+http://` (fail, medium) |

Addresses on the machine itself (`localhost`, `127.0.0.1`, `::1`) are always fine. `GOFLAGS=-insecure` is not
flagged: Go removed that flag in 1.17.

| Field | Default | |
|---|---|---|
| `tools` | all: `["npm", "pnpm", "yarn", "bun", "pip", "uv", "go", "cargo"]` | Which tools to judge. |
| `require_ignore_scripts` | `true` | Warn (low) when a package manager runs every dependency's install scripts: npm 11 and older without `ignore-scripts=true`, `dangerously-allow-all-scripts`, pnpm `dangerouslyAllowAllBuilds`, Yarn `enableScripts: true`. |
| `require_release_age` | `false` | Also warn (low) when npm or Bun has no minimum release age, so a version published minutes ago is installed. pnpm and Yarn are flagged only when their default gate is set to 0. |
| `allow_hosts` | `[]` | Globs of host names that may be used over http or as a trusted host, e.g. `"*.corp.example"` for an internal registry. Also matched against `GOINSECURE` patterns. |

### startup-items

What starts at login or on a schedule, as an inventory with a light touch: not an antivirus. Most items are only
counted ("28 items start at login or on a schedule; nothing unusual"). Commands are judged but never shown, since
they can hold tokens; evidence shows the source, file, label and program path. bordercheck's own service is never
counted or flagged.

| OS | Read |
|---|---|
| macOS | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` (label and program; disabled ones are left out). Login Items are not read: listing them needs root. |
| Linux | `~/.config/autostart/*.desktop`, systemd user units enabled in `~/.config/systemd/user`, `crontab -l` |
| Windows | `HKCU` and `HKLM` `Run` / `RunOnce`, the user's and the common Startup folder (shortcuts resolved), enabled scheduled tasks outside `\Microsoft\` |

| Flagged | |
|---|---|
| A command that downloads code and runs it (`curl … \| sh`, `sh -c "$(curl …)"`, `base64 -d \| sh`, `powershell -enc …`, `iex (… DownloadString …)`, `mshta http…`, `certutil -urlcache`) | fail, high |
| A program (or the script an interpreter runs) in `/tmp`, `/var/tmp`, `/private/tmp`, `/Users/Shared`, `~/Downloads`, `%TEMP%`, `C:\Windows\Temp`, or a hidden folder directly in home that developer tools don't use (`~/.local`, `~/.cargo`, `~/.nvm`… are fine) | warn, medium |
| A program, or its folder, that every user can write to (macOS, Linux) | warn, medium |
| A program that no longer exists | warn, low |

On macOS, programs under `~/Desktop`, `~/Documents`, `~/Downloads`, other apps' containers and `/Volumes` are
not looked at on disk (that could raise a privacy prompt), so they are never reported missing.

| Field | Default | |
|---|---|---|
| `allow` | `[]` | Globs on an item's label or program path (`~` allowed) to leave out, e.g. `"com.acme.*"`, `"~/.acme/bin/*"`. |
| `extra_suspicious_paths` | `[]` | More folders a program should not start from, e.g. `"~/Public"`. |

### backup

Can a lost or stolen laptop be found, and its files restored? Severities stay low, except for an unencrypted
backup: a backup disk is a copy of the whole disk, so an unencrypted one undoes FileVault. Nothing needs admin
rights or prompts; what cannot be read is said in a note.

- macOS: Time Machine destinations from `tmutil destinationinfo`, and their encryption and last backup from
  `/Library/Preferences/com.apple.TimeMachine.plist` (if reading them needs Full Disk Access, the check says it
  could not tell). Find My Mac is read from `FMMEnabled` in `/Library/Preferences/com.apple.FindMyMac.plist`;
  without that file, it is taken as on when NVRAM holds its token (`fmm-mobileme-token-FMM`; only the name is
  looked at).
- Windows: Find my device (`LocationSyncEnabled`, and the `AllowFindMyDevice` policy). File History, Windows
  Backup and OneDrive backups are not read.
- Linux: skipped; there is no standard backup or device-finding service to read.

| Field | Default | |
|---|---|---|
| `require_backup` | `false` | Warn (low) when no Time Machine backup is set up. Off by default because many organisations back up another way. |
| `require_encrypted` | `true` | Warn (medium) for a Time Machine backup that is not encrypted. |
| `require_find_my` | `true` | Warn (low) when Find My Mac / Find my device is off. |
| `max_backup_age_days` | `0` | Warn (low) when the last backup to a destination is older than this, 0–3650; `0` = don't check. |

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
    "mesh-vpn":   { "allow": ["tailscale"] },
    "os-updates": { "min_os_versions": { "macos": "26", "fedora": "" },
                    "min_browser_versions": { "chrome": "157.0.8103.39" } },
    "remote-access": { "allow": ["ssh", "teamviewer"] },
    "ssh-keys":   { "authorized_keys": false, "allow_keys": ["~/.ssh/ci_deploy"] },
    "tunnels":    { "lower_severity": ["cloudflared"] },
    "ai-agents":  { "extra_paths": ["~/.config/acme-agent/mcp.json"] }
  }
}
```
