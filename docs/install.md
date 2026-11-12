# Installing bordercheck on laptops

Installed, bordercheck runs every hour as a per-user service (no admin rights), reports to your organisation,
keeps its policy and itself up to date, and tells the person at the machine about new problems.

There are two ways to set machines up:

| | Invite links (enrolled) | `policies.json` (static) |
|---|---|---|
| What IT does | runs the [portal](portal.md), creates an invite per person, sends them one command | hosts one `policies.json` for everybody and runs its own report endpoint |
| What the person does | runs the command; nothing to type | runs the command and types their work email |
| Who sets the email | IT, in the invite | the person (limited by `report.email_domains`) |
| Report credential | a token for this install only | whatever your endpoint checks, e.g. one header in the policy, shared by every machine and readable by anyone who can fetch the file |
| Policy | chosen by the person's role, fetched with the install's token | the same file for everyone |
| IT can cut one machine off | yes, revoke that install | no, only rotate everybody's credential |

Use invite links with the bordercheck portal. Use a `policies.json` for any other report endpoint. Without any
endpoint, put `policies.json` beside the binary and people run `bordercheck` by hand: a plain run reads the
policy and sends nothing.

## With an invite link

IT creates an invite for the person in the portal and sends them the command it shows. macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh | sh -s -- https://bordercheck.acme.com/i/<code>
```

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/i/<code>
```

Or, with the binary already there: `bordercheck install https://bordercheck.acme.com/i/<code>`.

bordercheck copies itself into the [install folder](#the-service) and checks that the hourly service can be
registered, then spends the code (`POST /enroll`) and gets back this install's ID, the email and role IT set, a
token, and the URL of the policy for that role. It fetches the policy with the token, registers the service and
sends a first report. There is no email question; `-email` with an invite link is an error.

- **A code works once.** If something goes wrong before it is spent (no write access, no way to run a
  service), nothing is installed and the invite is still good. If something goes wrong after (the portal is
  down when the policy is fetched, the service fails to register), the enrollment is saved and the error says
  to run `<install folder>/bordercheck install` (or the same command again): that finishes the job without a new
  invite. If the network drops while the code is being sent, bordercheck cannot know whether it was spent; run
  the command again, and if it says the invite was used, ask IT for a new one.
- **A new invite on an enrolled machine replaces the enrollment** (new install ID, token, email and role) once
  the new code has been accepted; until then the old one keeps working. Waivers keyed by the old install ID stop
  applying. Going from an enrolled install to a `policies.json` install needs `bordercheck uninstall` first.
- **Refusals** say what to do: an invalid link (check you copied all of it), an expired, used or cancelled
  invite (ask IT for a new one; a used invite you did not use yourself is worth telling IT about), or too many
  attempts (wait a few minutes).

### What is stored

In the install folder:

| File | Holds | Access |
|---|---|---|
| `config.json` | install ID, email, role, the portal's address, the policy URL, a hash of the spent invite code, the pinned update source | this user (`0600`) |
| `token` | the install's token, nothing else | this user (`0600`); never printed, logged, put in `state.json`, a report or `bordercheck status` |
| `policies.json` | the last good policy from the portal | this user (`0600`) |

On Windows file modes don't apply: `%LOCALAPPDATA%\bordercheck` inherits the profile folder's permissions, so
the token can be read by the user, SYSTEM and local Administrators, like the rest of their profile, and not by
other standard users. On macOS and Linux root can read it too.

### How the token is used

Every hourly run fetches the policy with `Authorization: Bearer <token>` and posts the report with it. The token
is sent **only** to the portal that issued it: over https, never following a redirect, and only to the exact
host of the invite link. A policy that points `report.url` or `update.policy_url` at another host is refused and
the last good policy kept (with the reason in the log), rather than sending reports somewhere without the
token: that keeps reports going to IT and makes the mistake visible.

If the portal answers `401 {"error": "revoked"}`, IT has revoked this install: `bordercheck status` says so, the
person gets one desktop notification, no more reports are sent, and the service asks the portal again only once
a day (a report that gets through clears it). `bordercheck uninstall` deletes the token; it does not tell the
portal, which has no endpoint for that, so IT revokes or forgets the machine there.

What enrollment does and does not prove:

- A report carrying the token came from that install: nobody else can submit or overwrite its reports or claim
  its email, and IT can revoke it alone.
- It does not prove the machine tells the truth. The person at the machine can read the token and send whatever
  they like with it, as with any self-reported check.
- An invite link is a bearer credential until it is used or expires: whoever has an unused link can enroll a
  machine as that person. Send invites over a channel only that person reads, keep their lifetime short, and
  revoke ones that went astray.

## With a policies.json

Write a policy with a `report.url` (see [Policies](policies.md)), host it at an HTTPS URL, and have people run
one command. macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh | sh -s -- https://bordercheck.acme.com/policies.json
```

Windows (PowerShell):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/policies.json
```

The script picks the latest release for the OS and CPU, [checks it](#what-the-install-script-proves), and runs
`bordercheck install <url>`, which asks for the person's work email on the terminal.

Already have the binary? `./bordercheck install https://bordercheck.acme.com/policies.json` does the same, or
hand people a zip with `bordercheck` and `policies.json` side by side and they run `./bordercheck install`.
`-email you@acme.com` skips the question.

Your endpoint receives a `POST` of the [report](#what-is-sent) with the headers in `report.headers`. Anything in
those headers can be read by everyone who can fetch the policy, so give it a token that can only submit reports,
and treat reports as unauthenticated.

## Install script options

| `install.sh` | `install.ps1` | |
|---|---|---|
| `--email an@acme.com` | `-Email an@acme.com` | Don't ask for the email (scripted rollouts; not with an invite link) |
| `--version v1.2.3` | `-Version v1.2.3` | Install that release instead of the latest |
| `--dry-run` | `-DryRun` | Download and check, then stop before installing; never runs the downloaded binary |
| `--repo owner/name` | `-Repo owner/name` | Install from a fork; with an invite link, the installed copy also takes its [updates](#updates) from there |
| `--key <base64>` | `-Key <base64>` | The fork's ed25519 release key that must sign `SHA256SUMS` |

Options go before or after the URL. `install.sh --help` lists them.

## The service

Either way, install copies bordercheck and its policy to:

| OS | Install folder | Service |
|---|---|---|
| macOS | `~/Library/Application Support/bordercheck` | launchd LaunchAgent; runs while the person is logged in |
| Linux | `~/.local/share/bordercheck` (or `$XDG_DATA_HOME/bordercheck`) | systemd user timer `~/.config/systemd/user/bordercheck.timer`; runs while the person's systemd user session is up (`loginctl enable-linger` keeps it running when they are not) |
| Windows | `%LOCALAPPDATA%\bordercheck` | Task Scheduler task |

It registers an hourly per-user service (no admin rights) and sends a first report straight away. While that
first check runs, the terminal shows how far it is (checks done, percentage, which are still running), and the
install ends with a line saying it is done. The checks run together and get 90 seconds in all; one that is
still running then reports an error and the rest go through. The service
sends a report whenever `report.interval` has passed since the last one that got through, so a failed send
retries the next hour. On Linux, a login with no systemd user session (no systemd, some SSH or WSL setups) gets
a line in the user's crontab instead; `bordercheck status` says which.

When a check finds [signs of compromise](policies.md#signs-of-compromise) that differ from those last reported (new
ones, or the old ones gone), the service sends a report at once instead of waiting for `report.interval`, and
retries hourly until it gets through. It looks for them on every hourly wake, whatever `report.check_interval`
says, by running only the few checks that can show one. `bordercheck status` then starts with "Signs that this computer may be
compromised", lists them, says whether IT has been sent them, and what to do: stop using the computer for work,
tell IT, and do not just delete the item. Checks run every `report.check_interval` (or, when it is not set, only
when a report is due), so that is how soon a sign is noticed.

```sh
bordercheck status               # signs of compromise if any, email, enrollment, policy, what is sent, service, last report, report page, updates
bordercheck send -force          # send a report now
bordercheck fix                  # what to fix and how, as instructions an AI coding assistant can follow with you
bordercheck ignore <path> -reason "why"   # a secret, AI config token or SSH key that is not sensitive: stops counting, IT still sees it
bordercheck update               # refresh the policy and install a newer release now
bordercheck uninstall
```

## Notifications

Each time the service checks the machine (when a report is due), it shows a desktop notification for problems
that are new since the last check: the check IDs and summaries, and "Run bordercheck in a terminal to see how to
fix it". It never shows evidence (paths, ports, variable names), let alone a secret. A problem still there is
announced again every `notify.remind_every`; a fixed problem is forgotten, so it counts as new if it comes back;
waived results and passing machines stay silent. What was announced is kept in `state.json`. Which problems
notify is set in the policy's [`notify`](policies.md#notify).

A problem with [signs of compromise](policies.md#signs-of-compromise) is announced as such, and again when a fail
turns into one: the title is "bordercheck: this computer may be compromised", the text says what the signs are
(never which item) and "Stop using it for work and tell your IT team now. Do not delete the item yourself."

| OS | How | Needs |
|---|---|---|
| macOS | bordercheck's own app, `Bordercheck.app` in the install folder ([below](#borderchecks-notifications-on-macos)); until the person has allowed it, `osascript` `display notification` | the person's answer to macOS's question; the `osascript` fallback is listed as Script Editor in System Settings → Notifications |
| Windows | a toast through Windows PowerShell 5.1 | nothing; shown while the user is logged on |
| Linux | `notify-send`, else `gdbus` to the desktop's notification service | a desktop session |

A notification that cannot be shown is logged in `bordercheck.log` and tried at the next check; it never holds
up a report. `bordercheck send -force` (and the first report at install) is run by someone at a terminal, so it
prints the problems there instead and the next scheduled run does not repeat them. A plain `bordercheck` never
notifies.

### bordercheck's notifications on macOS

On a Mac, bordercheck installs a small app, `Bordercheck.app`, beside itself in the install folder (bundle ID
`io.github.ptrinh.bordercheck.notifier`, no Dock icon, it runs for a moment and quits). Notifications come from it,
so they show **bordercheck**'s name and shield icon, are listed as **bordercheck** in System Settings →
Notifications, and open the machine's report page when clicked.

**What the person sees.** A banner headed "bordercheck" with "1 problem on this computer", the problems, and
"Click to open your report page." when the receiver gave this machine a [report page](#report-page). Clicking
opens that page in the default browser. The link itself is never in the visible text.

**The permission question.** macOS asks once whether "bordercheck" may send notifications. bordercheck lets it ask
only while the person is at the terminal:

- `bordercheck install` run in a terminal (including `curl … | sh`): after the install lines, it says
  "bordercheck shows a notification when it finds a new problem on this computer; clicking it opens your report
  page. macOS will now ask whether "bordercheck" may send notifications. Choose Allow to get them.", then macOS
  asks, and install says what was chosen before running the first check.
- `bordercheck notifications`, any time later, which also reinstalls the app if it is missing or changed.

The hourly service never asks: it posts only if the person already allowed it.

| The person… | What happens | `bordercheck status` |
|---|---|---|
| allowed | notifications come from bordercheck; a click opens the report page | `Notifications: bordercheck's own (allowed in System Settings); …` |
| declined, or later turned bordercheck off in System Settings | **nothing** is shown: no Script Editor fallback, no browser. Reports go on as before | `Notifications: turned off for bordercheck in System Settings; …` |
| has not been asked (a scripted install with no terminal, an install upgraded from a version without the app) or did not answer | notifications come through Script Editor (`osascript`), as before | `Notifications: through Script Editor (osascript) until you allow bordercheck's own; run: bordercheck notifications` |

**To turn them off or back on:** System Settings → Notifications → bordercheck. macOS asks only once, so after a
"Don't Allow" `bordercheck notifications` just points there. An MDM configuration profile
(`com.apple.notificationsettings`) can allow or forbid notifications for `io.github.ptrinh.bordercheck.notifier`
ahead of time; bordercheck then uses that answer without anyone being asked, which suits scripted installs.

**Upgrades.** A copy that updates itself from a version without the app keeps using Script Editor until the
person runs `bordercheck notifications` (or `bordercheck install` again in a terminal); nothing pops up by
itself. Once installed, the app is replaced by the new version's after every self-update; macOS keeps the
person's answer, which belongs to the bundle ID.

**Fallback.** If the release has no app, the download or checks fail, or the app fails or does not answer,
bordercheck logs why and shows the notification through Script Editor. Uninstall removes the app; macOS may keep
a "bordercheck" entry in System Settings → Notifications until it tidies up.

**How the app is checked.** It is downloaded for bordercheck's own version from the pinned update source, like a
[binary update](#updates): only if the release's `SHA256SUMS` is signed by the trusted key and the zip matches it
(an enrolled install ignores any update source the portal names). It is installed only if its code signature is
valid, Developer ID, with that bundle ID; the Team ID is pinned at the first install, and a later app from
another team is refused. A digest of every file is recorded, and before each launch bordercheck checks the digest
and the signature again; a changed app is not run (`bordercheck notifications` reinstalls it). It is started
through `/usr/bin/open` with one fixed argument (`status`, `authorize` or `post`); the title, text and link go to
it in a file in the install folder readable only by this user, which is deleted when it quits, never on a
command line. Text from check results is cut to length and stripped of control characters by bordercheck and
again by the app, and treated as plain text. The app opens a link only if it is `https` on exactly the host
reports go to (checked by bordercheck and again by the app when clicked), never anything else, and runs nothing.

When a notification is clicked after the app has quit, macOS starts the app itself, without bordercheck's
pre-launch checks; it still runs only with a valid signature, as macOS checks it. macOS keeps a delivered
notification, with the link it opens, in its notification database for this user until it is cleared; the link
is otherwise in `state.json` for the same user.

### Report page

A receiver may answer a report with `{"report_url": "https://<host>/r/<id>"}`, a link to that
machine's own report that needs no login. bordercheck keeps it (in `state.json`, never in the log) only if it is
https on exactly the host reports go to, and shows it in `bordercheck status`.

- **With bordercheck's own notifications on a Mac**, every notification carries the link and opens the page
  when clicked. The page **does not open by itself**, whatever `notify.open_report` says: the person chooses
  when to look.
- **Otherwise** (Windows, Linux, and a Mac whose notifications still come through Script Editor, which cannot
  carry a link), when a notification announces a **high-severity** problem for the first time, the page also
  opens in the default browser (a `remind_every` reminder of the same problem only notifies; it does not open the
  page again): `open` on macOS, `rundll32 url.dll,FileProtocolHandler` on Windows, `xdg-open` on Linux, the link
  passed as one argument, never through a shell. Linux skips it quietly without a graphical session (a systemd
  user timer often has no `DISPLAY`). With `notify.open_report` off, or when the browser can't be opened, or on a
  reminder, the notification adds "Run bordercheck status for the link to your report page."
- **Notifications turned off for bordercheck** on a Mac: nothing is shown and the page does not open.

`bordercheck send -force` prints the link on the terminal instead. A receiver that sends no link changes nothing.
Anyone who has the link can see that machine's failing checks, so treat it like a password.

## Updates

**Policy.** With `update.policy_url`, every hourly run fetches the policy from that URL and keeps the last good
copy if the fetch fails or the new file is invalid. Change rules, the report endpoint or the update settings in
one place; no reinstall. An install from an invite link fetches from the policy URL it was enrolled with,
sending its token.

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

An install from an invite link goes further: the portal's policy never chooses the update source, not even at
install. Its `update.repo` and `update.public_key` are ignored; the install pins the built-in defaults (this repo
and the official release key) unless the person installing names another with
`bordercheck install <invite> -update-repo owner/name -update-key <base64>` (`--repo`/`--key` in `install.sh`,
`-Repo`/`-Key` in `install.ps1`). A compromised portal, or a role's policy edited carelessly, therefore cannot
point machines at another release. `update.binary` and `update.interval` still come from the policy.

A fork signs its own releases with its own key pair (see [CONTRIBUTING](../CONTRIBUTING.md#releasing)) and sets
`update.public_key` (or `--key`).

## What the install script proves

Before it runs anything it downloaded, the script checks that:

1. `SHA256SUMS.sig` is an ed25519 signature of `SHA256SUMS` by the release key written into the script (with
   OpenSSL 3, as on current Linux distributions), and
2. the binary matches its line in `SHA256SUMS`.

Both scripts use OpenSSL to verify the release signature when it supports Ed25519. Without a capable
OpenSSL (for example on stock macOS or Windows), an install has the downloaded binary
check the signature after the checksum matches. Dry runs never execute that binary. Without a
capable OpenSSL, a dry run checks only the checksum and says that the release signature was not verified.

What that does and does not prove:

- It catches a corrupted or truncated download, a binary swapped on the release without updating `SHA256SUMS`,
  and (with OpenSSL 3) a release whose `SHA256SUMS` was changed without the signing key.
- Without OpenSSL 3 the signature check runs inside the binary it is checking, so a binary planted by someone who
  can edit the release can simply say yes. The checksum still ties it to `SHA256SUMS`, but not `SHA256SUMS` to
  the key.
- `curl | sh` trusts whoever controls the script's URL. The script and the release both live on GitHub, so
  someone who takes over the GitHub account can change both. The signing key protects **updates** of installed
  copies (which trust only their built-in key) far better than it protects the first install. To close the gap,
  host `install.sh` yourself (next to `policies.json`) or pin it to a commit
  (`raw.githubusercontent.com/ptrinh/bordercheck/<commit>/install.sh`).

## Download by hand

Get `bordercheck-<version>-<os>-<arch>` from [Releases](https://github.com/ptrinh/bordercheck/releases/latest)
(macOS, Linux and Windows; arm64 and amd64) with `SHA256SUMS` and `SHA256SUMS.sig`. Compare
`shasum -a 256 <file>` with its line in `SHA256SUMS`; then `./<file> verify SHA256SUMS SHA256SUMS.sig <file>`
checks the signature (with the caveat above: a binary checking itself).

macOS binaries are signed with a Developer ID and notarized (since v0.2.0), so a browser download opens without a
Gatekeeper block; a bare binary cannot be stapled, so Gatekeeper looks the notarization up online. Windows
binaries are not Authenticode-signed yet.

**Homebrew** is not published yet. Each release carries a formula; once it is in the tap,
`brew install ptrinh/tap/bordercheck`, then `bordercheck install <url>`. The service runs its own copy, which
updates itself; `brew upgrade` updates the one on your PATH.

## What is sent

The report is the same JSON as `bordercheck -json`, plus `email` and `install_id`, plus `host.ips` and
`location` only when the policy asks for them:

```json
{
  "tool": "bordercheck", "version": "v0.2.0", "policy": "Acme", "time": "2026-10-30T14:46:07Z",
  "host": { "os": "darwin", "arch": "arm64", "hostname": "an-mbp", "ips": ["192.168.1.23", "2001:db8::23"] },
  "email": "an@acme.com", "install_id": "4f1c…",
  "counts": { "fail": 1, "error": 0, "warn": 1, "pass": 3, "skip": 1, "waived": 0 },
  "results": [ { "id": "firewall", "title": "Firewall is on", "status": "fail", "severity": "high",
                 "summary": "The macOS firewall is off.", "fix": "…",
                 "summary_parts": [ { "key": "firewall.mac.off" } ],
                 "fix_parts": [ { "key": "firewall.mac.off.fix" } ] } ]
}
```

- `summary_parts` and `fix_parts` (since 0.4, optional) are the same summary and fix as message keys with
  named parameters (strings and integers), in the order the English joins them, for example
  `[{"key": "listeners.exposed", "params": {"n": 3}}, {"key": "check.moreAllowed", "params": {"n": 2}}]`.
  The English text is rendered from exactly these parts (`internal/msg/catalog.go`), so the two always agree;
  the portal uses the parts to show the text in the reader's language and falls back to `summary`/`fix` for a
  key it does not know. A result whose text has no message (an error from the OS) has no parts. Keys never
  change meaning: a message with other parameters gets a new key. Receivers that do not know these fields
  ignore them.

- Secret values are never printed or sent. For long provider tokens (OpenAI, GitHub, AWS…) the report shows the
  last 4 characters, as the providers' own dashboards do, so people can tell which key it is (policy
  `secrets.show_tail`). Passwords show nothing.
- Evidence (file paths, variable names, ports) leaves the machine only when the policy sets
  `report.include_evidence`.
- What the person marked as not sensitive with `bordercheck ignore` is always sent, in the `user_ignored` of
  the `secrets`, `ai-agents` or `ssh-keys` result: `[{"path": "~/proj/.env", "name": "POSTGRES_PASSWORD", "kind": "Secret-looking
  variable", "reason": "local Docker database", "since": "2026-11-11"}]`, at most 200, never a value or its last
  characters. It is the record of what was set aside, so it does not depend on `report.include_evidence`.
  `bordercheck status` says so. Receivers that do not know the field ignore it.
- When a failing result shows [signs of compromise](policies.md#signs-of-compromise), the report has
  `"compromised": true` and `"compromise_checks": ["startup-items"]`, and that result lists its signs:
  `"compromise": [{"what": {"key": "compromise.startupDownloadRun"}, "detail": "LaunchAgent ~/Library/LaunchAgents/com.x.plist (com.x)"}]`.
  `what` is a message key like `summary_parts`; `detail` names the item (a name or path, never a command line or
  a value) and is sent only with `report.include_evidence`. The flag and the check IDs are always sent; none of
  it is when the policy sets `report.compromise_alert` to `false`. Receivers that do not know the fields ignore
  them.
- Secrets set aside as likely sample keys are always sent too, in the `secrets` result's `likely_samples`:
  `[{"path": "~/forks/app/config/default.pem", "kind": "Private key", "rule": "git-tracked"}]`, at most 200, never a
  value or its last characters, whatever `report.include_evidence` says ([Sample keys](#sample-keys)).
- The machine's IP addresses leave it only when the policy sets `report.include_ips`. Whatever the policy says,
  the receiver sees the public IP address the report arrives from, as every web server does, and may store it or
  look up a rough location from it.
- No device location is sent today, whatever the policy says ([why](policies.md#location)). The field would be
  `{"lat", "lon", "accuracy_m", "source", "time"}`.
- `bordercheck status` shows what this install sends (evidence, IP addresses, location), and install says so once
  when IP addresses or location are on. A plain `bordercheck` or `bordercheck -json` never includes them.
- An enrolled install's token travels in the `Authorization` header, never in the body, and only to the portal
  that issued it. The report page link a receiver may return is kept out of the log.
- SSH keys: key material is never shown, only type, fingerprint and comment. Tunnels: only the tool name and
  local port, since command lines can hold auth tokens.

Reports are self-reported by the machine: they tell you who needs help, not proof of compliance. A token proves
which install sent a report, not that the machine told the truth.

## Fixing secrets

On a Mac, move keys into the Keychain behind Touch ID with [touchenv](https://github.com/ptrinh/touch-env):

```sh
touchenv set OPENAI_API_KEY        # paste it, then delete the line from .zshrc / .env
touchenv run OPENAI_API_KEY -- python report.py
```

On Windows, use Credential Manager or a password manager CLI such as 1Password's `op run`. A key that sat in shell
history needs only those lines deleted; rotate keys only when there is evidence the machine was compromised.

### Secrets that are not sensitive

A value that only looks like a secret (a password for a database in a local container, a test key, a token for a
local MCP server, an SSH key used for one harmless thing) can be set aside by the person at the machine, with a
reason. Three checks take it:

| Check | What can be ignored | What cannot |
|---|---|---|
| `secrets` | any finding, by file, or by variable name or kind; one marked `[production]` is listed for IT as production | nothing |
| `ai-agents` | plain-text tokens, by config file, or by the setting the evidence shows (`mcpServers.x.headers.Authorization`) or the header / variable name | guardrails (approvals skipped, sandbox off) |
| `ssh-keys` | a key without a passphrase (`~/.ssh/aur`) | a key other users can read (`chmod 600` fixes it), `authorized_keys` (who can log in is IT's business), client settings such as `ForwardAgent` |

```sh
bordercheck ignore ~/proj/.env -reason "local Docker database, not reachable from outside"   # every finding in that file
bordercheck ignore ~/proj/.env -name POSTGRES_PASSWORD -reason "local Docker database"        # only that variable (or kind)
bordercheck ignore ~/.claude.json -name Authorization -reason "local MCP server, no secret behind it"
bordercheck ignore ~/.ssh/aur -reason "AUR upload key, used for nothing else"
bordercheck ignore -list                       # what is ignored, per check; entries that match nothing any more are marked stale
bordercheck unignore ~/proj/.env [-name POSTGRES_PASSWORD] [-check secrets]
```

The path is the one the report shows (`~/…` or absolute); `-name` is the name or the kind shown in the evidence.
Lines are never part of an entry, since they move when the file is edited. `-check secrets|ai-agents|ssh-keys`
says which check; without it bordercheck finds the one with a finding in that file, and asks for `-check` when
two do (an AI config with a token can be found by both `secrets` and `ai-agents`). bordercheck runs those checks
first and refuses a path or name that matches nothing (it lists what it finds in that file, by name), what cannot
be ignored (and says what to do instead), an empty reason, and a check whose policy sets `user_ignore` to `false`.

Ignored findings no longer count toward their check's status, severity or counts (the summary says how many were
ignored; if nothing else is left, the check passes). They are not hidden from IT: every report lists each one
under its check with its path, name, kind, reason and date, also when `report.include_evidence` is off (see
[What is sent](#what-is-sent)). The list is `ignored.json` in the install folder (one file for the three checks,
each entry naming its check), readable by this user only; a plain `bordercheck` run reads it too, installed or
not, and `bordercheck uninstall` removes it. An entry that no longer matches anything is kept (the finding may
come back) until `unignore` removes it. A list that cannot be read counts as empty, and the checks say so.

### Sample keys

Many keys on a developer's laptop are not real: a project's default key in a fork, a dummy `.env` for CI, the
certificates an SDK ships to everyone, a demo app's signing key. The `secrets` check sets those aside on its own,
so nobody has to ignore them one by one. A finding is a likely sample when one of these rules matches (the
policy's `checks.secrets.sample_rules` picks which; [policies](policies.md#secrets)):

| Rule | When |
|---|---|
| `git-tracked` | The file is tracked by a git repository below your home folder and is exactly what the repository's index records (unchanged since it was checked out or added). A file git ignores, an untracked file, or a changed one does not match. |
| `sdk` | A file an SDK ships identically to every user: Tizen Studio's (or the older Tizen SDK's) `…/certificates/…` folders, which hold the public developer CA and the default distributor signer. Keys an SDK generates for you, such as Android's `debug.keystore` or your Tizen author certificate, do not count. |
| `sample-dir` | A folder between your home folder and the file is named with one of the words `demo(s)`, `sample(s)`, `example(s)`, `fixture(s)`, `testdata`, `mock(s)` (split on `-`, `_` and `.`, any case), such as `demo-apps/` or `test_fixtures/`. `test` and `tests` do not count: real projects keep real keys for test servers there. The file's own name does not count. |

Never set aside: a finding marked `[production]`, anything inside a `.git` folder, and, by `sample-dir` alone,
a provider token that looks live (the kinds whose last 4 characters are shown: GitHub, OpenAI, AWS…). Something
you ignored with `bordercheck ignore` stays in your list, with your reason.

To read git's records bordercheck does not run git (a repository's own settings can make git run programs): it
reads the index file itself. When it cannot be sure, the rule does not match and the finding counts as usual: a
split or sparse index, an index format it does not know, a damaged index, a file over 10 MB, a repository whose
top is your home folder itself (a dotfiles repository), a symlinked file or folder, or a file whose line endings
or other git filters make it differ from what git stores.

Likely samples do not count toward the check's status or counts; the summary says how many there are ("3 more
look like sample keys."), and if nothing else is left the check passes. The terminal report shows one line with
the count per rule; `bordercheck -json` lists each one (path, name or kind, rule). Every report sends that list
to IT, who see it on the machine's page. A real key committed to a repository matches `git-tracked` too, which is
why the list is not hidden.
