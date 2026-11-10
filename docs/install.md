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
| `--dry-run` | `-DryRun` | Download and verify, then stop before installing |
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

```sh
bordercheck status               # email, enrollment, policy, what is sent, service, last report, report page, updates
bordercheck send -force          # send a report now
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

| OS | How | Needs |
|---|---|---|
| macOS | `osascript` `display notification` | nothing; listed as Script Editor in System Settings → Notifications |
| Windows | a toast through Windows PowerShell 5.1 | nothing; shown while the user is logged on |
| Linux | `notify-send`, else `gdbus` to the desktop's notification service | a desktop session |

A notification that cannot be shown is logged in `bordercheck.log` and tried at the next check; it never holds
up a report. `bordercheck send -force` (and the first report at install) is run by someone at a terminal, so it
prints the problems there instead and the next scheduled run does not repeat them. A plain `bordercheck` never
notifies.

**Report page.** A receiver may answer a report with `{"report_url": "https://<host>/r/<id>"}`, a link to that
machine's own report that needs no login. bordercheck keeps it (in `state.json`, never in the log) only if it is
https on exactly the host reports go to, and shows it in `bordercheck status`. When a notification announces a
**high-severity** problem for the first time, the page also opens in the default browser (a `remind_every`
reminder of the same problem only notifies; it does not open the page again): `open` on macOS, `rundll32 url.dll,FileProtocolHandler` on Windows, `xdg-open` on Linux, the
link passed as one argument, never through a shell. Linux skips it quietly without a graphical session (a
systemd user timer often has no `DISPLAY`). With `notify.open_report` off, or when the browser can't be opened,
or on a reminder, the notification adds "Run bordercheck status for the link to your report page." `bordercheck send -force`
prints the link on the terminal instead. A receiver that sends no link changes nothing. Anyone who has the link
can see that machine's failing checks, so treat it like a password.

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

Stock macOS (LibreSSL) and Windows PowerShell cannot check ed25519, so there the downloaded binary checks the
signature itself (`bordercheck verify`) with the key from the script, after step 2 passed. Any mismatch stops
the install with a message and nothing installed.

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
                 "summary": "The macOS firewall is off.", "fix": "…" } ]
}
```

- Secret values are never printed or sent. For long provider tokens (OpenAI, GitHub, AWS…) the report shows the
  last 4 characters, as the providers' own dashboards do, so people can tell which key to rotate (policy
  `secrets.show_tail`). Passwords show nothing.
- Evidence (file paths, variable names, ports) leaves the machine only when the policy sets
  `report.include_evidence`.
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

On Windows, use Credential Manager or a password manager CLI such as 1Password's `op run`. Rotate any key that
sat in shell history or a synced folder.
