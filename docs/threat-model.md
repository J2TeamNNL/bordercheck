# BorderCheck threat model

Status: written 2026-11-15 against branch `feature/next` (commit `d1a7ede`). Every claim below points at the
code it was checked against. Where the code does not implement a protection, this document says so.

BorderCheck is a configuration checker. An agent on each laptop (macOS, Windows, Linux) runs checks every hour
and reports to a portal the organisation runs itself on Cloudflare Workers + D1 (`receiver/`). It detects; it
does not prevent, contain or remediate.

## 1. Assets and data flow

### 1.1 What the agent reads

Running as the logged-in user, the agent reads whatever that user can read, within what the policy enables
(`internal/policy/policy.go`, `Checks`):

- OS state: firewall, disk encryption, listening ports, screen lock, OS/browser versions, sharing, startup items,
  trust store, admin rights, remote-access tools, tunnels, mesh VPNs, Docker (`internal/checks/*`).
- Files under the home folder, to a policy-set depth (`checks.secrets.walk_depth`, 0–20): `.env` files, key
  files, well-known credential stores (`secrets_locations.go`), git remotes, the Trash, `~/.ssh`, MCP/agent
  configs, browser profiles and extensions.
- AI assistant conversation history (Claude Code, Codex CLI, Aider) changed in the last `ai_chat_hours`, up to
  `ai_chat_max_mb` (`secrets_aichats.go`, `scanChats`).
- Any extra file the policy names (`checks.secrets.extra_files`, `checks.ai-agents.extra_paths`): any path, not
  limited to the home folder (`secrets.go`, `newSecretScanner`, lines 163–165).

### 1.2 What the agent sends

`agent.sendReport` (`internal/agent/agent.go:538`) posts a `report.Report` (`internal/report/report.go`):
tool version, policy name, host OS/arch/hostname, email, install ID, counts, and per check: id, title, status,
severity, summary, fix, and optionally evidence. Additionally, regardless of `include_evidence`:
`user_ignored` (path, variable name, kind, the person's reason) and `likely_samples` (`internal/check/check.go`).

Controlled by policy (`policy.Report`):

| Field | Default (`policies.example.json`, `receiver/src/sample-policy.json`) | Effect |
|---|---|---|
| `include_evidence` | false | per-finding lines: paths, line numbers, ports, process/container names; compromise item names |
| `include_ips` | false | the machine's interface addresses (`hostinfo.IPs`) |
| `include_location` | false | a device position where the OS gives one without a prompt (`hostinfo.Location`) |

With `include_evidence` off, `sendReport` (agent.go:563–576) clears `Evidence` and strips compromise details.

**The "never secret values" claim.** A secret finding (`secretFinding`, `internal/checks/secrets.go:85`) holds
path, line, kind, variable name, and for rules marked `showTail` the last 4 characters of a match of at least 20
characters (`scan`, secrets.go:395–397). The value itself is never stored in the finding. Two paths can still
put more than that into a report:

1. **Variable name taken from the line.** When a rule has no name group, the name is the first identifier
   before `:` or `=` on the line (`assignNameRe`, secrets.go:81, used at 392–394). If the secret is itself the
   key, as in a JSON/YAML map keyed by token (`"ghp_…": {…}`) or a line `ghp_…:x-oauth-basic`, the "name" is the
   whole token. Verified with the regex in isolation: both inputs return the full `ghp_…` string. It is sent as
   evidence (`f.String()`, secrets.go:107–108) and, if the person ignores the finding, in `user_ignored` even
   with evidence off.
2. **Policy-defined patterns.** `checks.secrets.extra_patterns` accepts any regex, a free-text `kind`, and its
   own `show_tail` (policy.go `SecretPattern`; only compile-checked at policy.go:627–634). Combined with
   `extra_files` (any path) and `include_evidence`, whoever writes the policy chooses which 4 characters are
   "the tail" (e.g. `^.{20}`, `^.{24}` …) and which files are read. See §3(f).

Secrets found in AI chat history are reported as `path:line kind` only; the surrounding context
(`chatContext`) is used by the local `bordercheck full-scan` and not put in the report (secrets.go:97,
`String()` does not use it).

### 1.3 What the portal stores and who sees it

D1 (`receiver/migrations/`): machines (email, hostname, OS, last seen, public IP and Cloudflare geolocation
unless `STORE_PUBLIC_IP`/`STORE_GEO` are `off`, both default on: `receiver/src/env.ts`), per-check state, report
history (`HISTORY_DAYS` default 180, `HISTORY_PER_MACHINE` default 500), enrollments with SHA-256 of machine
tokens (`tokens.ts`), invites (hashed), roles and policies, admins (token hashes), passkeys, audit rows.

Who sees it:

- The owner (ADMIN_TOKEN or the owner's passkeys) and Cloudflare Access users: everything (`auth.ts`, `viewer`).
- Named admins: machines in the roles they are scoped to (`scope.ts`).
- API (`API_TOKEN` / `API_READ_TOKEN`) and MCP (`MCP_TOKEN` / `MCP_READ_TOKEN`) callers: everything their
  surface exposes; MCP returns evidence only on request (`mcp-tools.ts`).
- Anyone holding a report link `/r/<id>`: that machine's results, for `REPORT_LINK_DAYS` (default 30), no login
  (`REPORT_LINKS` default on). The link is stored in the agent's `state.json`.
- The alert webhook (`ALERT_WEBHOOK_URL`, e.g. Slack/Discord): alert lines with email/hostname.

## 2. Components and trust boundaries

**Agent process.** A per-user service, never root: a LaunchAgent in `~/Library/LaunchAgents`
(`service_darwin.go`), a systemd user timer or the user's crontab (`service_linux.go`), a per-user scheduled
task on Windows. It wakes hourly; checks and reports run on `check_interval`/`interval` (min 15 min,
`policy.validate`); a small set of compromise checks run on every wake (`compromiseWatch`, agent.go:173).

**Install folder** (`agent.Dir`): `~/Library/Application Support/bordercheck`, `%LOCALAPPDATA%\bordercheck`,
`~/.local/share/bordercheck`. Created 0700 for enrolled installs (`prepareDir`, enroll.go:307), files written
0600 (`writeJSON`), binary 0755. Holds the binary, `policies.json`, `config.json` (email, install ID, pinned
update source), `token` (enrolled installs only; enroll.go:150–163; on Windows it inherits the folder ACL:
user, SYSTEM, Administrators), `state.json`, `ignored.json`, `bordercheck.log`. Everything here is writable by
the user, and so by anything running as the user.

**Enrollment and machine auth.** `bordercheck install https://<portal>/i/<code>` spends a one-time invite
(43-char random code, stored hashed) at `POST /enroll` with redirects refused (`enroll`, enroll.go:213). The
response gives a `bcm_` token (32 random bytes, stored as SHA-256 on the portal). The token is sent only to the
issuing origin over https (`bearer.allows`, enroll.go:109) with redirects refused (`noRedirects`). The portal
accepts reports only with an enrolled, non-revoked token and overwrites `install_id`/`email` from the
enrollment (`handleReport`, `receiver/src/ingest.ts`). Tokens do not expire; revocation is per machine.

**Policy delivery.** Each run refreshes the policy (`currentPolicy`, agent.go:793). For an enrolled install it
fetches `cfg.Enrollment.PolicyURL` with the token and refuses a policy whose `report.url` or
`update.policy_url` is on another origin (`checkEnrolledPolicy`, enroll.go:186). For a `policies.json` install
it fetches `update.policy_url` (https only) with no origin restriction: the fetched policy can point
`report.url` and `report.headers` anywhere. On fetch or validation failure the last good copy is kept. In both
cases `update.repo` and `update.public_key` from the refreshed policy are ignored in favour of the values pinned
in `config.json` (agent.go:820–824).

**What a policy can change** (no field is executed as a command; it can only select, tune and widen what is
read and sent): which checks run and their thresholds; waivers (exempt a check for a machine or role until a
date); `include_evidence` / `include_ips` / `include_location`; `extra_files`, `extra_paths`,
`extra_patterns`, `show_tail`, `walk_depth`, `ai_chat_hours`; `user_ignore` per check; notifications; for
`policies.json` installs, the report destination and headers. It cannot change the update source.

**Self-update chain** (`updateBinary`, agent.go:626 → `update.Run`, `internal/update/update.go:47`):

1. Only when the policy has `update.binary` and `update.interval` (≥1h) has passed.
2. GET `https://github.com/<repo>/releases/latest/download/SHA256SUMS` (≤64 KiB) and `SHA256SUMS.sig` (≤1 KiB).
   `repo` is the pinned value: for enrolled installs `policy.Default().Update.Repo` unless `-update-repo` was
   passed at install (`updatePins`, enroll.go:334); for `policies.json` installs whatever the policy said at
   install time (agent.go:317).
3. `VerifySums` (update.go:127): ed25519 over the exact bytes of SHA256SUMS with the pinned key, or
   `OfficialKey` (update.go:32) when none was pinned.
4. `findAsset` takes the first line for this OS/arch and reads the version from the file name; `newer` refuses
   equal or older versions (no downgrade).
5. Download `releases/download/<version>/<name>` (≤200 MiB), compare SHA-256 with the signed line.
6. `replace` (update.go:223): write `bin.new`, run it with `-version` and require the version string, rename over
   the binary. The old version then runs the new one's `setup` (`runNewVersion`, agent.go:434).

Not verified by the updater: Apple code signature or notarization, Authenticode, the git tag or commit, any
expiry or freshness of the signature. The ed25519 signature is the only gate.

The macOS notification app (Bordercheck.app) is fetched with the same signed-SUMS rule (`update.FetchAsset`)
and, in addition, checked with `codesign --verify --strict --deep` and its Team ID pinned on first install
(`internal/notifier/notifier.go:301–330`, `agent/notifier.go:157–161`).

**Release pipeline** (`.github/workflows/release.yml`), on any pushed tag `v*`:
build + test on Ubuntu → codesign/notarize macOS binaries on a macOS runner if the `MACOS_*` secrets exist,
otherwise use binaries a maintainer signed locally with `scripts/sign-macos-release.sh` and uploaded to a draft
release (accepted if `go version -m` says `vcs.revision=$GITHUB_SHA` and `vcs.modified=false`, lines 257–266) →
`scripts/sums.sh` signs SHA256SUMS with the repo secret `BORDERCHECK_SIGNING_KEY` (line 270–273) via
`scripts/sign/main.go` → `go run . verify` checks the result against `OfficialKey` → publish as latest.
The private key exists in the GitHub Actions secret store and in whatever offline copy the maintainer keeps.
As checked on 2026-11-15 with `gh api`: the repo has no rulesets, no deployment environments, and `main` has
no branch protection.

**Install scripts.** The invite page shows `curl -fsSL <INSTALL_SH_URL> | sh -s -- <link>` (`enroll.ts:177`),
default `https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh` (`env.ts:48`). `install.sh`
pins `OFFICIAL_KEY` and verifies with OpenSSL 3 when it can (lines 184–195). Without OpenSSL 3 (stock macOS
ships LibreSSL) it checks the binary against the *unverified* SHA256SUMS and then asks the downloaded binary
to verify its own signature (`install.sh:234–238`; `install.ps1:146–151` the same on Windows without an
Ed25519-capable OpenSSL).

**Portal admin auth** (`receiver/src/auth.ts`, `viewer`): Cloudflare Access JWT (RS256, `aud`, `iss`, `exp`
checked), or `ADMIN_TOKEN` as bearer or via a 12-hour HMAC session cookie keyed by `ADMIN_TOKEN`
(`HttpOnly; Secure; SameSite=Strict`, path `/admin`), passkeys, named admins (`bca_` tokens stored hashed,
sessions invalidated by a `gen` counter). Token sign-in can be switched off once a passkey works. State-changing
cookie requests require same-origin (`sameOrigin`). Login, enroll, page, API and MCP are rate-limited per IP.

**MCP and REST API** (`mcp.ts`, `api.ts`): separate static bearer tokens (≥16 chars) compared in constant
time. Neither surface may change `report.url`, `report.headers`, `update.policy_url`, `update.repo`,
`update.public_key`; MCP also may not set waivers or turn on evidence/IPs/location (`fleet.ts:554–571`). MCP
can still disable checks and add `extra_patterns`/`extra_files`. Machine-supplied text is returned inside an
`untrusted` object (fleet.ts header).

**Guard hooks** (`internal/guard`, `main.go:522–604`): `bordercheck guard install` adds three Claude Code hooks to
`~/.claude/settings.json`: block a prompt with a secret, refuse a Bash command that prints secrets wholesale,
redact secrets in Bash output. Every hook fails open: unreadable input, a policy that fails to load (falls back
to the default policy) or a scan error lets the content through (exit 0). A prompt containing `#allow-secret`
(`guard.Allow`) is let through on purpose. Only Bash is covered; the Read/Edit/Write tools and other hook-less
paths are not. Anything running as the user can remove the hooks; the secrets check only notes their absence.

## 3. Attackers

### (a) Network attacker (on-path, no CA compromise)

- CAN: see that a laptop talks to the portal and to github.com; block reports (the portal raises a "silent"
  alert after `SILENT_DAYS`, default 7, `alerts.ts`); block updates (freeze at the current version); block policy
  refresh (the last good policy is kept).
- CANNOT: read or alter reports, tokens or policies (all https; report and policy URLs must be https,
  `policy.validate`; `http://localhost` is allowed for testing only); redirect the token (redirects refused);
  serve a binary (ed25519 + SHA-256).
- With a trusted rogue CA (corporate MITM proxy, compromised CA): everything https protects, except the
  binary signature. Then also: forge policies to `policies.json` installs and the stock-macOS install path
  (see b).

### (b) Control of the GitHub account, repo or CI

The code comment at `update.go:3–4` says taking over the GitHub account "is not enough to push code to
installed machines; the signing key is also needed". That holds only if the attacker cannot run the release
workflow. Today:

- **Push access alone is enough to ship a signed release to every agent with `update.binary` on.** Push a
  commit with malicious code and a tag `v<higher>` on it. The workflow at that commit runs, signs SHA256SUMS
  with `BORDERCHECK_SIGNING_KEY` and publishes it as latest. Agents install it within `update.interval`.
  No Apple identity is needed: the updater does not check code signatures, and the workflow publishes unsigned
  macOS binaries with only a warning when `MACOS_*` secrets are absent (release.yml:72–75).
- **Push access is enough to steal the key.** Any workflow on any branch of the repo can read repo secrets on
  `push` events; no environment with required reviewers guards it. A stolen key keeps working after the account
  is recovered, until `OfficialKey` is changed in a release that agents accept, which itself needs the key.
- **New installs need even less.** `install.sh`/`install.ps1` are fetched from `main` on
  raw.githubusercontent.com. A commit to `main` changes the script that every new `curl | sh` runs; the
  pinned key inside it is whatever the attacker writes. On stock macOS, even an unmodified script trusts the
  downloaded binary to check its own signature (§2), so whoever controls the release assets controls the
  binary: a malicious binary's `verify` simply exits 0.
- The Homebrew formula is rendered from the same signed SHA256SUMS (`scripts/homebrew-formula.sh`).
- CANNOT (without push or Actions access): edit a release's assets without the signature failing on
  installed agents; downgrade agents (`newer`).
- Third-party actions are pinned by tag (`actions/checkout@v4` etc.), not by commit SHA.

What an attacker needs, end to end: **write access to the repo (a maintainer's GitHub session, PAT, or a
compromised Action) — nothing else.** The ed25519 key raises the bar only for someone who can modify release
assets but cannot run workflows.

### (c) Compromise of the Cloudflare account, the portal, or an admin/API/MCP token

- CAN: read every stored report, email, hostname, IP and geolocation, and history; edit roles and so the policy
  every enrolled machine fetches: disable checks, add waivers, turn on evidence/IPs/location (dashboard and API;
  not MCP), add `extra_files`/`extra_patterns` (all surfaces including MCP) and use them as in (f); revoke
  machines; mint invites and named admins (owner only).
- With the Cloudflare account (deploy rights): replace the Worker, which bypasses every check in `receiver/`;
  set `INSTALL_SH_URL`/`INSTALL_PS1_URL` to an attacker's https script, which the invite page then tells new
  enrollees to pipe into a shell (`env.ts`, `scriptURL` accepts any https URL). That is code execution on newly
  enrolling machines, not on existing ones.
- CANNOT: change where enrolled agents send reports or fetch policy (`checkEnrolledPolicy`), or their update
  source (`updatePins`; the portal's policy is never consulted for it). Cannot run commands on existing agents:
  no policy field is executed.
- Static secrets (`ADMIN_TOKEN`, `API_TOKEN`, `MCP_TOKEN`, read variants) never expire and are rotated only by
  `wrangler secret put`. Rotating `ADMIN_TOKEN` also signs out every session, passkey ones included (the session
  HMAC key is derived from it, `auth.ts`, `sessionKey`).
- An MCP client is a model that reads machine-supplied text. A prompt injection in a hostname or evidence line
  could get a write-token MCP client to disable checks or add patterns; the guard rails stop only the fields
  listed in §2. Writes are audited (`audit.ts`).

### (d) Malware running as the employee

- CAN: read the `token` file (0600 protects only from other users) and post forged reports with any results
  (the portal cannot tell a forged report from a real one; `README.md`: "Reports are self-reported"); edit
  `policies.json`, `ignored.json`, `state.json`; stop the service (`launchctl bootout`, `systemctl --user stop`)
  — noticed only as a silent machine after `SILENT_DAYS`; replace the binary in the install folder, which the
  LaunchAgent/timer then runs hourly (a persistence spot, though one of many the user can already write);
  remove the guard hooks; read the report link in `state.json`.
- CANNOT: obtain more than the user already has from BorderCheck (no privileged component); use the token
  against another portal origin.
- Detection value against such malware is limited to the window before it tampers with the agent. The
  compromise checks (`checks.CompromiseCheckIDs`) report at the next hourly wake if the agent is still intact.

### (e) A careless or uncooperative employee

- CAN: mark secrets, AI-agent tokens and passphrase-less SSH keys as "not sensitive" (`bordercheck ignore`), only
  for checks where the policy sets `user_ignore`. Guardrail findings cannot be ignored (`policy.AIAgents`).
- What the admin sees: every ignored entry stays in every report under `user_ignored` with path, name, kind,
  reason and since, even with `include_evidence` off (`userIgnore.finish`, `internal/checks/userignore.go:103`).
  The check's summary says how many were ignored.
- CAN also: edit `ignored.json` by hand, block the portal, uninstall (the portal is not told, `agent.Uninstall`),
  or forge reports as in (d). Uninstall and blocking surface as silence.
- Note the variable-name leak (§1.2): an ignored finding whose "name" is a token sends that token to IT.

### (f) A malicious policy author or admin

With the dashboard or API (or MCP, minus the evidence switch), an admin can make agents read and send more than
the documented "path, kind, last 4":

- `extra_files` can name any file the user can read (e.g. `~/.ssh/id_ed25519`, browser or app files). Its
  extension decides the rules: `.pem`/`.key`/`.p8` get only the private-key rule (`scanFile`, secrets.go:364–368);
  any other file gets all rules, including `extra_patterns`.
- `extra_patterns` with `show_tail: true` reveals the last 4 characters of any match of ≥20 characters. A regex
  such as `^.{20}` reveals characters 17–20 of the first matching line … and the policy can be changed every
  hour. Only one rule matches per line, but different patterns per refresh walk through a file. A pattern's
  match/no-match is itself a 1-bit oracle via the check's status, even with evidence off.
- Turn on `include_location`/`include_ips`; set long `ai_chat_hours`.
- The person at the machine is told what the policy sends at install (`printSends`) and in `bordercheck status`
  ("Sends: …"), but not when a refreshed policy changes it, and `status` does not list `extra_files` or
  `extra_patterns`.
- Every role change is in the portal's audit trail (`audit.ts`); an admin with the Cloudflare account can delete
  it.

### (g) Privacy risk to employees

- Collected by default: email, hostname, OS, public IP and Cloudflare city-level geolocation on every report
  (portal side, `STORE_PUBLIC_IP`/`STORE_GEO` default on), check results, and the names/kinds of what they
  ignored with their reasons. History for 180 days.
- Optional, by policy: file paths (can reveal project and client names), interface IPs, device location,
  findings in AI chat history (path and line of a conversation file; not its text).
- `README.md` "Privacy and security" says "No location is sent". That is the default only; `include_location`
  sends a device position (`agent.go:555–559`). The README should say so.
- Report links (`/r/<id>`) work without login for 30 days for anyone who has them.
- The webhook sends alert text (with email/hostname) to a third-party chat service.

## 4. Out of scope and non-goals

- Prevention, blocking, quarantine or remediation. BorderCheck reports; the person or IT fixes. The guard hooks
  are a best-effort filter that fails open, not a DLP control.
- EDR or anti-malware. The compromise checks look for a few indicators; they do not detect, or survive,
  malware that targets BorderCheck (see 3d).
- Tamper-proof attestation. Reports are self-reported by a process the user controls.
- Complete secret detection. Detection is regex and format-based (`secretRules`, `secrets_locations.go`),
  bounded by walk depth, file size, time limits (`secretScanTimeout`) and cloud-placeholder skipping. Unknown
  token formats, secrets in binary files, encrypted/compressed files, deeper folders, or other users' files are
  missed. False negatives are expected.
- Protecting against root/Administrator on the laptop, or against Cloudflare/GitHub themselves.

## 5. Residual risks, ranked

1. **CI can sign anything; push = fleet-wide code execution.** `BORDERCHECK_SIGNING_KEY` is a repo secret usable
   by any tag or branch workflow; no branch, tag or environment protection is configured.
   *Being fixed (v0.5.17–v0.5.18):* a new key, kept in touchenv on the maintainer's Mac, signs SHA256SUMS there
   (`sign-macos-release.sh`); v0.5.17 trusts it and the previous key, v0.5.18 is the first release signed with it
   and trusts it alone, after which the repo secret is deleted. Rulesets now forbid deleting or moving `v*` tags
   and force-pushing or deleting `main` (the repository admin can bypass).
   *Recommend:* move signing off CI: sign SHA256SUMS on the maintainer's machine (the macOS signing already
   runs there, `sign-macos-release.sh`) with the key behind a hardware key or Touch ID (touchenv), and have CI
   only verify. If it must stay in CI: put it in a deployment environment with required reviewers and a tag
   pattern, add a ruleset restricting who may create `v*` tags, protect `main` (reviews, no force-push), require
   signed commits/tags. Consider a second key (2-of-2) or a release delay agents honour (e.g. install only
   releases older than N hours) so a bad release can be pulled.
2. **Install path trusts GitHub, not the key, on stock macOS/Windows.** *Partly fixed in v0.5.17:* on macOS,
   `install.sh` checks the binary's Developer ID (Team ID) with `codesign` before running it. Self-verification
   (`install.sh:234–238`, `install.ps1:146–151`) proves nothing against a malicious binary, and the script
   itself comes from `main`. *Recommend:* verify ed25519 without the downloaded binary (macOS: a small
   verifier in Swift/`CryptoKit` via `swift -e`, or check the Developer ID signature with `codesign -v -R
   '=anchor apple generic and certificate leaf[subject.OU] = "<TEAM>"'` before running it); serve the install
   scripts from the portal or a tagged release instead of `main`; say plainly in `docs/install.md` that without
   OpenSSL 3 the signature step is not independent.
3. **Policy author can exfiltrate file contents** via `extra_files` + `extra_patterns` + `show_tail` (§3f).
   *Recommend:* refuse `show_tail` on `extra_patterns` unless the regex has a fixed token prefix and ≥20
   characters of random body; cap the number of patterns; restrict `extra_files` to the home folder and refuse
   known key/credential paths for pattern rules; show `extra_files`/`extra_patterns` in `bordercheck status`
   and notify the person when a refreshed policy widens collection.
4. **Variable name can be the secret** (`secrets.go:81`, `392–394`). *Fixed:* `safeName` drops a captured name that
   matches a provider-token rule, is longer than 40 characters or looks random; `TestTokenIsNeverTheName` covers
   `"ghp_…": …` and `ghp_…:x-oauth-basic`.
5. **Updater gate is the ed25519 key only.** *Fixed in v0.5.17:* on macOS, when the running binary has a Developer ID
   signature, `update.sameSigner` requires the new one to be signed by the same team before it runs.
   *Recommend:* refuse unsigned macOS releases in CI instead of warning.
6. **Long-lived portal credentials.** Machine tokens, `ADMIN_TOKEN`, `API_TOKEN`, `MCP_TOKEN` never expire.
   *Recommend:* document a rotation procedure and cadence; prefer Access + passkeys and switch token sign-in off;
   give MCP the read token by default; add token rotation on the machine side (re-issue on each policy fetch,
   or periodic rotation).
7. **Cloudflare account = control of new installs** (`INSTALL_SH_URL`). *Recommend:* hardware security keys
   for the Cloudflare and GitHub accounts of everyone with deploy/push rights; restrict the invite page to the
   official script URLs, or show the script's expected SHA-256.
8. **Forged/silenced reports.** Inherent to a user-space agent. *Recommend:* lower `SILENT_DAYS` for sensitive
   roles; alert on a machine whose version stops advancing after a release; treat results as advisory.
9. **Freeze.** A blocked or held-back `latest` keeps agents on an old version indefinitely. *Recommend:* report
   the update error and version to the portal (it already gets the version) and alert on agents N releases
   behind.

## 6. Questions for an external reviewer

Update chain:

- `internal/update/update.go`: `Run` (47), `VerifySums` (127), `findAsset` (178), `newer` (264), `replace`
  (223). Is it sound that the version comes from the asset name inside the signed file, that the first matching
  line wins, and that `replace` executes the new binary before the swap?
- `internal/update/update.go:32` `OfficialKey`; `install.sh:36` `OFFICIAL_KEY` (a test keeps them equal).
- `internal/agent/agent.go`: `updateBinary` (626), `currentPolicy` (793, pinning at 820–824), `Install` (317).
- `internal/agent/enroll.go`: `updatePins` (334), `installEnrolled` (362).
- `internal/agent/notifier.go` / `internal/notifier/notifier.go`: `FetchAsset` + codesign + Team ID pinning.
- `.github/workflows/release.yml`: presigned-binary acceptance via `go version -m` (257–266) — buildinfo is
  self-declared; is that check meaningful against someone who can upload to a draft release?
- `scripts/sums.sh`, `scripts/sign/main.go`, `scripts/sign-macos-release.sh`.
- `install.sh` 180–240 and `install.ps1` 90–151: the fallback where the binary verifies itself.

Portal auth:

- `receiver/src/auth.ts`: `accessIdentity`, `viewer`, `newSession`/`validSession` (HMAC keyed by ADMIN_TOKEN),
  `sameOrigin`.
- `receiver/src/passkeys.ts`, `admins.ts`, `scope.ts`: owner vs named admin vs Access, role scoping.
- `receiver/src/mcp.ts` (token check ~80), `api.ts`, `fleet.ts` `policyGuard` / `MCP_ROLE_RULES` (554–571).
- `receiver/src/enroll.ts`: `handleEnroll`, `serveMachinePolicy` (127); `ingest.ts` `handleReport`.
- `receiver/src/roles.ts` `validateRolePolicy`: should it restrict `extra_files`, `extra_patterns`,
  `show_tail`?

Data minimisation:

- `internal/checks/secrets.go` `scan` (373) and `assignNameRe` (81): can any other field carry part of a value?
- `internal/agent/agent.go` `sendReport` (538): is everything that bypasses `include_evidence`
  (`user_ignored`, `likely_samples`, summaries) acceptable?
