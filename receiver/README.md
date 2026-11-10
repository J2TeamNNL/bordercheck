# bordercheck receiver

**The other end of `report.url`: a Cloudflare Worker that stores bordercheck reports, shows them to IT, and
alerts when something goes wrong.**

- `POST /report` takes the report each installed bordercheck sends.
- `/admin` is a dashboard: every machine with its email, hostname, OS, version, last report and fail/warn
  counts; a filter for non-compliant and silent machines; each machine's failing checks with summary, fix,
  evidence and since when; and which checks fail most across the organisation.
- An hourly cron posts alerts to Discord, Slack or any webhook: a machine **newly** fails a high-severity
  check, a machine has been **silent** for more than `SILENT_DAYS` (someone who uninstalls bordercheck
  otherwise just disappears), and optionally a digest.
- **Enrollment portal**: give each person an invite, each machine gets its own token and the policy of its
  role (Dev, Support, Sales…), with per-machine waivers. See [Enrollment](#enrollment).
- `GET /policies.json` serves one shared policy to machines installed without an invite ([legacy
  mode](#legacy-mode-the-shared-token)).
- Each report records the **public IP and Cloudflare's IP-based location**, and the machine's own local
  addresses and position if it sends them. This is personal data: read [What is stored](#what-is-stored).
- Each accepted report gets a **login-free link** to that machine's own results, which bordercheck can open for
  the person at the machine ([Report links](#report-links)).

Storage is one D1 database. No framework, no build step beyond what Wrangler does.

## Deploy

```sh
cd receiver
npm install
npx wrangler d1 create bordercheck            # put the printed database_id in wrangler.jsonc
npx wrangler d1 migrations apply bordercheck --remote

openssl rand -hex 32 | npx wrangler secret put REPORT_TOKEN   # what laptops send
openssl rand -hex 32 | npx wrangler secret put ADMIN_TOKEN    # dashboard sign-in (see Access below)
npx wrangler secret put ALERT_WEBHOOK_URL                     # paste the Discord or Slack webhook URL

npx wrangler deploy
```

Keep a copy of `ADMIN_TOKEN` in your password manager: it is the dashboard login. Tokens must be at least
16 characters; with no usable `REPORT_TOKEN` the receiver refuses every report not sent with an enrolled
machine's token, and with neither Access nor
`ADMIN_TOKEN` the dashboard is off.

Then add a custom domain (e.g. `bordercheck.acme.com`) in `routes`, set `DASHBOARD_URL` so alerts and invite
links use it, and deploy again. Upgrading an existing deployment: `npx wrangler d1 migrations apply bordercheck
--remote` adds the new tables and columns; existing machines keep reporting with the shared token and show as
**legacy**.

With enrollment only, `REPORT_TOKEN` is optional: set `LEGACY_MODE` to `"off"` and skip it.

## Enrollment

1. **Roles** (dashboard → Roles). A role is a name and a policy, the same JSON as `policies.json`. Leave out
   `report.url`, `report.headers` and `update.policy_url`: they are filled in per machine.
2. **Invites** (→ Invites). Paste one or many emails, pick a role, optionally an expiry (default `INVITE_DAYS`)
   and a note. The page then shows, **once**, each person's invite link and install commands:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.sh | sh -s -- https://bordercheck.acme.com/i/<code>
   ```
   ```powershell
   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ptrinh/bordercheck/main/install.ps1))) https://bordercheck.acme.com/i/<code>
   ```

   Send each person their own (this version sends no email). Only a hash of the code is stored, so a lost
   command can't be shown again: **Re-issue** the invite (the old code stops working). Invites are listed as
   pending, used, expired or revoked, so you can see who hasn't installed. `INSTALL_SH_URL` /
   `INSTALL_PS1_URL` point the commands at your own copy of the scripts.
3. The person runs the command. bordercheck exchanges the code for a token for **that machine**; the code then
   stops working. Opening the link in a browser shows the same instructions (and doesn't use it up).
4. **Machines** (→ a machine's page): role, the invite and email it came from, **Revoke** (its token stops
   working at once; history stays; **Restore** undoes it), **Change role**, and **Waivers**: pick a check, an end
   date (at most a year) and a reason; it reaches the machine through `/policy` at its next hourly refresh.
5. **Audit** lists every change made in the dashboard (who, when, what) and every enrollment.

What the role check catches and doesn't: it is a JSON object; top-level fields, and those in `report`, `update`,
`notify` and `waivers`, are ones bordercheck knows; check names exist; `enabled`/`on_problem` have the right
types; durations parse and meet bordercheck's minimums; role waivers have a check, email or install_id, a reason
and an end within a year; no report token in `report.headers`. It does not check the settings inside each check
(globs, regexes, versions, lists). bordercheck validates the whole file and keeps its last good policy if one is
invalid, so try a role locally first: `bordercheck -policy role.json -print-policy`.

Waivable checks are the ones bordercheck's policy knows (`firewall`, `disk-encryption`, `listeners`,
`tailscale`, `docker`, `secrets`, `ssh-keys`, `tunnels`, `ai-agents`, `os-updates`, `screen-lock`,
`remote-access`). An unknown check ID would make bordercheck reject the whole policy, so the portal offers only
these; a check added to bordercheck later needs this list updated (`POLICY_CHECKS` in `src/roles.ts`).

### Wire contract

What bordercheck and this receiver exchange. `<host>` is the deployment's origin.

**Invite link**: `https://<host>/i/<code>`, `<code>` = 32 random bytes, base64url without padding (43
characters). `GET` returns an HTML page with the install commands; it never consumes the code.

**`POST /enroll`**, no auth header, JSON body:

```json
{"code": "<code>", "host": {"os": "darwin", "arch": "arm64", "hostname": "an-mbp"}, "version": "v0.4.0"}
```

`200`:

```json
{"install_id": "<32 hex>", "email": "an@acme.com", "role": "Dev", "token": "bcm_<43 base64url>",
 "policy_url": "https://<host>/policy", "report_url": "https://<host>/report"}
```

The token is shown only here. Failures are `{"error": "<code>", "message": "<for a person>"}`:

| `error` | Status | |
|---|---|---|
| `invalid_code` | 404 | unknown or malformed code |
| `expired` | 410 | |
| `used` | 409 | already enrolled a machine; of two concurrent enrolls exactly one gets 200 |
| `revoked` | 410 | cancelled or re-issued by an admin |
| `bad_request` | 400 | body not a JSON object, no string `code`, `host` not an object, over 8 KB |
| `rate_limited` | 429 | with `Retry-After`; more than `ENROLL_RATE_LIMIT` attempts per IP per `RATE_WINDOW_SECONDS` |

**`GET /policy`** with `Authorization: Bearer <token>`: the machine's policy, composed from its role: `report.url`
= `https://<host>/report`, `report.headers` without any `Authorization` header or token, `update.policy_url` =
`https://<host>/policy`, `name` = the role's policy name or else the role name, and `waivers` = the role's
waivers that name this machine's email or install_id, plus this machine's waivers as
`{"check", "install_id", "until", "reason"}`. Waivers that ended more than 30 days ago are left out. `401
{"error": "unauthorized"}` for an unknown token, `401 {"error": "revoked"}` for a revoked one.

**`POST /report`** with `Authorization: Bearer <token>`: as before, except `install_id` and `email` come from
the token's enrollment and the body's are ignored (they may be absent). `401 {"error": "revoked"}` for a revoked
token. Every accepted report (machine token or shared token) answers `{"ok": true, "fail": n, "warn": n,
"report_url": "https://<host>/r/<id>"}` (`report_url` only while `REPORT_LINKS` is on).

Optional report fields, accepted from any bordercheck: `host.ips` (array of the machine's interface addresses;
invalid entries are dropped, at most 32 kept) and `location` (`{"lat", "lon", "accuracy_m", "source",
"time"}`; dropped whole if lat/lon are missing or out of range).

### Security notes

- Invite codes (256 bits), machine tokens (256 bits) and report-link ids (192 bits) come from the CSPRNG and
  are stored only as SHA-256. They are too long to guess, so a plain hash is enough, and lookups by hash leak
  nothing useful through timing. The shared tokens and admin token are compared in constant time.
- A code is consumed in one transaction that also creates the enrollment, so it works exactly once.
- `/enroll`, `/i/` and `/r/` are rate-limited per client IP (`CF-Connecting-IP`, stored hashed). For a
  public deployment also add a Cloudflare rate-limiting rule on `/enroll`.
- Codes, tokens and link ids are never logged, put in alerts or in the audit trail. The code is in the
  invite URL's path, so Cloudflare's request logs (if you enable Logpush) see it; it is single-use and
  short-lived.
- **A leaked install command** lets whoever runs it first enroll one machine as that person, in that role, until
  it is used or expires. The real person's attempt then fails with `used`, which shows up; revoke that machine
  and re-issue. It gives no access to the dashboard or other machines.
- **A leaked machine token** lets its holder send reports as that one machine and read its policy (which holds
  no secrets but shows that machine's waivers). Revoke the machine; reinstall with a new invite.
- **Read access to the database** shows reports, emails, IPs and locations, but no usable code, token or link.
- The shared `REPORT_TOKEN` can't write to an enrolled machine's install_id.

### Legacy mode: the shared token

With `LEGACY_MODE` `"on"` (the default) everything below keeps working unchanged next to enrollment. Set it to
`"off"` once every machine is enrolled: the shared `REPORT_TOKEN` is then refused on `/report` and
`/policies.json` answers `410 {"error": "legacy_disabled"}`, so a copy of the shared token or policy can no
longer be used to bypass enrollment. A legacy machine moves to enrollment by reinstalling with an invite; it
gets a new install ID (the old record goes silent; forget it when convenient).

## Report links

Each accepted report's response carries `report_url`, `https://<host>/r/<id>`: a page, with no login, showing
**that machine's latest results** for the person at it: what fails or warns, severity, summary and fix,
waived items and their end date, when it was checked, and its email and hostname. bordercheck can open it when
it announces a new high-severity problem.

It never shows evidence (file paths, port numbers, container names: a map of the machine for whoever holds the
link; the person at the machine sees them by running bordercheck), other machines, admin controls, the audit
trail, IPs or locations. Pages are script-free, `no-store`, `noindex`, `no-referrer`, and unknown, expired and
revoked links all get the same 404.

A new link is issued with every report, because only a hash is stored and so an old one can't be handed out
again. Links expire after `REPORT_LINK_DAYS` (30). An enrolled machine keeps its newest 3 links working; a
legacy machine only its newest, since anyone with the shared token can send a report as any legacy install_id
and would otherwise keep a link to the real machine's later results. Revoking, restoring, **Reset report
links** on the machine page, or forgetting it, end all its links.

**What a leaked link exposes**: until it expires or is replaced, that machine's latest pass/fail results with
summaries and fix text, its email and hostname, and when it last reported. Nothing else. Turn the feature off
with `REPORT_LINKS` `"off"`.

## Point bordercheck at it (legacy mode)

Upload your policy from the dashboard (**Policy**) or with the admin token:

```sh
curl -X PUT https://bordercheck.acme.com/admin/policies.json \
  -H "Authorization: Bearer $ADMIN_TOKEN" --data-binary @policies.json
```

Write the report token as a placeholder; the Worker fills it in from the `REPORT_TOKEN` secret when it serves
the file (a literal token in an upload is swapped for the placeholder before it is stored):

```jsonc
{
  "name": "Acme",
  "report": {
    "url": "https://bordercheck.acme.com/report",
    "headers": { "Authorization": "Bearer {{REPORT_TOKEN}}" },
    "interval": "24h",
    "email_domains": ["acme.com"]
  },
  "update": { "binary": true, "policy_url": "https://bordercheck.acme.com/policies.json" }
}
```

The receiver doesn't check the policy's rules; bordercheck does, and keeps its last good copy if the new one
is invalid. Check it locally first with `bordercheck -policy policies.json -print-policy`.

People then install with:

```sh
./bordercheck install https://bordercheck.acme.com/policies.json
```

You can also host `policies.json` elsewhere and only use `POST /report`.

### The report token is not a secret from your staff

bordercheck fetches `policies.json` with a plain GET (it has nothing to authenticate with before it is
installed), and the file carries the report token. So **anyone who can fetch the policy can submit reports**.
That token can only submit: it can't read the dashboard, the policy upload or anyone's results. The worst a
holder can do is send false reports, overwrite a machine's report if they know its `install_id`, or fill the
database with made-up machines. Limits on that:

- `ALLOWED_EMAIL_DOMAINS` refuses reports from emails outside your domains.
- `MAX_MACHINES` caps new install IDs; history per machine is capped too.
- `POLICY_KEY` (secret) makes `/policies.json` answer only with `?key=<POLICY_KEY>`. Install with
  `…/policies.json?key=…` and put the same URL in `update.policy_url`. That keeps the token from people who
  only know your domain; every laptop still has it.
- A Cloudflare rate-limiting rule on `/report` (a laptop sends about once a day).
- Rotate: set `REPORT_TOKEN_PREVIOUS` to the old token, `REPORT_TOKEN` to a new one. Laptops pick up the new
  token with the next hourly policy refresh; delete `REPORT_TOKEN_PREVIOUS` after a few days.

Reports are self-reported anyway: they tell you who needs help, not proof of compliance.

## Dashboard access

The dashboard shows each machine's weak spots, so it is never public. Two ways in; either is enough:

**Cloudflare Access (recommended).** Create a self-hosted Access application for `bordercheck.acme.com/admin`
(only `/admin`: `/report`, `/policy`, `/enroll`, `/i/…`, `/r/…` and `/policies.json` must stay reachable by
laptops and people), allow your IT group, and set
`ACCESS_TEAM_DOMAIN` (e.g. `acme.cloudflareaccess.com`) and `ACCESS_AUD` (the application's AUD tag) in
`wrangler.jsonc`. The Worker verifies the `Cf-Access-Jwt-Assertion` JWT itself (signature against your team's
keys, audience, issuer, expiry), so a request that skips Access, say through the `workers.dev` URL, is still
refused.

**Admin token.** Without Access, `/admin` asks for `ADMIN_TOKEN` and sets a 12-hour session cookie
(HttpOnly, Secure, SameSite=Strict, signed with the token, so changing the token signs everyone out). Scripts
can send `Authorization: Bearer <ADMIN_TOKEN>`. If you use only Access, don't set `ADMIN_TOKEN`.

Pages carry a CSP with no scripts at all, and every value from a report (hostname, email, title, summary,
evidence) is escaped: a report is attacker-controllable input. Forms only accept same-origin posts.

## Alerts

`ALERT_WEBHOOK_URL` takes a Discord webhook (`https://discord.com/api/webhooks/…`), a Slack incoming webhook
(`https://hooks.slack.com/…`), or any URL that accepts JSON (`{"text": …, "alerts": [...]}`). The format is
picked from the URL; `ALERT_WEBHOOK_FORMAT` overrides it.

| Alert | Raised | Once per |
|---|---|---|
| High-severity fail | when a report has a check at `fail` + `high` that wasn't in the previous report | time the check starts failing; a check that stays failing alerts once |
| Silent | by the cron, when a machine's last report is older than `SILENT_DAYS` | silence; the next report clears it and posts "reporting again" |
| Digest | by the cron every `DIGEST_HOURS` (`0` = off) | interval |

Alerts wait in D1 until the webhook accepts them, so an outage delays them instead of losing or repeating
them; after 7 days of failures they are dropped. Values from reports appear inside `code` spans, and Discord
messages are sent with mentions disabled, so a hostname like `@everyone` or a markdown link can't ping or
phish your channel. The **Alerts** page lists recent alerts and their delivery, webhook or not.

`waived` results (a failing check exempted by policy until a date) count as not failing and never alert; the
dashboard shows them separately with their expiry. When the waiver lapses and the check fails again, that is a
new failure and alerts. Check IDs, OSes and statuses are not hardcoded: new ones show up as they arrive, and a
status this receiver doesn't know is shown as is, as neither failing nor passing.

## Configuration

Secrets (`npx wrangler secret put NAME`):

| Name | |
|---|---|
| `REPORT_TOKEN` | Shared bearer token for legacy mode. Not needed with `LEGACY_MODE=off`. |
| `REPORT_TOKEN_PREVIOUS` | Also accepted, while rotating. |
| `ADMIN_TOKEN` | Dashboard sign-in without Access. |
| `ALERT_WEBHOOK_URL` | Where alerts go. Without it alerts are only listed on the dashboard. |
| `POLICY_KEY` | If set, `/policies.json` needs `?key=`. |

Vars (`wrangler.jsonc`):

| Name | Default | |
|---|---|---|
| `DASHBOARD_URL` | | Base URL for links in alerts |
| `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | | Cloudflare Access |
| `ALLOWED_EMAIL_DOMAINS` | any | Comma-separated |
| `SILENT_DAYS` | `7` | |
| `DIGEST_HOURS` | `0` (`168` in the sample config) | |
| `HISTORY_DAYS` | `180` | History and delivered alerts older than this are deleted |
| `HISTORY_PER_MACHINE` | `500` | |
| `MAX_REPORT_BYTES` | `262144` | |
| `MAX_MACHINES` | `10000` | |
| `ALERT_WEBHOOK_FORMAT` | from the URL | `discord`, `slack` or `json` |
| `LEGACY_MODE` | `on` | `off` refuses the shared `REPORT_TOKEN` and `/policies.json` |
| `INVITE_DAYS` | `7` | Default invite lifetime (1–90 in the form) |
| `INSTALL_SH_URL`, `INSTALL_PS1_URL` | the repo's `main` scripts | Plain `https://` URLs only (they go into shell commands); anything else falls back to the default |
| `ENROLL_RATE_LIMIT` | `10` | `/enroll` attempts per client IP per window |
| `PAGE_RATE_LIMIT` | `60` | `/i/` and `/r/` page views per client IP per window |
| `RATE_WINDOW_SECONDS` | `600` | |
| `STORE_PUBLIC_IP` | `on` | Public IP and the machine's local addresses; see [What is stored](#what-is-stored) |
| `STORE_GEO` | `on` | Cloudflare's IP-based location and the device-reported position |
| `ALERT_NEW_COUNTRY` | `off` | Alert when a machine reports from a country not in its kept history |
| `REPORT_LINKS` | `on` | Login-free `/r/<id>` links |
| `REPORT_LINK_DAYS` | `30` | |

## What is stored

| Table | Holds | Kept |
|---|---|---|
| `machines` | Per `install_id`: email, hostname, OS, version, counts, first/last seen, the latest report as received | until you **Forget** the machine on its page |
| `checks` | Each check's current status per machine and since when | as `machines` |
| `reports` | Per report: time, counts, each check's status (not the summaries or evidence) | `HISTORY_DAYS`, at most `HISTORY_PER_MACHINE` per machine |
| `alerts` | Alerts with an email/hostname/title snapshot | `HISTORY_DAYS` after delivery |
| `meta` | The uploaded policy (token as placeholder), last digest time | |
| `roles` | Role names and policies | until deleted (only when unused) |
| `invites` | Email, role, note, who made it, expiry, state; SHA-256 of the code | kept |
| `enrollments` | Per enrolled machine: email, role, invite, hostname/OS at enrollment, revoked or not; SHA-256 of the token | kept (revoking keeps it) |
| `machine_waivers` | Check, end date, reason, who added/removed it | kept |
| `audit` | Who changed what and when | kept |
| `report_links` | SHA-256 of each live report link, its machine and expiry | until it expires or is replaced |
| `rate_limits` | Request counts per hashed client IP | one window |

### IP addresses and locations: personal data

**By default the receiver records where each laptop reports from.** That is personal data about your
employees (it can show where someone lives or travels). Tell them, check it fits your privacy notice and local
law (e.g. GDPR: purpose, minimisation, retention), and switch off what you don't need:

| Recorded | From | Switch | Where |
|---|---|---|---|
| Public IP | `CF-Connecting-IP`, set by Cloudflare (no other header is trusted) | `STORE_PUBLIC_IP` | latest on `machines`, per report in `reports` |
| IP-based location: country, region, city, coordinates, time zone, ASN and network name | Cloudflare's `request.cf` (an estimate from the IP, often only city-level) | `STORE_GEO` | as above |
| Local interface addresses | the report's `host.ips`, sent by the machine if its policy allows; unverified | `STORE_PUBLIC_IP` | as above, and in the stored latest report |
| Device-reported position (lat/lon, accuracy, source, time) | the report's `location`, sent by the machine if its policy allows and the OS gives one; unverified | `STORE_GEO` | as above |

Retention is the history's: per-report rows go after `HISTORY_DAYS` (and beyond `HISTORY_PER_MACHINE`), and a
machine silent for longer than `HISTORY_DAYS` has its latest IP and locations cleared too. **Forget machine**
deletes all of it at once. Turning a switch off stops collecting from the next report (the latest values are
overwritten with nothing); older history ages out as above. Under `wrangler dev` there is no Cloudflare in front,
so nothing is recorded.

The dashboard shows them on the machine page (with a plain OpenStreetMap link carrying only the coordinates,
loaded only if you click it) and a short place/IP column in the machine list. Webhook alerts never carry IPs or
coordinates; the optional new-country alert (`ALERT_NEW_COUNTRY`) carries only the two country codes.
Report links never show them.

Only the latest report keeps summaries and evidence. Evidence (file paths, ports, container names) arrives
only if the policy sets `include_evidence`. Secret values are never in a report. Times are the receiver's
clock; the machine's own clock is kept beside it. Forgetting a machine deletes its rows; if it reports again it
comes back as new.

## Develop

```sh
npm test                 # vitest in the Workers runtime, with D1 and migrations
npm run typecheck
npx wrangler d1 migrations apply bordercheck --local
npx wrangler dev --var REPORT_TOKEN:dev-report-token-123456 --var ADMIN_TOKEN:dev-admin-token-1234567
```

`bordercheck -json` plus `email` and `install_id` is a valid report to `curl` at `http://localhost:8787/report`.
