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
- `GET /policies.json` serves your policy, so `update.policy_url` and `report.url` can point at one deployment.

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
16 characters; with no usable `REPORT_TOKEN` the receiver refuses every report, and with neither Access nor
`ADMIN_TOKEN` the dashboard is off.

Then add a custom domain (e.g. `bordercheck.acme.com`) in `routes`, set `DASHBOARD_URL` so alerts link to
the dashboard, and deploy again.

## Point bordercheck at it

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
(only `/admin`: `/report` and `/policies.json` must stay reachable by laptops), allow your IT group, and set
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
| `REPORT_TOKEN` | Bearer token bordercheck sends. Required. |
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

## What is stored

| Table | Holds | Kept |
|---|---|---|
| `machines` | Per `install_id`: email, hostname, OS, version, counts, first/last seen, the latest report as received | until you **Forget** the machine on its page |
| `checks` | Each check's current status per machine and since when | as `machines` |
| `reports` | Per report: time, counts, each check's status (not the summaries or evidence) | `HISTORY_DAYS`, at most `HISTORY_PER_MACHINE` per machine |
| `alerts` | Alerts with an email/hostname/title snapshot | `HISTORY_DAYS` after delivery |
| `meta` | The uploaded policy (token as placeholder), last digest time | |

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
