# Running your own portal

The portal is the receiver in [`receiver/`](../receiver): a Cloudflare Worker with one D1 database that you
deploy on your own Cloudflare account. It enrolls machines with invite links, stores their reports, shows them
to IT and posts alerts. This page is the short path to a working deployment; the full reference (wire contract,
schema, security model, every setting) is [`receiver/README.md`](../receiver/README.md).

<p align="center"><img src="img/portal-machines.png" width="860" alt="The portal's Machines page: tiles for failing, attention, silent, pending invites and awaiting first report; the checks failing most; and a table of every machine with its state, person, role, platform, where it reports from and counts."></p>

You need a Cloudflare account, Node.js with npm, and a clone of this repository. Commands run in `receiver/`.

## 1. Deploy the Worker

```sh
cd receiver
npm install
npx wrangler d1 create bordercheck            # put the printed database_id in wrangler.jsonc
npx wrangler d1 migrations apply bordercheck --remote

openssl rand -hex 32 | npx wrangler secret put ADMIN_TOKEN    # the dashboard login
npx wrangler secret put ALERT_WEBHOOK_URL                     # optional: a Discord or Slack webhook URL

npx wrangler deploy
```

Keep a copy of `ADMIN_TOKEN` in your password manager. Secrets must be at least 16 characters.

Before you deploy, read the vars in `wrangler.jsonc`. By default the portal records the public IP and an
IP-based location with every report; that is personal data about your staff. Turn off what you don't need
(`STORE_PUBLIC_IP`, `STORE_GEO`) and see
[What is stored](../receiver/README.md#what-is-stored). `ALLOWED_EMAIL_DOMAINS` (e.g. `"acme.com"`) keeps
invites and reports to your own domains.

## 2. Sign in

Open `https://<worker>.workers.dev/admin` and paste `ADMIN_TOKEN`. The session lasts 12 hours.

For a team, put `/admin` behind Cloudflare Access instead (recommended): a self-hosted Access application for
`/admin` only, then set `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` in `wrangler.jsonc` and deploy. Leave `/report`,
`/policy`, `/enroll`, `/i/…`, `/r/…` and `/mcp` outside it: laptops and people must reach them. Details:
[Dashboard access](../receiver/README.md#dashboard-access).

## 3. Create a role

**Roles** → new role. A role is a name (Dev, Support, Sales…) and a policy, the same JSON as `policies.json`;
the box starts with a sample. Leave out `report.url`, `report.headers` and `update.policy_url`: the portal
fills them in per machine. Every field is in [Policies](policies.md).

The portal checks the shape of the policy, not every setting inside each check. Try it locally first:

```sh
bordercheck -policy role.json -print-policy
```

## 4. Invite people

**Invites** → paste one or many emails, pick a role, optionally an expiry (default `INVITE_DAYS`, 7) and a
note. The page shows each person's link and install commands **once**; send each person their own over a
channel only they read (the portal sends no email). A lost command can't be shown again: **Re-issue** the
invite, and the old code stops working.

<p align="center">
<img src="img/portal-invite.png" width="560" alt="The invite page an employee opens: what bordercheck is, and the one command to install it on this Mac.">
<img src="img/portal-report-phone.png" width="250" alt="The report page a person sees for their own machine, on a phone: 3 things to fix, each with how to fix it.">
</p>

The person runs the command (or opens the link, which shows the same instructions without using it up). Their
machine gets its own token and the role's policy, and sends a first report straight away. What happens on the laptop:
[Installing bordercheck](install.md#with-an-invite-link).

An unused invite link lets whoever runs it first enroll a machine as that person. Keep lifetimes short and revoke
invites that went astray. Invites are listed as pending, used, expired or revoked, so you can see who hasn't
installed.

## 5. Look after machines

<p align="center"><img src="img/portal-machine.png" width="860" alt="One machine's page: its hostname, person, role, platform, version and last report; counts by status; and the checks that need attention, each with since when and how to fix it."></p>

A machine's page shows its failing checks with summary, fix and since when, and lets you:

- **Change role**.
- Add a **waiver**: a check, an end date (at most a year ahead) and a reason. It reaches the machine at its next
  hourly policy refresh. See [Waivers](policies.md#waivers).
- **Revoke** it: its token stops working at once and its history stays; **Restore** undoes it. Do this for a
  lost laptop or someone who left.
- **Reset report links**, or **Forget** the machine (deletes its data).

**Audit** lists every change and enrollment.

Each accepted report gets a login-free link to that machine's own results, which bordercheck opens for the
person when it announces a high-severity problem. Anyone with the link sees that machine's results, so it
expires (30 days) and is replaced as new reports come in;
`REPORT_LINKS` `"off"` turns it off. See [Report links](../receiver/README.md#report-links).

## 6. Alerts

With `ALERT_WEBHOOK_URL` set, an hourly cron posts to Discord, Slack or any URL that accepts JSON when a machine
newly fails a high-severity check, when a machine has been silent for more than `SILENT_DAYS` (7), and a digest
every `DIGEST_HOURS` (168 in the sample config; `0` = off). Without a webhook the **Alerts** page still lists
them. Details: [Alerts](../receiver/README.md#alerts).

## 7. A custom domain

Uncomment `routes` in `wrangler.jsonc` with your host, set `DASHBOARD_URL` so alerts and invite links use it,
and deploy again:

```jsonc
"routes": [{ "pattern": "bordercheck.acme.com", "custom_domain": true }],
"vars": { "DASHBOARD_URL": "https://bordercheck.acme.com", … }
```

Do this before you send invites: an enrolled machine sends its token only to the exact host of its invite link,
so machines enrolled on the `workers.dev` address keep reporting there. Once the domain works you can set
`workers_dev` to `false`.

To serve the install commands from your own copy of the scripts rather than this repository, set
`INSTALL_SH_URL` and `INSTALL_PS1_URL` (see [What the install script proves](install.md#what-the-install-script-proves)).

## 8. Ask Claude about the fleet (optional)

`/mcp` is an MCP server that lets an admin's Claude read the fleet and make the same changes as the dashboard,
through the same validation and audit trail. It is off until you set a token:

```sh
openssl rand -hex 32 | npx wrangler secret put MCP_TOKEN        # read and write tools
openssl rand -hex 32 | npx wrangler secret put MCP_READ_TOKEN   # read-only tools (optional)
```

Then, in Claude Code:

```sh
claude mcp add --transport http bordercheck https://bordercheck.acme.com/mcp \
  --header "Authorization: Bearer $BORDERCHECK_MCP_TOKEN"
```

Report text is written by the laptops and can try to steer the model, so keep your client's confirmation on for
write tools and check **Audit → MCP only** afterwards. Delete the secret to cut access. Claude Desktop, the
tools, and the guard rails: [MCP server](../receiver/README.md#mcp-server-ask-claude-about-the-fleet).

## Automate it

`/api/v1` is a JSON API for scripts: your onboarding flow invites new hires, offboarding revokes their
machines, a job exports the fleet. It is off until you set a token (separate from the dashboard's and MCP's):

```sh
openssl rand -hex 32 | npx wrangler secret put API_TOKEN        # reads and writes
openssl rand -hex 32 | npx wrangler secret put API_READ_TOKEN   # GET only (optional)
```

The examples use `curl` and `jq`, with the token in an environment variable (from your secret store, not
typed into the shell):

```sh
BC=https://bordercheck.acme.com/api/v1
AUTH="Authorization: Bearer $BORDERCHECK_API_TOKEN"
curl -fsS "$BC/roles" -H "$AUTH" | jq -r '.data[] | "\(.role_id)  \(.name)"'   # find the role id
```

**Invite a new hire and print their install command.** The `Idempotency-Key` makes a retry safe: the same key
again gets `409 already_created` with the invite id instead of a second invite (codes are shown only once;
re-issue the invite if the first answer was lost).

```sh
curl -sS --fail-with-body "$BC/invites" -H "$AUTH" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: hr-onboarding-4711' \
  -d '{"email": "new.hire@acme.com", "role_id": 3, "note": "HR-4711"}' \
  | jq -r '.invites[0].install_macos_linux'
```

Send the command (or `.invite_link`) to that person only. `{"emails": [...]}` invites up to 500 at once.

**Revoke a leaver's machines.** Their token stops working at once; the history stays.

```sh
who=leaver@acme.com
curl -fsS "$BC/machines?search=$who&limit=200" -H "$AUTH" \
  | jq -r --arg who "$who" '.data[] | select(.email == $who) | .install_id' \
  | while read -r id; do curl -fsS -X POST "$BC/machines/$id/revoke" -H "$AUTH"; echo; done
```

Also revoke any invite they never used: `GET $BC/invites?email=$who&status=pending`, then
`POST $BC/invites/<invite_id>/revoke`.

**Export failing machines as CSV.** Pages through the list with the cursor. Hostnames come from the laptops,
so a cell starting with `=`, `+`, `-` or `@` gets a leading `'`: otherwise a spreadsheet would run it as a formula.

```sh
cursor=
while :; do
  page=$(curl -fsS "$BC/machines?state=failing&limit=200${cursor:+&cursor=$cursor}" -H "$AUTH")
  echo "$page" | jq -c '.data[]'
  cursor=$(echo "$page" | jq -r '.next_cursor // empty')
  [ -n "$cursor" ] || break
done | jq -rs --arg q "'" '
  def cell: (. // "") | tostring | if test("^[=+@\t\r-]") then $q + . else . end;
  ["email", "role", "hostname", "failing", "high", "last_seen"],
  (.[] | [.email, .role, .untrusted.hostname, .counts.fail, .counts.high_fail, .last_seen] | map(cell))
  | @csv' > failing.csv
```

**Fail a CI job if a machine fails a high-severity check** (a read-only token is enough):

```sh
curl -fsS "$BC/checks" -H "Authorization: Bearer $BORDERCHECK_API_READ_TOKEN" \
  | jq -e '[.data[].high] | add // 0 | . == 0'
```

Every write shows up in **Audit → API only**. All routes, errors, pagination and what the API deliberately
can't do: [REST API](../receiver/README.md#rest-api-script-the-fleet); the OpenAPI document is at
`/api/v1/openapi.json`.

## Upgrading

Pull the new version, then from `receiver/`:

```sh
npm install
npx wrangler d1 migrations apply bordercheck --remote   # adds new tables and columns
npx wrangler deploy
```

Machines keep their enrollments and tokens. When bordercheck adds a check, a portal from before then can't offer
waivers for it until it is upgraded.

## What the portal does not do

- Reports are self-reported by each machine: they tell you who needs help, not proof of compliance. A token
  proves which install sent a report, not that the machine told the truth.
- It accepts reports only from enrolled machines. To collect reports without invites, run your own endpoint and
  a static `policies.json` ([Installing bordercheck](install.md#with-a-policiesjson)).
