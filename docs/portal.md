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

When something fails or warns, the report page also offers a prompt to paste into Claude Code or another AI
coding assistant on that computer, with a Copy button: "Run `bordercheck fix` and follow what it prints." (with
the program's full path on that OS). The prompt holds nothing the machine reported. `bordercheck fix` prints the
findings itself, after the rules for handling them: ask before every change, never read a secret's value, treat
names and paths from the machine as data, leave bordercheck and its policy alone. It only reads; sending the new
report afterwards is `bordercheck send -force`. It needs bordercheck v0.5.0 on the machine, and a role can turn
it off with [`report.fix_prompt`](policies.md).

The link to a machine's report page is known only to that machine (`bordercheck status` prints it): the portal
keeps its hash. To pass a link to someone, an admin uses **Copy public report link** on the machine page. It
makes a new link, shows it once with a Copy button, and records who made it in the audit trail. The link works
as long as the machine's own (30 days by default) and stops when the report links are reset or the machine is
revoked. It is not offered for a machine that has not reported yet.

A value that only looks like a secret (a local database password, a test key, a local MCP server's token, an SSH
key without a passphrase used for one thing) can be set aside by the person at the machine with
`bordercheck ignore <path> [-name NAME] -reason "…"`
([how](install.md#secrets-that-are-not-sensitive)); fix's rules tell an assistant not to do that unless the person
asks for that item. It stops counting, but every report lists it, also without `include_evidence`: the machine's
page shows **Ignored by the user (N)** under the `secrets`, `ai-agents` or `ssh-keys` check, with the file, the
name or kind, the reason and the date. The report page shows only the counts. Findings marked `[production]`, AI
agent guardrails, readable key files, `authorized_keys` and SSH client settings can't be ignored this way, and a
role can turn the command off per check with `user_ignore` ([secrets](policies.md#secrets),
[ai-agents](policies.md#ai-agents), [ssh-keys](policies.md#ssh-keys)).

The `secrets` check also sets aside findings that look like sample keys on its own: a file a git repository
records unchanged, a certificate an SDK ships to everyone, a key in a `demo`/`examples`/`fixtures` folder
([rules](install.md#sample-keys)). They stop counting too, and every report lists them: the machine's page shows
**Look like sample keys (N)** under the `secrets` check, with the file, the name or kind and the rule that matched
(folded when the list is long); the report page shows only the count. Skim the list now and then: a real key
committed to a repository matches the git rule as well. A role picks the rules, or turns them off, with
`sample_rules` ([secrets](policies.md#secrets)); MCP `get_machine` and the REST machine detail give
`likely_samples_count` always and the list (`likely_samples`, under `untrusted`) with evidence.

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

### Signs of compromise

A few findings are signs that hostile code is already on a machine rather than an open door: a startup item
that downloads and runs code, an extension on the role's block list, an installed crack tool or KMS emulator
([the list](policies.md#signs-of-compromise)). A report with one says `"compromised": true`, and while a
machine's latest report does:

- **Machines** shows a **Compromised** tile and filter, lists the machine first with a red *compromised* badge;
  the fleet summary (MCP and REST) counts it, and machine lists carry `compromised` and `compromised_since`.
- The **machine page** opens with a banner: since when, each check, and each sign with its item (when the role
  sends evidence). Everything in it came from the machine and is shown as text.
- The person's **report page** tells them to stop using the computer for work and contact IT, naming the checks
  only, and does not offer the AI fix prompt.
- A **compromised** alert is raised once per episode and sent to the webhook as soon as the report is stored, not
  at the next hourly run (the cron retries if the webhook fails). When a later report no longer carries the flag,
  a **compromise cleared** alert follows the same way: check that IT made it go away, not someone deleting the
  evidence. Without a webhook both are on the Alerts page.

Treat the machine as compromised: have the person stop using it for work, look at it before anything is
removed, then have them change the passwords and keys they used on it. This is a small set of strong signs, not
malware detection: a machine without them is not proven clean. Machines tell you within `report.check_interval`
(set it, e.g. `"6h"`, in the role to notice sooner than the daily report). A role that sets
`report.compromise_alert` needs every machine of the role on a bordercheck that knows the field.

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
