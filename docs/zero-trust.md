# Enforcing BorderCheck with Cloudflare Zero Trust

BorderCheck itself only looks and reports. To make access depend on it, the portal answers Cloudflare Zero
Trust's **device posture** checks: before Access lets a person into an application, Cloudflare asks how that
device stands. A machine that is not enrolled,
has failed a check for too long, shows signs of compromise or has gone silent loses access.

- [How the score works](#how-the-score-works)
- [What you need](#what-you-need), and [the `warp` check](#turn-on-the-warp-check) that tells people to install the client
- [Set up the integration](#set-up-the-integration) (once)
- [Enforce it](#enforce-it): Access applications, and phones
- [Roll it out](#roll-it-out) without locking everyone out
- [Troubleshooting](#troubleshooting) and [limits](#limits)

## How the score works

Cloudflare polls the portal at `POST /posture/cloudflare` with the devices its client (WARP) knows; the portal
answers a score from 0 to 100 for each:

| Machine | Score |
|---|---|
| Compliant | 100 |
| Warnings or errors only ("attention"), within the role's `access.warn_grace` (default 7 days) | 90 |
| A check fails ("non-compliant"), within the role's `access.fail_grace` (default 3 days) | 70 |
| Past those grace periods | 0 |
| **Signs of compromise**: always, no grace | 0 |
| Silent: no report for `SILENT_DAYS`, or the role's `report.interval` + 2 days if longer (a weekly role: 9 days) | 0 |
| Revoked, never reported, not enrolled, unknown device | 0 |

With a posture rule **score ≥ 60**, a machine gets time to fix what BorderCheck found and loses access after; a
compromised one loses it at once. The grace runs from when the oldest current warning (or fail) began; waived
checks do not count. Each role sets its own in its policy ([`access`](policies.md#access)):

```json
{ "access": { "warn_grace": "168h", "fail_grace": "72h" } }
```

Go durations up to `2160h` (90 days); `"0"` = no grace. Only the portal's owner can change them (not a named
admin, not MCP), and the portal leaves the section out of the policy it sends to machines.

**Matching a device to a machine.** By hardware serial number (BorderCheck v0.5.19 and later send it); a device
whose serial matches no machine is matched by the email the person was invited with and the short hostname
(`Ans-MacBook-Pro` = `ans-macbook-pro.local`). Several machines matching one device: the lowest score wins.
So people must sign in to WARP with the **same email** their BorderCheck invite was sent to.

## What you need

- A Cloudflare Zero Trust organisation, with the Cloudflare One client (WARP) on every device you want to let in,
  enrolled in that organisation, in **Posture only** mode: the client reports the device's posture and routes no
  traffic, so nothing else changes on people's machines or networks.
- The portal on a **hostname in a zone of the same Cloudflare account** (a custom domain such as
  `bordercheck.example.com`), so an Access application can sit in front of `/posture/cloudflare`. A
  `*.workers.dev` address can't carry a path-scoped Access application. Keep `workers_dev` on if machines already
  report there.
- The portal at a version with `/posture/cloudflare` and migration `0009` applied.

Without the client, a device is unknown to Cloudflare and fails every posture check. Most people do not have it
yet when you start, so **turn on the `warp` check** below first: BorderCheck then tells each of them what is
missing, long before you enforce anything.

### Turn on the `warp` check

The `warp` check is **not released yet** (planned for v0.5.21; turning it on in a policy before then is refused). It will look at the Cloudflare One client (WARP) on the machine: installed,
registered to your Zero Trust team, connected, and, if you ask for it, in "Posture only" mode. It is **off by
default**; turn it on in the policy of every role whose people must get through Zero Trust:

```json
{ "checks": { "warp": { "enabled": true, "team": "<your team name>", "posture_only": true } } }
```

- `team`: your Zero Trust team name (`<team>.cloudflareaccess.com`). A client registered to another team, or to
  none (the free consumer WARP), does not count.
- `posture_only`: also expect the "Posture only" service mode.

What it finds is a **warning**, never a fail: the person sees what to do on their report page and in a
notification, and the machine counts as "attention", within `access.warn_grace` once you enforce. The service
mode comes from your device profile's **Service mode** setting in the Zero Trust dashboard, not from the person:
set the default profile to **Posture only** before turning `posture_only` on. The portal leaves the check out of
the policy it serves to machines older than the release that has the check (they would refuse it), so once it
is out you can turn it on at once: each machine starts checking when it updates.

## Set up the integration

Five steps, in the Zero Trust dashboard or with the [`cf` CLI](https://developers.cloudflare.com/) (set
`CLOUDFLARE_ACCOUNT_ID`; run each write with `--dry-run` first). Nothing here blocks anyone yet: enforcement is
the [next section](#enforce-it).

### 1. A service token for Cloudflare to call the portal

Dashboard: **Access → Service auth → Service tokens → Create**, e.g. `BorderCheck posture`, duration one year.
Copy the **client ID** and **client secret** into your password manager: the secret is shown once.

```sh
cf zero-trust access service-tokens create --name "BorderCheck posture" --duration 8760h
```

The response holds the secret: send it straight to your secret store rather than to the terminal or a log.
Note when the token expires: the integration stops working then (renew it before).

### 2. An Access application in front of the posture path

Dashboard: **Access → Applications → Add an application → Self-hosted**, domain = the portal's hostname, path
`posture/cloudflare`. One policy: action **Service Auth**, include **Service token** = the token from step 1.
After saving, copy the application's **Application Audience (AUD) tag**.

```sh
cf zero-trust access applications create --body '{
  "type": "self_hosted",
  "name": "BorderCheck posture",
  "domain": "bordercheck.example.com/posture/cloudflare",
  "policies": [{ "name": "Posture service token", "decision": "non_identity",
                 "include": [{ "service_token": { "token_id": "<service token id>" } }] }]
}'
```

Cloudflare's own calls are the only ones that get through: people, even signed-in ones, are refused at the
door, and the portal also refuses any Access JWT that carries an email.

### 3. Tell the portal

In the portal's Wrangler config, under `vars`, then deploy:

| Var | Value |
|---|---|
| `ACCESS_TEAM_DOMAIN` | `<team>.cloudflareaccess.com` |
| `POSTURE_ACCESS_AUD` | the AUD tag from step 2 |
| `POSTURE_CLIENT_ID` | optional: the service token's client ID; then only that token gets answers |

Setting `ACCESS_TEAM_DOMAIN` alone does not put the dashboard behind Access (that needs `ACCESS_AUD` too).
Without `POSTURE_ACCESS_AUD`, `/posture/cloudflare` answers 404.

### 4. The custom service provider

Dashboard: **Integrations → Service providers → Add → Custom service provider**: the client ID and secret from
step 1, REST API URL `https://<portal hostname>/posture/cloudflare`, polling frequency e.g. 10 minutes.

```sh
cf zero-trust devices posture integrations create --name "BorderCheck" --type custom_s2s --interval 10m \
  --config-api-url "https://bordercheck.example.com/posture/cloudflare" \
  --config-access-client-id "<client id>" --config-access-client-secret "$SECRET"   # from your secret store
```

### 5. The posture check

Dashboard: **Reusable components → Posture checks → Service provider checks → Add**: provider = the
integration from step 4, **Score** greater than or equal to **60**. Give it an expiration, so that if the portal
can't be reached devices fail instead of keeping an old pass. Cloudflare wants a schedule with it, and the
expiration at least 15 minutes longer than the schedule (e.g. schedule 10 minutes, expiration 30).

```sh
cf zero-trust devices posture rules create --body '{
  "name": "BorderCheck score >= 60", "type": "custom_s2s", "schedule": "10m", "expiration": "30m",
  "input": { "connection_id": "<integration id>", "operator": ">=", "score": 60 }
}'
```

(The rule's `description` is limited to 100 characters.)

From now on Cloudflare shows each device's result (**My Team → Devices → a device → Posture checks**) but no
policy uses it yet: a dry run you can watch.

## Enforce it

Add the check from step 5 to the policies that decide who gets in. Start with one application (see
[Roll it out](#roll-it-out)).

### Access applications (web apps, SSH and databases behind Tunnel)

For each self-hosted application: **Policies → the Allow policy → Add require → Device posture → "BorderCheck
score >= 60"**. A `require` must hold on top of the `include` rules (who the person is), so existing identity
rules stay as they are. Bypass and Service Auth policies (webhooks, agents, health checks) are not people's
devices: leave them alone.

### Phones and tablets: let them through (the default) or not

BorderCheck does not run on iOS or Android, so a phone never passes the BorderCheck check. Zero Trust tells a
phone apart only when it runs the **Cloudflare One Agent** app signed in to your team: without it, Access sees
who the person is but not what device they are on, and any posture requirement fails.

To let phones through (recommended default), create two Cloudflare One Client checks once, **OS version**,
iOS and Android, each with the oldest version you accept. A phone that is not kept up to date is the easiest one
to exploit, so this is the most useful signal Zero Trust has about a phone; the versions the Cloudflare One
client still supports are a sensible floor (in November 2026: iOS 18, Android 14):

```sh
cf zero-trust devices posture rules create --body '{"name": "Mobile: iOS 18 or later", "type": "os_version",
  "match": [{"platform": "ios"}], "input": {"version": "18.0.0", "operator": ">="}}'
cf zero-trust devices posture rules create --body '{"name": "Mobile: Android 14 or later", "type": "os_version",
  "match": [{"platform": "android"}], "input": {"version": "14.0.0", "operator": ">="}}'
```

Raise the versions over time (`cf zero-trust devices posture rules update <id> --body …`). A posture result
only exists for a device whose client is enrolled in your team, so passing the OS version check also shows the
app is running and signed in to the right team.

Then, in each application where you require the BorderCheck check, add a **second Allow policy** next to it:

| Policy | Include (any of) | Require (all of) |
|---|---|---|
| Computers | your people (e.g. emails ending in `@example.com`) | Device posture: *BorderCheck score >= 60* |
| Phones | Device posture: *Mobile: iOS 18 or later*, *Mobile: Android 14 or later* | your people (the same identity rule) |

Access lets a person in when any Allow policy matches, so phones pass the second one and computers must pass the
first. To keep phones out of an application, leave the Phones policy out of it.

**What Zero Trust cannot tell about a phone.** Whether it is jailbroken or rooted, or a simulator or emulator:
the client has no such check. That takes an MDM or mobile threat defense product (Intune, Jamf, Lookout…)
connected as another service provider. Until then, let phones into the applications where that risk is
acceptable and leave the Phones policy out of the sensitive ones (admin panels, databases, SSH, cluster
consoles): those then stay reachable only from computers that pass BorderCheck.

## Roll it out

1. **Set up, don't enforce.** Steps 1–5 only, and [the `warp` check](#turn-on-the-warp-check) on in each
   role, so people hear from BorderCheck that they need the client. Check device results in Zero Trust and the portal's filters
   (*Fail, error or warn*, *Silent*): who would lose access today, and why (not enrolled, WARP signed in with
   another email, an old warning past its grace…).
2. **Announce a date.** Tell people what to do by when: install BorderCheck from their invite, sign in to WARP
   with the same email, fix what their report page lists. A machine that already has a warning older than
   `warn_grace` (or a fail older than `fail_grace`) loses access the moment you enforce: give the date enough
   room, or raise the grace for the first weeks (owner, in the role's `access`).
3. **Enforce on one application** first, ideally one used daily by people who can report problems quickly.
4. **Then the rest**, application by application.
5. **Undo** = remove the posture requirement from a policy. Nothing on the portal side needs to change.

## Troubleshooting

A device scores 0 though the person has BorderCheck:

- **No client, or registered elsewhere.** The `warp` check on the machine says which: not installed, another
  team, not connected.
- **Different email.** WARP's user and the BorderCheck invite must be the same address (case does not matter).
- **No serial and a different hostname.** Before v0.5.19 there is no serial; the short hostname in WARP must
  match the one in the portal. Update BorderCheck (it updates itself daily when the policy allows).
- **Past the grace.** The machine page in the portal shows each check's "since".
- **Silent.** No report for `SILENT_DAYS` (or the role's report interval + 2 days): the service stopped or the machine was off; `bordercheck status`
  on the machine says why.
- **Revoked**, or **signs of compromise**: by design.

The integration shows errors in Zero Trust: check the service token has not expired, the Access application's
path and policy, and the portal's `POSTURE_ACCESS_AUD` / `POSTURE_CLIENT_ID`.

## Limits

- BorderCheck's view is what each machine reports about itself: it raises the bar for everyone, it is not
  hardware attestation, and a person with admin rights on their machine can lie to it.
- Changes show at Cloudflare's next poll, and open sessions are not cut.
- Applications that sign people in with Google directly (not through Access) are not covered: put them behind
  Access first.
