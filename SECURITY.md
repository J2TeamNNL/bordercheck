# Security policy

BorderCheck runs on employees' computers and updates itself, so a weakness in it can reach every computer it is
installed on. Reports are welcome, and reviews even more.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Please do not open a public
issue for a security problem. You will get an answer within 7 days; a fix for a serious problem is released as soon as
it is ready, and you are credited in the release notes unless you would rather not be.

## Bounty

**US$100** for each confirmed vulnerability in scope that was not already known (the limits listed in the threat model are) or reported, paid once the fix is
released. When several reports describe the same problem, the first one gets it. Reports must come through private
reporting and stay private until the fix is out; testing must not touch other people's computers, accounts or data.

## Scope

Most worth a look (see [the threat model](docs/threat-model.md) for how each part is meant to hold):

- **The update chain**: how a new version is found, downloaded, checked (signed `SHA256SUMS`, macOS code signature and
  notarization) and started; whether anything short of the signing key can make agents run other code.
- **The agent on the computer**: the install folder, state and token files, the hourly schedule, and whether another
  local user or a process of the same user can make it do something it should not.
- **What leaves the computer**: the report must never hold a secret's value, only where it is and its kind (and the last
  4 characters of a provider token). Any way to make a value reach the portal is a vulnerability.
- **The portal** (`receiver/`, a Cloudflare Worker): enrollment, the agents' tokens, admin sign-in, the MCP endpoint,
  roles and policies: whether one computer can read or change another's reports, or anyone can act as an admin.
- **`bordercheck guard`**: the Claude Code hooks; a secret that gets past them is worth reporting, though they are a
  safety net by design, not a boundary.

Out of scope: secrets the scan does not recognise (false negatives of the rules; an issue is fine), findings that need
an attacker already running as root/administrator, denial of service of the portal by volume, and reports from
automated scanners without a way to reproduce.

## Supported versions

Only the latest release. Agents update themselves within a day.
