-- Enrollment portal: roles, per-person invites, per-machine tokens, waivers
-- delivered through /policy, an audit trail, rate limits. Plus where each
-- report came from, and login-free links to a machine's own report.
--
-- Existing deployments upgrade in place: no existing row changes meaning.
-- A machine with no enrollments row reports with the shared REPORT_TOKEN and
-- is shown as "legacy".

-- A role is a named policy (same JSON shape as policies.json) that machines
-- belong to. report.url, report.headers' token and update.policy_url are set
-- per machine when served from /policy.
CREATE TABLE roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  policy TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- One invite per person. Only the SHA-256 of the code is kept; the code is
-- shown once, when the invite is made.
CREATE TABLE invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,      -- hex SHA-256 of the code
  email TEXT NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles (id),
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,                        -- set once, atomically, by /enroll
  used_install_id TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  reissued_as INTEGER                  -- the invite that replaced this one
);
CREATE INDEX invites_by_email ON invites (email);
CREATE INDEX invites_by_created ON invites (created_at);

-- One row per enrolled machine. Only the SHA-256 of its token is kept.
-- Revoking sets revoked_at; nothing is deleted.
CREATE TABLE enrollments (
  install_id TEXT PRIMARY KEY,         -- 32 hex, assigned by the server
  token_hash TEXT NOT NULL UNIQUE,     -- hex SHA-256 of the machine token
  email TEXT NOT NULL,                 -- from the invite; reports can't change it
  role_id INTEGER NOT NULL REFERENCES roles (id),
  invite_id INTEGER REFERENCES invites (id),
  hostname TEXT NOT NULL DEFAULT '',   -- as claimed at enrollment
  os TEXT NOT NULL DEFAULT '',
  arch TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  enrolled_at TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT,
  last_policy_at TEXT                  -- last GET /policy, at most hourly precision
);
CREATE INDEX enrollments_by_role ON enrollments (role_id);

-- Per-machine waivers, added in the dashboard and delivered through /policy
-- keyed by install_id. Removing one keeps the row.
CREATE TABLE machine_waivers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  install_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  until TEXT NOT NULL,                 -- YYYY-MM-DD
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  removed_at TEXT,
  removed_by TEXT
);
CREATE INDEX machine_waivers_by_install ON machine_waivers (install_id);

-- Who changed what. Never holds codes, tokens or report-link ids.
CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  who TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_by_time ON audit (at);

-- Fixed-window counters for unauthenticated endpoints. key is
-- "<bucket>:<hash of the client IP>".
CREATE TABLE rate_limits (
  key TEXT PRIMARY KEY,
  win INTEGER NOT NULL,                -- window number (epoch seconds / window length)
  count INTEGER NOT NULL
) WITHOUT ROWID;

-- Login-free links to a machine's own latest report (/r/<id>). Only the
-- SHA-256 of the id is kept; a new one is issued with each accepted report.
CREATE TABLE report_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_hash TEXT NOT NULL UNIQUE,
  install_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX report_links_by_install ON report_links (install_id, id);

-- Where reports come from: Cloudflare's view of the connection (public IP,
-- IP-based geolocation) and what the machine itself says (local addresses,
-- device-reported position). Empty when not collected.
ALTER TABLE machines ADD COLUMN public_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE machines ADD COLUMN geo TEXT NOT NULL DEFAULT '';             -- JSON, from request.cf
ALTER TABLE machines ADD COLUMN local_ips TEXT NOT NULL DEFAULT '';       -- JSON array, from the report
ALTER TABLE machines ADD COLUMN device_location TEXT NOT NULL DEFAULT ''; -- JSON, from the report
ALTER TABLE reports ADD COLUMN ip TEXT NOT NULL DEFAULT '';
ALTER TABLE reports ADD COLUMN geo TEXT NOT NULL DEFAULT '';
ALTER TABLE reports ADD COLUMN device_location TEXT NOT NULL DEFAULT '';
