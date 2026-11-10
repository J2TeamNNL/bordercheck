-- One row per installed bordercheck, holding its latest report.
CREATE TABLE machines (
  install_id TEXT PRIMARY KEY,
  email TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  arch TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  policy TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,          -- receiver clock, ISO 8601 UTC
  last_seen TEXT NOT NULL,           -- receiver clock
  report_time TEXT,                  -- the machine's own clock, as sent
  fail INTEGER NOT NULL DEFAULT 0,
  high_fail INTEGER NOT NULL DEFAULT 0,
  error INTEGER NOT NULL DEFAULT 0,
  warn INTEGER NOT NULL DEFAULT 0,
  waived INTEGER NOT NULL DEFAULT 0,
  pass INTEGER NOT NULL DEFAULT 0,
  skip INTEGER NOT NULL DEFAULT 0,
  other INTEGER NOT NULL DEFAULT 0,  -- statuses this receiver does not know
  report TEXT NOT NULL,              -- the latest report as received
  silent_alerted_at TEXT             -- set when a "silent" alert was raised, cleared by the next report
);
CREATE INDEX machines_last_seen ON machines (last_seen);

-- Current status of each check on each machine, and since when.
CREATE TABLE checks (
  install_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  since TEXT NOT NULL,               -- first report with this status, in an unbroken run
  PRIMARY KEY (install_id, check_id)
) WITHOUT ROWID;
CREATE INDEX checks_by_check ON checks (check_id, status);

-- Compact history: counts and each check's status per report. Pruned by age and count.
CREATE TABLE reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  install_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  fail INTEGER NOT NULL DEFAULT 0,
  warn INTEGER NOT NULL DEFAULT 0,
  error INTEGER NOT NULL DEFAULT 0,
  waived INTEGER NOT NULL DEFAULT 0,
  statuses TEXT NOT NULL             -- {"firewall":"fail","secrets":"pass",...}
);
CREATE INDEX reports_by_install ON reports (install_id, id);
CREATE INDEX reports_by_time ON reports (received_at);

-- Alerts raised by reports or the cron, delivered to the webhook by the cron.
CREATE TABLE alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                -- high_fail | silent | back
  install_id TEXT NOT NULL,
  check_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}', -- snapshot of email, hostname, title… at the time
  created_at TEXT NOT NULL,
  sent_at TEXT,                      -- NULL while pending
  delivery TEXT NOT NULL DEFAULT ''  -- sent | no webhook | dropped: …
);
CREATE INDEX alerts_pending ON alerts (sent_at, id);
CREATE INDEX alerts_by_time ON alerts (created_at);

-- Small settings: the served policies.json, when the last digest went out.
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
