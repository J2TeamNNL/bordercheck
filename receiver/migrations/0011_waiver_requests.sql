-- Waivers asked for from the machine itself (bordercheck waiver request, sent
-- with the machine's token). An admin approves one, which adds an ordinary
-- machine_waivers row (waiver_id), or rejects it. reason is the requester's
-- text: untrusted, like everything a machine sends.
CREATE TABLE waiver_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  install_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  until TEXT NOT NULL,                       -- YYYY-MM-DD
  reason TEXT NOT NULL,
  accept_risk INTEGER NOT NULL DEFAULT 0,    -- the person said they accept the risk
  status TEXT NOT NULL DEFAULT 'pending',    -- pending | approved | rejected
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  decision_note TEXT NOT NULL DEFAULT '',
  waiver_id INTEGER                          -- the waiver an approval added
);
CREATE INDEX waiver_requests_by_install ON waiver_requests (install_id, status);
CREATE INDEX waiver_requests_by_status ON waiver_requests (status, created_at);
