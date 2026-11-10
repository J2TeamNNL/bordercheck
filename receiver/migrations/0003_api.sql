-- REST API (/api/v1): Idempotency-Key records for POST /invites, so a script
-- that retries does not invite the same people twice. Only a hash of the key
-- and of the request body are kept, with the ids of the invites it created;
-- never the invite codes. Rows expire after 24 hours and the cron prunes them.
CREATE TABLE api_idempotency (
  key_hash TEXT PRIMARY KEY,           -- hex SHA-256 of the Idempotency-Key header
  request_hash TEXT NOT NULL,          -- hex SHA-256 of the canonical request body
  state TEXT NOT NULL,                 -- pending | done
  invite_ids TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX api_idempotency_expiry ON api_idempotency (expires_at);
