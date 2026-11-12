-- Passkeys (WebAuthn) for the admin dashboard's token/session sign-in. Only
-- public keys are kept: a passkey's private key never leaves the person's
-- device or password manager. A passkey is bound to the portal's hostname.
CREATE TABLE passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id TEXT NOT NULL UNIQUE,  -- base64url, as the authenticator made it
  public_key TEXT NOT NULL,            -- SubjectPublicKeyInfo, base64url
  alg INTEGER NOT NULL,                -- COSE algorithm: -7 (ES256) or -257 (RS256)
  sign_count INTEGER NOT NULL DEFAULT 0,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

-- One-time WebAuthn challenges. Only a SHA-256 of the challenge is kept; a row
-- is deleted when it is used (successfully or not) and expired rows are
-- removed whenever a new challenge is issued.
CREATE TABLE passkey_challenges (
  hash TEXT PRIMARY KEY,               -- hex SHA-256 of the challenge bytes
  kind TEXT NOT NULL,                  -- register | login
  expires_at INTEGER NOT NULL          -- epoch milliseconds
) WITHOUT ROWID;
CREATE INDEX passkey_challenges_expiry ON passkey_challenges (expires_at);

-- Whether the admin token may sign in is a row in meta:
-- key 'admin_token_login', value 'off' (absent or anything else: on).
