-- Named admins: people the owner (whoever holds ADMIN_TOKEN, or a passkey of
-- the owner's) lets into the portal, each with a name and a token of their own.
-- Only a SHA-256 of the token is kept; the token is shown once, when it is
-- made. `gen` is part of every session cookie of that admin: bumping it (new
-- token) signs all their sessions out, and deleting the row does too.
CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  token_hash TEXT NOT NULL UNIQUE,     -- hex SHA-256 of the token (bca_…)
  gen INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,            -- the audit name of who added them
  last_used_at TEXT                    -- last sign-in (form or passkey), not every request
);

-- Whose passkey: NULL is the owner's, otherwise admins.id. Deleting an admin
-- deletes their passkeys in the same batch (index.ts / admins.ts).
ALTER TABLE passkeys ADD COLUMN admin_id INTEGER;
CREATE INDEX passkeys_admin ON passkeys (admin_id);

-- Which roles a named admin manages: their machines, invites and the roles
-- themselves. Exactly these rows are their scope (none: they see nothing but
-- may create a role, which lands here). The owner and Access viewers are not
-- scoped. Rows go with the admin or the role (D1 enforces foreign keys).
CREATE TABLE admin_roles (
  admin_id INTEGER NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
  role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
  PRIMARY KEY (admin_id, role_id)
) WITHOUT ROWID;
CREATE INDEX admin_roles_role ON admin_roles (role_id);
