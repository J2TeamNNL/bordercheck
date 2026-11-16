-- A named admin's own MCP token (bcp_…), separate from their sign-in token:
-- /mcp with it sees and changes only what the admin manages (admin_roles).
-- Only a SHA-256 of the token is kept; it is shown once, when it is made.
-- mcp_write: 1 = read and write tools, 0 = read tools only.
ALTER TABLE admins ADD COLUMN mcp_hash TEXT;
ALTER TABLE admins ADD COLUMN mcp_write INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN mcp_created_at TEXT;
CREATE UNIQUE INDEX admins_mcp_hash ON admins (mcp_hash);
