-- How many checks in a machine's latest report carry Info: things worth
-- knowing that are not a problem (Android keystores, sign-in caches, keys in
-- AI chat history). Never counted as a problem; for the "With info" filter.
ALTER TABLE machines ADD COLUMN info INTEGER NOT NULL DEFAULT 0;
