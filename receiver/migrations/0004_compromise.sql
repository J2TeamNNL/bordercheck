-- Signs of compromise: a report from a newer bordercheck can say
-- "compromised": true (a finding that shows hostile code is, or very probably
-- is, already on the machine). compromised_since is when the current unbroken
-- run of such reports began, NULL while the latest report does not say so.
-- Existing rows and older clients stay NULL: not compromised.
ALTER TABLE machines ADD COLUMN compromised_since TEXT;
-- Each report in the history: 1 when it said "compromised".
ALTER TABLE reports ADD COLUMN compromised INTEGER NOT NULL DEFAULT 0;
