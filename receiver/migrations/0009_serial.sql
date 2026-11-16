-- The machine's hardware serial number, as its BorderCheck service reports it
-- (at enrollment, then in each report), so a Zero Trust client's device can
-- be matched to a machine (posture.ts). Not unique: firmware placeholders are
-- dropped by the client, and a duplicate gets the worse posture.
ALTER TABLE enrollments ADD COLUMN serial TEXT COLLATE NOCASE;
ALTER TABLE machines ADD COLUMN serial TEXT COLLATE NOCASE;
CREATE INDEX enrollments_serial ON enrollments (serial);
CREATE INDEX machines_serial ON machines (serial);
