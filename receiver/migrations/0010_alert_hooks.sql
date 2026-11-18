-- Alerts can go to several webhooks (ALERT_WEBHOOK_URL holds a list). An alert
-- stays pending until every webhook has taken it; delivered_to lists the
-- webhooks that have, so a failing one does not make the others repeat it.
ALTER TABLE alerts ADD COLUMN delivered_to TEXT NOT NULL DEFAULT '';
