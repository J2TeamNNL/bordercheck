import { applyD1Migrations, type D1Migration, env } from "cloudflare:test";
import { beforeAll, beforeEach } from "vitest";

const e = env as unknown as { DB: D1Database; TEST_MIGRATIONS: D1Migration[] };

beforeAll(async () => {
  await applyD1Migrations(e.DB, e.TEST_MIGRATIONS);
});

beforeEach(async () => {
  await e.DB.batch(["machines", "checks", "reports", "alerts", "meta"].map((t) => e.DB.prepare(`DELETE FROM ${t}`)));
});
