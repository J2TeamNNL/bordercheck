import { beforeEach, describe, expect, it } from "vitest";
import { chunk, lit, payload, runCron, webhookFormat, webhooks } from "../src/alerts";
import type { Env } from "../src/env";
import { handleReport } from "../src/ingest";
import { enrolled, env, report, reportRequest, result } from "./helpers";

const DISCORD = "https://discord.com/api/webhooks/123/abc";
const SLACK = "https://hooks.slack.com/services/T/B/X";

// Reports come from one enrolled machine.
let machine: { install_id: string; token: string };
beforeEach(async () => {
  machine = await enrolled();
});
const req = (body: unknown) => reportRequest(body, machine.token);
const day = (d: number) => new Date(Date.UTC(2026, 10, d, 10));

function recorder(fail = false) {
  const calls: { url: string; body: any }[] = [];
  const send = async (url: string, body: unknown) => {
    if (fail) throw new Error("webhook answered 500");
    calls.push({ url, body });
  };
  return { calls, send };
}

const withHook = (url = DISCORD, extra: Partial<Env> = {}): Env => ({ ...env, ALERT_WEBHOOK_URL: url, DIGEST_HOURS: "0", ...extra });

describe("webhook format", () => {
  it("detects Discord and Slack", () => {
    expect(webhookFormat(withHook(DISCORD))).toBe("discord");
    expect(webhookFormat(withHook("https://discordapp.com/api/webhooks/1/x"))).toBe("discord");
    expect(webhookFormat(withHook(SLACK))).toBe("slack");
    expect(webhookFormat(withHook("https://example.com/hook"))).toBe("json");
    expect(webhookFormat(withHook("https://example.com/hook", { ALERT_WEBHOOK_FORMAT: "slack" }))).toBe("slack");
  });

  it("neutralises mentions, links and formatting from reports", () => {
    expect(lit("@everyone [click](https://evil.example)")).toBe("`@everyone [click](https://evil.example)`");
    expect(lit("a`b\nc")).toBe("`a b c`");
    expect(payload("discord", "x")).toMatchObject({ content: "x", allowed_mentions: { parse: [] } });
    expect(payload("slack", "<!channel> & co")).toEqual({ text: "&lt;!channel&gt; &amp; co" });
  });

  it("chunks under the size limit", () => {
    const lines = Array.from({ length: 100 }, (_, i) => `line ${i} ${"x".repeat(50)}`);
    const groups = chunk(lines, 1900);
    expect(groups.flat()).toEqual(lines);
    for (const g of groups) expect(g.join("\n").length).toBeLessThan(1900);
  });
});

describe("cron", () => {
  it("sends a new high-severity fail once, to Discord", async () => {
    const e = withHook(DISCORD, { DASHBOARD_URL: "https://bordercheck.example.com/" });
    await handleReport(req(report({ host: { os: "darwin", arch: "arm64", hostname: "@everyone" } })), e, day(1));
    const r = recorder();
    expect(await runCron(e, day(1), r.send)).toMatchObject({ sent: 1, failed: null });
    expect(r.calls).toHaveLength(1);
    const content: string = r.calls[0].body.content;
    expect(content).toContain("high-severity fail `firewall`");
    expect(content).toContain("`@everyone`");
    expect(content).toContain(`https://bordercheck.example.com/admin/machine/${machine.install_id}`);
    expect(r.calls[0].body.allowed_mentions).toEqual({ parse: [] });

    await handleReport(req(report()), e, day(2)); // still failing
    expect((await runCron(e, day(2), r.send)).sent).toBe(0);
    expect(r.calls).toHaveLength(1);
  });

  it("works with Slack payloads", async () => {
    const e = withHook(SLACK);
    await handleReport(req(report()), e, day(1));
    const r = recorder();
    await runCron(e, day(1), r.send);
    expect(r.calls[0].body.text).toContain("*BorderCheck*: 1 new alert");
    expect(r.calls[0].body.content).toBeUndefined();
  });

  it("keeps alerts pending while the webhook fails, then delivers them", async () => {
    const e = withHook();
    await handleReport(req(report()), e, day(1));
    expect(await runCron(e, day(1), recorder(true).send)).toMatchObject({ sent: 0, failed: "discord webhook: webhook answered 500" });
    const r = recorder();
    expect((await runCron(e, day(1), r.send)).sent).toBe(1);
    expect((await runCron(e, day(1), r.send)).sent).toBe(0);
  });

  it("drops alerts the webhook refused for a week", async () => {
    const e = withHook();
    await handleReport(req(report()), e, day(1));
    await runCron(e, day(1), recorder(true).send);
    const r = recorder();
    await runCron({ ...e, SILENT_DAYS: "30" }, day(9), r.send);
    expect(r.calls).toHaveLength(0);
    const a = await env.DB.prepare("SELECT delivery FROM alerts").first("delivery");
    expect(a).toMatch(/^dropped/);
  });

  it("alerts once when a machine goes silent, and when it comes back", async () => {
    const e = withHook(DISCORD, { SILENT_DAYS: "3" });
    await handleReport(req(report({}, [result("firewall", "pass")])), e, day(1));
    const r = recorder();
    expect((await runCron(e, day(3), r.send)).silent).toBe(0);
    expect((await runCron(e, day(5), r.send)).silent).toBe(1);
    expect((await runCron(e, day(6), r.send)).silent).toBe(0); // not again
    expect(r.calls).toHaveLength(1);
    expect(r.calls[0].body.content).toContain("no report since 2026-11-01");

    await handleReport(req(report({}, [result("firewall", "pass")])), e, day(7));
    await runCron(e, day(7), r.send);
    expect(r.calls[1].body.content).toContain("reporting again");
    // and can go silent again later
    expect((await runCron(e, day(11), r.send)).silent).toBe(1);
  });

  it("marks alerts as not delivered when there is no webhook", async () => {
    await handleReport(req(report()), env, day(1));
    await runCron({ ...env, ALERT_WEBHOOK_URL: "" }, day(1), recorder().send);
    expect(await env.DB.prepare("SELECT delivery FROM alerts").first("delivery")).toBe("no webhook");
  });

  it("sends a digest every DIGEST_HOURS", async () => {
    const e = withHook(DISCORD, { DIGEST_HOURS: "168" });
    await handleReport(req(report()), e, day(1));
    const r = recorder();
    await runCron(e, day(1), r.send);
    const digests = () => r.calls.filter((c) => c.body.content.includes("digest"));
    expect(digests()).toHaveLength(1);
    expect(digests()[0].body.content).toContain("1 machines, 1 non-compliant");
    expect(digests()[0].body.content).toContain("`firewall` 1");
    await runCron(e, new Date(day(1).getTime() + 3600_000), r.send);
    expect(digests()).toHaveLength(1);
    await runCron(e, day(8), r.send);
    expect(digests()).toHaveLength(2);
  });

  it("prunes history older than HISTORY_DAYS", async () => {
    const e = withHook(DISCORD, { HISTORY_DAYS: "2" });
    await handleReport(req(report()), e, day(1));
    await handleReport(req(report()), e, day(5));
    await runCron(e, day(5), recorder().send);
    expect(await env.DB.prepare("SELECT COUNT(*) n FROM reports").first("n")).toBe(1);
  });
});

const TG = "https://api.telegram.org/bot123456:SECRET-token/sendMessage";

describe("Telegram and several webhooks", () => {
  it("reads a list of URLs and takes Telegram's chat from the URL or ALERT_TELEGRAM_CHAT_ID", () => {
    const hooks = webhooks(withHook(`${DISCORD}, ${TG}?chat_id=-100200\n https://api.telegram.org/bot99:x not-a-url`));
    expect(hooks.map((h) => h.format)).toEqual(["discord", "telegram", "telegram"]);
    expect(hooks[1]).toMatchObject({ url: TG, chatId: "-100200" });
    expect(hooks[2]).toMatchObject({ url: "https://api.telegram.org/bot99:x/sendMessage", chatId: undefined });
    expect(webhooks(withHook(TG, { ALERT_TELEGRAM_CHAT_ID: "42" }))[0].chatId).toBe("42");
    expect(webhookFormat(withHook(TG))).toBe("telegram");
    expect(webhooks(withHook(`${DISCORD} ${DISCORD}`))).toHaveLength(1);
    expect(payload("telegram", "**x** <b>", {}, "-1")).toEqual({ chat_id: "-1", text: "**x** <b>", disable_web_page_preview: true });
  });

  it("sends to every webhook; one that fails gets the alert later, the others not again", async () => {
    const e = withHook(`${SLACK},${TG}?chat_id=-100200`);
    await handleReport(req(report()), e, day(1));
    const calls: { url: string; body: any }[] = [];
    let telegramDown = true;
    const send = async (url: string, body: unknown) => {
      if (url.startsWith("https://api.telegram.org/") && telegramDown) throw new Error("webhook answered 502");
      calls.push({ url, body });
    };
    const first = await runCron(e, day(1), send);
    expect(first).toMatchObject({ sent: 0, failed: "telegram webhook 2: webhook answered 502" });
    expect(calls.map((c) => c.url)).toEqual([SLACK]);
    telegramDown = false;
    expect((await runCron(e, day(1), send)).sent).toBe(1);
    expect(calls.map((c) => c.url)).toEqual([SLACK, TG]);
    expect(calls[1].body).toMatchObject({ chat_id: "-100200", disable_web_page_preview: true });
    expect(calls[1].body.text).toMatch(/^BorderCheck: 1 new alert\n/);
    expect((await runCron(e, day(1), send)).sent).toBe(0);
    expect(calls).toHaveLength(2);
  });

  it("says so when a Telegram webhook has no chat, without its token", async () => {
    const e = withHook(TG);
    await handleReport(req(report()), e, day(1));
    const r = recorder();
    const out = await runCron(e, day(1), r.send);
    expect(out.failed).toContain("no chat_id");
    expect(out.failed).not.toContain("SECRET");
    expect(r.calls).toHaveLength(0);
  });

  it("sends the digest to each webhook", async () => {
    const e = withHook(`${DISCORD} ${TG}?chat_id=-1`, { DIGEST_HOURS: "24" });
    const r = recorder();
    expect((await runCron(e, day(1), r.send)).digest).toBe(true);
    expect(r.calls.map((c) => c.url)).toEqual([DISCORD, TG]);
    expect(r.calls[0].body.content).toMatch(/^\*\*BorderCheck digest\*\*/);
    expect(r.calls[1].body.text).toMatch(/^BorderCheck digest:/);
  });
});
