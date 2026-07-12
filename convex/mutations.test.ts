/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import { api, internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");
process.env.ANONYMOUS_SESSION_SECRET = "test-anonymous-session-secret";
const alice = "11111111-1111-4111-8111-111111111111";
const bob = "22222222-2222-4222-8222-222222222222";

async function completeScan(t: ReturnType<typeof convexTest>, scanId: Id<"scans">) {
  await t.mutation(internal.mutations.claimScanRun, { scanId });
  await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "auditing_dependencies" });
  await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "verifying" });
  await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "completed" });
}

describe("anonymous scan isolation and controls", () => {
  it("creates a canonical scan for a valid anonymous session", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/Acme/widget.git", sessionToken: alice });
    const scan = await t.query(api.mutations.getScan, { scanId, sessionToken: alice });
    expect(scan?.repoUrl).toBe("https://github.com/Acme/widget");
    expect(scan?.status).toBe("initialized");
    expect(scan).not.toHaveProperty("ownerTokenIdentifier");
  });

  it("does not expose one browser session to another", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: alice });
    expect(await t.query(api.mutations.getScan, { scanId, sessionToken: bob })).toBeNull();
  });

  it("rejects malformed anonymous session capabilities", async () => {
    const t = convexTest(schema, modules);
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: "guessable" })).rejects.toThrow("Invalid anonymous session");
  });

  it("returns the same active scan for an idempotent retry", async () => {
    const t = convexTest(schema, modules);
    const first = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: alice });
    const second = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: alice });
    expect(second).toBe(first);
  });

  it("atomically claims once and recovers an expired lease without duplicate output", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: alice });
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe("claimed");
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe("busy");
    await t.mutation(internal.mutations.appendScanLog, { scanId, agent: "SecurityLead", message: "partial", level: "info" });
    await t.mutation(internal.mutations.createFinding, { scanId, filePath: "package.json", type: "vulnerable_dependency", severity: "HIGH", description: "Partial", evidence: "CVE-2026-0003", status: "open" });
    await t.run((ctx) => ctx.db.patch(scanId, { claimedAt: Date.now() - 31 * 60 * 1000 }));
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe("claimed");
    expect(await t.query(api.mutations.getScanLogs, { scanId, sessionToken: alice })).toEqual([]);
    expect(await t.query(api.mutations.getScanFindings, { scanId, sessionToken: alice })).toEqual([]);
  });

  it("enforces one active scan beyond the hourly quota window", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/long-running", sessionToken: alice });
    await t.run((ctx) => ctx.db.patch(scanId, { startedAt: Date.now() - 2 * 60 * 60 * 1000 }));
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/other", sessionToken: alice })).rejects.toThrow("Finish the active scan");
  });

  it("enforces the per-session hourly quota", async () => {
    const t = convexTest(schema, modules);
    for (let index = 0; index < 5; index += 1) {
      const scanId = await t.mutation(api.mutations.createScan, { repoUrl: `https://github.com/acme/widget-${index}`, sessionToken: alice });
      await completeScan(t, scanId);
    }
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/overflow", sessionToken: alice })).rejects.toThrow("hourly scan quota");
  });

  it("enforces deployment-wide hourly capacity", async () => {
    const t = convexTest(schema, modules);
    for (let index = 0; index < 30; index += 1) {
      const sessionToken = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
      const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken });
      expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe("claimed");
    }
    const overflow = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/overflow", sessionToken: bob });
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId: overflow })).toBe("capacity");
  });

  it("enforces persistent output caps", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/capped", sessionToken: alice });
    await t.run((ctx) => ctx.db.patch(scanId, { logCount: 250, findingCount: 100 }));
    expect(await t.mutation(internal.mutations.appendScanLog, { scanId, agent: "SecurityLead", message: "overflow", level: "warning" })).toBeNull();
    expect(await t.mutation(internal.mutations.createFinding, { scanId, filePath: "package.json", type: "vulnerable_dependency", severity: "HIGH", description: "overflow", evidence: "none", status: "open" })).toBeNull();
  });

  it("records completed-scan risk acceptance idempotently", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget", sessionToken: alice });
    await completeScan(t, scanId);
    const findingId = await t.mutation(internal.mutations.createFinding, { scanId, filePath: "package.json", type: "vulnerable_dependency", severity: "HIGH", description: "Synthetic", evidence: "CVE-2026-0001", status: "open" });
    if (!findingId) throw new Error("Expected finding to be stored.");
    const storedFindingId = findingId;
    const first = await t.mutation(api.mutations.acceptRisk, { findingId: storedFindingId, reason: "Accepted for isolated fixture testing.", sessionToken: alice });
    const second = await t.mutation(api.mutations.acceptRisk, { findingId: storedFindingId, reason: "Accepted for isolated fixture testing.", sessionToken: alice });
    expect(second).toBe(first);
  });
});
