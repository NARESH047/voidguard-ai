/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import { api, internal } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");

describe("scan authorization and controls", () => {
  it("creates a canonical scan owned by the authenticated user", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/Acme/widget.git" });
    const scan = await t.query(api.mutations.getScan, { scanId });
    expect(scan?.repoUrl).toBe("https://github.com/Acme/widget");
    expect(scan?.status).toBe("initialized");
  });

  it("does not expose a scan to another user", async () => {
    const t = convexTest(schema, modules);
    const alice = t.withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const bob = t.withIdentity({ subject: "bob", issuer: "https://auth.test" });
    const scanId = await alice.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    expect(await bob.query(api.mutations.getScan, { scanId })).toBeNull();
  });

  it("requires authentication to create scans", async () => {
    const t = convexTest(schema, modules);
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" })).rejects.toThrow("Authentication required");
  });

  it("returns the same active scan for an idempotent retry", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const first = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    const second = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    expect(second).toBe(first);
  });

  it("atomically claims a scan only once and recovers an expired lease", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe(true);
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe(false);
    await t.mutation(internal.mutations.appendScanLog, { scanId, agent: "SecurityLead", message: "partial", level: "info" });
    await t.mutation(internal.mutations.createFinding, {
      scanId,
      filePath: "package.json",
      type: "vulnerable_dependency",
      severity: "HIGH",
      description: "Partial finding",
      evidence: "CVE-2026-0003",
      status: "open",
    });
    await t.run((ctx) => ctx.db.patch(scanId, { claimedAt: Date.now() - 31 * 60 * 1000 }));
    expect(await t.mutation(internal.mutations.claimScanRun, { scanId })).toBe(true);
    expect(await t.query(api.mutations.getScanLogs, { scanId })).toEqual([]);
    expect(await t.query(api.mutations.getScanFindings, { scanId })).toEqual([]);
  });

  it("enforces one active scan beyond the hourly quota window", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/long-running" });
    await t.run((ctx) => ctx.db.patch(scanId, { startedAt: Date.now() - 2 * 60 * 60 * 1000 }));
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/other" })).rejects.toThrow("Finish the active scan");
  });

  it("enforces the hourly scan quota", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    for (let index = 0; index < 5; index += 1) {
      const scanId = await t.mutation(api.mutations.createScan, { repoUrl: `https://github.com/acme/widget-${index}` });
      await t.mutation(internal.mutations.claimScanRun, { scanId });
      await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "auditing_dependencies" });
      await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "verifying" });
      await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "completed" });
    }
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/overflow" })).rejects.toThrow("Hourly scan quota reached");
  });

  it("records risk acceptance idempotently", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test", email: "alice@example.com" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    await t.mutation(internal.mutations.claimScanRun, { scanId });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "auditing_dependencies" });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "verifying" });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "completed" });
    const findingId = await t.mutation(internal.mutations.createFinding, {
      scanId,
      filePath: "package.json",
      type: "vulnerable_dependency",
      severity: "HIGH",
      description: "Synthetic finding",
      evidence: "CVE-2026-0001",
      status: "open",
    });
    await t.mutation(internal.mutations.attachPatchToFinding, { findingId, remediationPatch: "--- a/package.json\n+++ b/package.json" });
    const [proposal] = await t.query(api.mutations.getScanFindings, { scanId });
    expect(proposal.status).toBe("open");
    expect(proposal.remediationPatch).toContain("package.json");
    const first = await t.mutation(api.mutations.acceptRisk, { findingId, reason: "Accepted for isolated fixture testing." });
    const second = await t.mutation(api.mutations.acceptRisk, { findingId, reason: "Accepted for isolated fixture testing." });
    expect(second).toBe(first);
  });

  it("rejects risk acceptance for non-open findings", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    await t.mutation(internal.mutations.claimScanRun, { scanId });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "auditing_dependencies" });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "verifying" });
    await t.mutation(internal.mutations.updateScanStatus, { scanId, status: "completed" });
    const findingId = await t.run((ctx) => ctx.db.insert("findings", {
      scanId,
      filePath: "package.json",
      type: "vulnerable_dependency",
      severity: "HIGH",
      description: "Already remediated fixture",
      evidence: "CVE-2026-0002",
      status: "remediated",
    }));
    await expect(t.mutation(api.mutations.acceptRisk, { findingId, reason: "This must not be accepted twice." })).rejects.toThrow("Only open findings");
  });
});
