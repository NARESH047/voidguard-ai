import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { v } from "convex/values";
import { parseGitHubRepoUrl } from "./lib/security";
import { anonymousOwnerKey } from "./lib/session";

const scanStatus = v.union(
  v.literal("initialized"),
  v.literal("scanning_secrets"),
  v.literal("auditing_dependencies"),
  v.literal("writing_remediations"),
  v.literal("verifying"),
  v.literal("completed"),
  v.literal("failed"),
);

const agent = v.union(
  v.literal("SecurityLead"),
  v.literal("SecretsScanner"),
  v.literal("DependencyAuditor"),
  v.literal("RemediationWriter"),
  v.literal("QA_Verifier"),
);

const logLevel = v.union(v.literal("info"), v.literal("warning"), v.literal("error"), v.literal("success"));
const activeStatuses = ["initialized", "scanning_secrets", "auditing_dependencies", "writing_remediations", "verifying"] as const;
const SCAN_LEASE_MS = 30 * 60 * 1000;
const SESSION_HOURLY_LIMIT = 5;
const GLOBAL_HOURLY_LIMIT = 30;

function exposeScan(scan: Doc<"scans">) {
  const { ownerTokenIdentifier, claimedAt, ...publicScan } = scan;
  void ownerTokenIdentifier;
  void claimedAt;
  return publicScan;
}

export const createScan = mutation({
  args: { repoUrl: v.string(), sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const repository = parseGitHubRepoUrl(args.repoUrl);
    const activeScans = await Promise.all(activeStatuses.map((status) =>
      ctx.db
        .query("scans")
        .withIndex("by_owner_and_status", (q) => q.eq("ownerTokenIdentifier", ownerTokenIdentifier).eq("status", status))
        .order("desc")
        .first(),
    ));
    const activeScan = activeScans.find(Boolean);
    const hourAgo = Date.now() - 60 * 60 * 1000;
    const recentScans = await ctx.db
      .query("scans")
      .withIndex("by_owner_and_startedAt", (q) => q.eq("ownerTokenIdentifier", ownerTokenIdentifier).gte("startedAt", hourAgo))
      .order("desc")
      .take(SESSION_HOURLY_LIMIT + 1);

    if (activeScan) {
      if (activeScan.repoUrl === repository.canonicalUrl) return activeScan._id;
      throw new Error("Finish the active scan before starting another repository.");
    }
    if (recentScans.length >= SESSION_HOURLY_LIMIT) throw new Error("This browser session has reached its hourly scan quota.");

    return ctx.db.insert("scans", {
      ownerTokenIdentifier,
      repoUrl: repository.canonicalUrl,
      status: "initialized",
      logCount: 0,
      findingCount: 0,
      startedAt: Date.now(),
    });
  },
});

export const getScan = query({
  args: { scanId: v.id("scans"), sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const scan = await ctx.db.get(args.scanId);
    return scan?.ownerTokenIdentifier === ownerTokenIdentifier ? exposeScan(scan) : null;
  },
});

export const listRecentScans = query({
  args: { sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const scans = await ctx.db
      .query("scans")
      .withIndex("by_owner_and_startedAt", (q) => q.eq("ownerTokenIdentifier", ownerTokenIdentifier))
      .order("desc")
      .take(20);
    return scans.map(exposeScan);
  },
});

export const getScanLogs = query({
  args: { scanId: v.id("scans"), sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) return [];
    return ctx.db.query("scanLogs").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).order("asc").take(250);
  },
});

export const getScanFindings = query({
  args: { scanId: v.id("scans"), sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) return [];
    return ctx.db.query("findings").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).order("desc").take(100);
  },
});

export const requireOwnedScan = internalQuery({
  args: { scanId: v.id("scans"), ownerTokenIdentifier: v.string() },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    return scan?.ownerTokenIdentifier === args.ownerTokenIdentifier ? scan : null;
  },
});

export const claimScanRun = internalMutation({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan || ["completed", "failed"].includes(scan.status)) return "busy" as const;
    const now = Date.now();
    const leaseStartedAt = scan.claimedAt ?? scan.startedAt;
    if (scan.status !== "initialized" && now - leaseStartedAt < SCAN_LEASE_MS) return "busy" as const;
    const recentClaims = await ctx.db
      .query("scans")
      .withIndex("by_claimedAt", (q) => q.gte("claimedAt", now - 60 * 60 * 1000))
      .order("desc")
      .take(GLOBAL_HOURLY_LIMIT + 1);
    if (recentClaims.length >= GLOBAL_HOURLY_LIMIT) return "capacity" as const;
    if (scan.status !== "initialized") {
      while (true) {
        const logs = await ctx.db.query("scanLogs").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).take(250);
        await Promise.all(logs.map((document) => ctx.db.delete(document._id)));
        if (logs.length < 250) break;
      }
      while (true) {
        const findings = await ctx.db.query("findings").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).take(100);
        await Promise.all(findings.map((document) => ctx.db.delete(document._id)));
        if (findings.length < 100) break;
      }
    }
    await ctx.db.patch(args.scanId, { status: "scanning_secrets", claimedAt: now, logCount: 0, findingCount: 0, completedAt: undefined, errorMessage: undefined });
    return "claimed" as const;
  },
});

export const renewScanLease = internalMutation({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan || ["completed", "failed"].includes(scan.status)) return false;
    await ctx.db.patch(args.scanId, { claimedAt: Date.now() });
    return true;
  },
});

const legalTransitions: Record<string, readonly string[]> = {
  initialized: [],
  scanning_secrets: ["auditing_dependencies"],
  auditing_dependencies: ["writing_remediations", "verifying"],
  writing_remediations: ["verifying", "auditing_dependencies"],
  verifying: ["auditing_dependencies", "completed"],
};

export const updateScanStatus = internalMutation({
  args: { scanId: v.id("scans"), status: scanStatus, errorMessage: v.optional(v.string()) },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan) throw new Error("Scan not found.");
    if (scan.status === args.status) return;
    if (["completed", "failed"].includes(scan.status)) throw new Error("Terminal scan status cannot be changed.");
    if (args.status !== "failed" && !legalTransitions[scan.status]?.includes(args.status)) {
      throw new Error(`Illegal scan transition: ${scan.status} -> ${args.status}.`);
    }
    if (args.status === "completed" || args.status === "failed") {
      await ctx.db.patch(args.scanId, {
        status: args.status,
        claimedAt: undefined,
        completedAt: Date.now(),
        ...(args.errorMessage ? { errorMessage: args.errorMessage.slice(0, 1000) } : {}),
      });
      return;
    }
    await ctx.db.patch(args.scanId, { status: args.status });
  },
});

export const appendScanLog = internalMutation({
  args: { scanId: v.id("scans"), agent, message: v.string(), level: logLevel },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan || (scan.logCount ?? 0) >= 250) return null;
    await ctx.db.patch(args.scanId, { logCount: (scan.logCount ?? 0) + 1 });
    return ctx.db.insert("scanLogs", { ...args, message: args.message.slice(0, 4000) });
  },
});

export const createFinding = internalMutation({
  args: {
    scanId: v.id("scans"),
    filePath: v.string(),
    type: v.union(v.literal("leaked_secret"), v.literal("vulnerable_dependency"), v.literal("security_misconfig")),
    severity: v.union(v.literal("CRITICAL"), v.literal("HIGH"), v.literal("MEDIUM"), v.literal("LOW")),
    description: v.string(),
    evidence: v.string(),
    cveId: v.optional(v.string()),
    citations: v.optional(v.array(v.object({ title: v.string(), url: v.string() }))),
    remediationPatch: v.optional(v.string()),
    status: v.literal("open"),
  },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan || (scan.findingCount ?? 0) >= 100) return null;
    await ctx.db.patch(args.scanId, { findingCount: (scan.findingCount ?? 0) + 1 });
    return ctx.db.insert("findings", {
      ...args,
      description: args.description.slice(0, 4000),
      evidence: args.evidence.slice(0, 8000),
      citations: args.citations?.slice(0, 12),
      remediationPatch: args.remediationPatch?.slice(0, 20_000),
    });
  },
});

export const attachPatchToFinding = internalMutation({
  args: { findingId: v.id("findings"), remediationPatch: v.string() },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.findingId, { remediationPatch: args.remediationPatch.slice(0, 20_000) });
  },
});

export const acceptRisk = mutation({
  args: { findingId: v.id("findings"), reason: v.string(), sessionToken: v.string() },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const finding = await ctx.db.get(args.findingId);
    if (!finding) throw new Error("Finding not found.");
    const scan = await ctx.db.get(finding.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) throw new Error("Finding not found.");
    if (scan.status !== "completed") throw new Error("Risk can be accepted only after the scan completes.");
    const reason = args.reason.trim();
    if (reason.length < 10 || reason.length > 1000) throw new Error("Provide a risk acceptance reason between 10 and 1000 characters.");
    const existing = await ctx.db
      .query("risk_register")
      .withIndex("by_finding", (q) => q.eq("findingId", args.findingId))
      .unique();
    if (existing) {
      if (finding.status !== "accepted_risk") await ctx.db.patch(args.findingId, { status: "accepted_risk" });
      return existing._id;
    }
    if (finding.status !== "open") throw new Error("Only open findings can be accepted as risk.");
    await ctx.db.patch(args.findingId, { status: "accepted_risk" });
    return ctx.db.insert("risk_register", {
      findingId: args.findingId,
      ownerTokenIdentifier,
      repoUrl: scan.repoUrl,
      findingHash: `${finding.scanId}:${finding._id}`,
      acceptedBy: "Anonymous visitor",
      acceptedAt: Date.now(),
      reason,
    });
  },
});
