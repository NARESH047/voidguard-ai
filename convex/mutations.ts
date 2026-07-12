import { internalMutation, internalQuery, mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { parseGitHubRepoUrl } from "./lib/security";

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

async function requireIdentity(ctx: { auth: { getUserIdentity: () => Promise<{ tokenIdentifier: string; email?: string } | null> } }) {
  const identity = await ctx.auth.getUserIdentity();
  if (!identity?.tokenIdentifier) throw new Error("Authentication required.");
  return identity;
}

export const createScan = mutation({
  args: { repoUrl: v.string() },
  handler: async (ctx, args) => {
    const identity = await requireIdentity(ctx);
    const repository = parseGitHubRepoUrl(args.repoUrl);
    const recentScans = await ctx.db
      .query("scans")
      .withIndex("by_owner_and_startedAt", (q) =>
        q.eq("ownerTokenIdentifier", identity.tokenIdentifier).gte("startedAt", Date.now() - 60 * 60 * 1000),
      )
      .order("desc")
      .take(6);
    const activeScan = recentScans.find((scan) => !["completed", "failed"].includes(scan.status));
    if (activeScan) {
      if (activeScan.repoUrl === repository.canonicalUrl) return activeScan._id;
      throw new Error("Finish the active scan before starting another repository.");
    }
    if (recentScans.length >= 5) throw new Error("Hourly scan quota reached. Try again later.");
    return ctx.db.insert("scans", {
      ownerTokenIdentifier: identity.tokenIdentifier,
      repoUrl: repository.canonicalUrl,
      status: "initialized",
      startedAt: Date.now(),
    });
  },
});

export const getScan = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const identity = await requireIdentity(ctx);
    const scan = await ctx.db.get(args.scanId);
    return scan?.ownerTokenIdentifier === identity.tokenIdentifier ? scan : null;
  },
});

export const listRecentScans = query({
  args: {},
  handler: async (ctx) => {
    const identity = await requireIdentity(ctx);
    return ctx.db
      .query("scans")
      .withIndex("by_owner_and_startedAt", (q) => q.eq("ownerTokenIdentifier", identity.tokenIdentifier))
      .order("desc")
      .take(20);
  },
});

export const getScanLogs = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const identity = await requireIdentity(ctx);
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== identity.tokenIdentifier) return [];
    return ctx.db.query("scanLogs").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).order("asc").take(250);
  },
});

export const getScanFindings = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const identity = await requireIdentity(ctx);
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== identity.tokenIdentifier) return [];
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
    if (!scan || scan.status !== "initialized") return false;
    await ctx.db.patch(args.scanId, { status: "scanning_secrets" });
    return true;
  },
});

export const updateScanStatus = internalMutation({
  args: { scanId: v.id("scans"), status: scanStatus, errorMessage: v.optional(v.string()) },
  handler: async (ctx, args) => {
    if (args.status === "completed" || args.status === "failed") {
      await ctx.db.patch(args.scanId, {
        status: args.status,
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
    await ctx.db.insert("scanLogs", { ...args, message: args.message.slice(0, 4000) });
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
    status: v.union(v.literal("open"), v.literal("remediated"), v.literal("accepted_risk")),
  },
  handler: async (ctx, args) => ctx.db.insert("findings", {
    ...args,
    description: args.description.slice(0, 4000),
    evidence: args.evidence.slice(0, 8000),
    citations: args.citations?.slice(0, 12),
    remediationPatch: args.remediationPatch?.slice(0, 20_000),
  }),
});

export const attachPatchToFinding = internalMutation({
  args: { findingId: v.id("findings"), remediationPatch: v.string() },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.findingId, { remediationPatch: args.remediationPatch.slice(0, 20_000) });
  },
});

export const acceptRisk = mutation({
  args: { findingId: v.id("findings"), reason: v.string() },
  handler: async (ctx, args) => {
    const identity = await requireIdentity(ctx);
    const finding = await ctx.db.get(args.findingId);
    if (!finding) throw new Error("Finding not found.");
    const scan = await ctx.db.get(finding.scanId);
    if (!scan || scan.ownerTokenIdentifier !== identity.tokenIdentifier) throw new Error("Finding not found.");
    const reason = args.reason.trim();
    if (reason.length < 10 || reason.length > 1000) throw new Error("Provide a risk acceptance reason between 10 and 1000 characters.");
    const existing = await ctx.db
      .query("risk_register")
      .withIndex("by_finding", (q) => q.eq("findingId", args.findingId))
      .unique();
    if (existing) return existing._id;
    if (finding.status !== "open") throw new Error("Only open findings can be accepted as risk.");
    await ctx.db.patch(args.findingId, { status: "accepted_risk" });
    return ctx.db.insert("risk_register", {
      findingId: args.findingId,
      ownerTokenIdentifier: identity.tokenIdentifier,
      repoUrl: scan.repoUrl,
      findingHash: `${finding.scanId}:${finding._id}`,
      acceptedBy: identity.email ?? identity.tokenIdentifier,
      acceptedAt: Date.now(),
      reason,
    });
  },
});
