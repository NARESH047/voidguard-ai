import { internalMutation, mutation, query } from "./_generated/server";
import { v } from "convex/values";

const repoUrlValidator = v.string();

function requireIdentity(identity: { tokenIdentifier?: string } | null) {
  if (!identity?.tokenIdentifier) throw new Error("Authentication required.");
  return identity.tokenIdentifier;
}

function validateRepoUrl(repoUrl: string) {
  try {
    const url = new URL(repoUrl);
    const parts = url.pathname.split("/").filter(Boolean);
    if (url.protocol !== "https:" || !["github.com", "www.github.com"].includes(url.hostname.toLowerCase()) || parts.length < 2) {
      throw new Error("Use a valid HTTPS GitHub repository URL.");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Use a")) throw error;
    throw new Error("Use a valid HTTPS GitHub repository URL.");
  }
}

export const createScan = mutation({
  args: { repoUrl: repoUrlValidator },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = requireIdentity(await ctx.auth.getUserIdentity());
    const repoUrl = args.repoUrl.trim();
    validateRepoUrl(repoUrl);
    return ctx.db.insert("scans", {
      ownerTokenIdentifier,
      repoUrl,
      status: "initialized",
      startedAt: Date.now(),
    });
  },
});

export const getScan = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = requireIdentity(await ctx.auth.getUserIdentity());
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) return null;
    return scan;
  },
});

export const getScanLogs = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = requireIdentity(await ctx.auth.getUserIdentity());
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) return [];
    return ctx.db.query("scanLogs").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).order("asc").take(250);
  },
});

export const getFindings = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const ownerTokenIdentifier = requireIdentity(await ctx.auth.getUserIdentity());
    const scan = await ctx.db.get(args.scanId);
    if (!scan || scan.ownerTokenIdentifier !== ownerTokenIdentifier) return [];
    return ctx.db.query("findings").withIndex("by_scan", (q) => q.eq("scanId", args.scanId)).take(100);
  },
});

export const updateStatus = internalMutation({
  args: {
    scanId: v.id("scans"),
    status: v.union(
      v.literal("initialized"),
      v.literal("scanning_secrets"),
      v.literal("auditing_dependencies"),
      v.literal("writing_remediations"),
      v.literal("verifying"),
      v.literal("completed"),
      v.literal("failed"),
    ),
    errorMessage: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.scanId, {
      status: args.status,
      completedAt: ["completed", "failed"].includes(args.status) ? Date.now() : undefined,
      errorMessage: args.errorMessage,
    });
  },
});

export const appendLog = internalMutation({
  args: {
    scanId: v.id("scans"),
    agent: v.union(
      v.literal("SecurityLead"),
      v.literal("SecretsScanner"),
      v.literal("DependencyAuditor"),
      v.literal("RemediationWriter"),
      v.literal("QA_Verifier"),
    ),
    message: v.string(),
    level: v.union(v.literal("info"), v.literal("warning"), v.literal("error"), v.literal("success")),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("scanLogs", args);
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
    remediationPatch: v.optional(v.string()),
    status: v.union(v.literal("open"), v.literal("remediated"), v.literal("accepted_risk")),
  },
  handler: async (ctx, args) => ctx.db.insert("findings", args),
});

export const attachPatch = internalMutation({
  args: { findingId: v.id("findings"), remediationPatch: v.string() },
  handler: async (ctx, args) => ctx.db.patch(args.findingId, { remediationPatch: args.remediationPatch, status: "remediated" }),
});
