import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const scanStatus = v.union(
  v.literal("initialized"),
  v.literal("scanning_secrets"),
  v.literal("auditing_dependencies"),
  v.literal("writing_remediations"),
  v.literal("verifying"),
  v.literal("completed"),
  v.literal("failed"),
);

const logLevel = v.union(
  v.literal("info"),
  v.literal("warning"),
  v.literal("error"),
  v.literal("success"),
);

export default defineSchema({
  waitlist: defineTable({
    email: v.string(),
    repositoryUrl: v.string(),
    source: v.literal("landing_page"),
    status: v.union(v.literal("queued"), v.literal("contacted")),
  }).index("by_email", ["email"]),
  scans: defineTable({
    ownerTokenIdentifier: v.string(),
    repoUrl: v.string(),
    status: scanStatus,
    claimedAt: v.optional(v.number()),
    auditAsOf: v.optional(v.string()),
    commitSha: v.optional(v.string()),
    branch: v.optional(v.string()),
    eligibleFileCount: v.optional(v.number()),
    inspectedFileCount: v.optional(v.number()),
    omittedFileCount: v.optional(v.number()),
    logCount: v.optional(v.number()),
    findingCount: v.optional(v.number()),
    startedAt: v.number(),
    completedAt: v.optional(v.number()),
    errorMessage: v.optional(v.string()),
  })
    .index("by_owner", ["ownerTokenIdentifier"])
    .index("by_owner_and_startedAt", ["ownerTokenIdentifier", "startedAt"])
    .index("by_owner_and_status", ["ownerTokenIdentifier", "status"])
    .index("by_startedAt", ["startedAt"])
    .index("by_claimedAt", ["claimedAt"]),
  scanLogs: defineTable({
    scanId: v.id("scans"),
    agent: v.union(
      v.literal("SecurityLead"),
      v.literal("SecretsScanner"),
      v.literal("StaticAnalyzer"),
      v.literal("DependencyAuditor"),
      v.literal("RemediationWriter"),
      v.literal("QA_Verifier"),
    ),
    message: v.string(),
    level: logLevel,
  }).index("by_scan", ["scanId"]),
  findings: defineTable({
    scanId: v.id("scans"),
    filePath: v.string(),
    type: v.union(
      v.literal("leaked_secret"),
      v.literal("vulnerable_dependency"),
      v.literal("security_misconfig"),
    ),
    claimType: v.optional(v.union(v.literal("confirmed_issue"), v.literal("review_required"), v.literal("unknown"))),
    severity: v.union(v.literal("CRITICAL"), v.literal("HIGH"), v.literal("MEDIUM"), v.literal("LOW")),
    description: v.string(),
    evidence: v.string(),
    cveId: v.optional(v.string()),
    citations: v.optional(v.array(v.object({ title: v.string(), url: v.string() }))),
    remediationPatch: v.optional(v.string()),
    status: v.union(v.literal("open"), v.literal("remediated"), v.literal("accepted_risk")),
  }).index("by_scan", ["scanId"]),
  risk_register: defineTable({
    findingId: v.optional(v.id("findings")),
    ownerTokenIdentifier: v.string(),
    repoUrl: v.string(),
    findingHash: v.string(),
    acceptedBy: v.string(),
    acceptedAt: v.number(),
    reason: v.string(),
  })
    .index("by_owner_and_repo", ["ownerTokenIdentifier", "repoUrl"])
    .index("by_finding", ["findingId"]),
});
