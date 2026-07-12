import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import { createOpenAIClient, lookupDependencyVulnerabilities, type GroundedVulnerability } from "./grounding";
import { loadRepositoryFiles } from "./github";
import { buildQaInstructions, buildRemediationInstructions } from "./lib/instructions";
import { detectDependencyIntegrityIssues, detectSecrets, detectStaticSecurityIssues, extractDependencies, validateRemediationPatch } from "./lib/security";
import { anonymousOwnerKey, verifyAuditProof } from "./lib/session";

const agents = {
  lead: "SecurityLead" as const,
  secrets: "SecretsScanner" as const,
  static: "StaticAnalyzer" as const,
  dependencies: "DependencyAuditor" as const,
  remediation: "RemediationWriter" as const,
  qa: "QA_Verifier" as const,
};

type LogLevel = "info" | "warning" | "error" | "success";
type Agent = (typeof agents)[keyof typeof agents];
type Remediation = { remediationPatch: string; reason: string; confidence: number };

function parseJsonObject(raw: string, label: string) {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`${label} returned invalid structured output.`);
  }
}

async function generateRemediation(grounding: GroundedVulnerability, auditAsOf: string) {
  const client = createOpenAIClient();
  const model = process.env.VOIDGUARD_REMEDIATION_MODEL ?? "gpt-5.2";
  const response = await client.responses.create({
    model,
    input: buildRemediationInstructions(grounding, auditAsOf),
    text: {
      format: {
        type: "json_schema",
        name: "remediation",
        strict: true,
        schema: {
          type: "object",
          additionalProperties: false,
          required: ["remediationPatch", "reason", "confidence"],
          properties: {
            remediationPatch: { type: "string" },
            reason: { type: "string" },
            confidence: { type: "number", minimum: 0, maximum: 1 },
          },
        },
      },
    },
  });
  const parsed = parseJsonObject(response.output_text, "RemediationWriter");
  if (typeof parsed.remediationPatch !== "string" || typeof parsed.reason !== "string" || typeof parsed.confidence !== "number") {
    throw new Error("RemediationWriter returned incomplete structured output.");
  }
  return parsed as Remediation;
}

async function verifyRemediation(grounding: GroundedVulnerability, remediation: Remediation, auditAsOf: string) {
  if (!remediation.remediationPatch) return { approved: false, verdict: remediation.reason };
  const client = createOpenAIClient();
  const model = process.env.VOIDGUARD_QA_MODEL ?? process.env.VOIDGUARD_REMEDIATION_MODEL ?? "gpt-5.2";
  const response = await client.responses.create({
    model,
    input: buildQaInstructions(grounding, remediation.remediationPatch, auditAsOf),
    text: {
      format: {
        type: "json_schema",
        name: "qa_verdict",
        strict: true,
        schema: {
          type: "object",
          additionalProperties: false,
          required: ["approved", "verdict"],
          properties: { approved: { type: "boolean" }, verdict: { type: "string" } },
        },
      },
    },
  });
  const parsed = parseJsonObject(response.output_text, "QA Verifier");
  if (typeof parsed.approved !== "boolean" || typeof parsed.verdict !== "string") {
    throw new Error("QA Verifier returned incomplete structured output.");
  }
  return { approved: parsed.approved, verdict: parsed.verdict };
}

export const runAutonomousAudit = action({
  args: { scanId: v.id("scans"), sessionToken: v.string(), proofNonce: v.string() },
  handler: async (ctx, args) => {
    if (!await verifyAuditProof(args.sessionToken, args.scanId, args.proofNonce)) throw new Error("Audit challenge failed.");
    const ownerTokenIdentifier = await anonymousOwnerKey(args.sessionToken);
    const scan = await ctx.runQuery(internal.mutations.requireOwnedScan, {
      scanId: args.scanId,
      ownerTokenIdentifier,
    });
    if (!scan) throw new Error("Scan not found.");

    const log = (agent: Agent, message: string, level: LogLevel = "info") =>
      ctx.runMutation(internal.mutations.appendScanLog, { scanId: args.scanId, agent, message, level });

    const claimResult = await ctx.runMutation(internal.mutations.claimScanRun, { scanId: args.scanId });
    if (claimResult === "capacity") throw new Error("VoidGuard is at hourly capacity. Try again later.");
    if (claimResult !== "claimed") throw new Error("Scan has already been started or completed.");

    const auditAsOf = new Date().toISOString();
    let findingCount = 0;
    let workflowFailures = 0;
    try {
      await log(agents.lead, `Opening bounded read-only audit for ${scan.repoUrl}.`);
      const repository = await loadRepositoryFiles(scan.repoUrl);
      await ctx.runMutation(internal.mutations.recordScanContext, {
        scanId: args.scanId,
        auditAsOf,
        commitSha: repository.commitSha,
        branch: repository.branch,
        eligibleFileCount: repository.eligibleFileCount,
        inspectedFileCount: repository.files.length,
        omittedFileCount: repository.omittedFileCount,
      });
      await ctx.runMutation(internal.mutations.renewScanLease, { scanId: args.scanId });
      await log(agents.lead, `Loaded ${repository.files.length} of ${repository.eligibleFileCount} eligible files from ${repository.owner}/${repository.repo}@${repository.branch} (${repository.commitSha.slice(0, 12)}); ${repository.omittedFileCount} omitted by bounds.`);

      for (const file of repository.files) {
        const matches = detectSecrets(file.content);
        for (const match of matches) {
          const storedSecret = await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: file.path,
            type: "leaked_secret",
            claimType: match.kind === "credential_assignment" ? "review_required" : "confirmed_issue",
            severity: match.severity,
            description: match.description,
            evidence: match.evidence,
            status: "open",
          });
          if (!storedSecret) break;
          findingCount += 1;
          await log(agents.secrets, `Redacted credential-like material detected in ${file.path}.`, "error");
        }
      }
      await log(
        agents.secrets,
        findingCount > 0 ? `Bounded secrets pass produced ${findingCount} redacted finding(s).` : "Bounded secrets pass completed without credential findings.",
        findingCount > 0 ? "warning" : "success",
      );

      let staticFindingCount = 0;
      for (const file of repository.files) {
        for (const issue of detectStaticSecurityIssues(file.path, file.content)) {
          if (staticFindingCount >= 40) break;
          const storedIssue = await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: file.path,
            type: "security_misconfig",
            claimType: "review_required",
            severity: issue.severity,
            description: issue.description,
            evidence: issue.evidence,
            status: "open",
          });
          if (!storedIssue) break;
          findingCount += 1;
          staticFindingCount += 1;
          await log(agents.static, `${issue.kind} detected in ${file.path}.`, "warning");
        }
      }
      await log(
        agents.static,
        staticFindingCount > 0 ? `Deterministic static analysis produced ${staticFindingCount} finding(s).` : "Deterministic static analysis completed without high-signal findings.",
        staticFindingCount > 0 ? "warning" : "success",
      );

      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "auditing_dependencies" });
      const packageFile = repository.files.find((file) => file.path === "package.json");
      if (!packageFile) {
        await log(agents.dependencies, "No package.json found; dependency grounding was skipped.", "warning");
      } else {
        const lockfiles = Object.fromEntries(
          repository.files
            .filter((file) => ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"].includes(file.path))
            .map((file) => [file.path, file.content]),
        );
        const integrityIssues = detectDependencyIntegrityIssues(packageFile.content, lockfiles);
        for (const issue of integrityIssues) {
          const storedIssue = await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: "package.json",
            type: "security_misconfig",
            claimType: "review_required",
            severity: issue.severity,
            description: issue.description,
            evidence: issue.evidence,
            status: "open",
          });
          if (!storedIssue) break;
          findingCount += 1;
          await log(agents.dependencies, `${issue.kind}: ${issue.description}`, "warning");
        }
        const packageLock = repository.files.find((file) => file.path === "package-lock.json")?.content;
        const dependencies = extractDependencies(packageFile.content, 12, packageLock);
        await log(agents.dependencies, `Grounding ${dependencies.length} prioritized dependencies with OpenAI web search.`);
        for (const dependency of dependencies) {
          let grounding: GroundedVulnerability;
          try {
            grounding = await lookupDependencyVulnerabilities(dependency.name, dependency.version, auditAsOf);
            await ctx.runMutation(internal.mutations.renewScanLease, { scanId: args.scanId });
          } catch (error) {
            workflowFailures += 1;
            await log(
              agents.dependencies,
              `${dependency.name}@${dependency.version}: grounding failed safely (${error instanceof Error ? error.message : "unknown error"}).`,
              "warning",
            );
            continue;
          }
          if (grounding.assessment === "UNKNOWN") {
            const storedUnknown = await ctx.runMutation(internal.mutations.createFinding, {
              scanId: args.scanId,
              filePath: packageFile.path,
              type: "security_misconfig",
              claimType: "unknown",
              severity: "MEDIUM",
              description: `Exact-version advisory status for ${dependency.name}@${dependency.version} remains unknown after a fresh authoritative-source search.`,
              evidence: grounding.summary,
              citations: grounding.citations,
              status: "open",
            });
            if (storedUnknown) findingCount += 1;
            await log(agents.dependencies, `${dependency.name}@${dependency.version}: exact-version status is unknown; manual review required.`, "warning");
            continue;
          }
          if (grounding.assessment === "UNAFFECTED") {
            await log(agents.dependencies, `${dependency.name}@${dependency.version}: current authoritative evidence explicitly excludes the exact version.`, "success");
            continue;
          }

          const findingId = await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: packageFile.path,
            type: "vulnerable_dependency",
            claimType: "review_required",
            severity: grounding.severity === "NONE" ? "MEDIUM" : grounding.severity,
            description: grounding.summary,
            evidence: grounding.cveIds.join(", ") || "Authoritative advisory without CVE identifier",
            cveId: grounding.cveIds[0],
            citations: grounding.citations,
            status: "open",
          });
          if (!findingId) {
            await log(agents.dependencies, "Finding output limit reached; remaining dependency findings were withheld.", "warning");
            break;
          }
          const storedFindingId = findingId;
          findingCount += 1;
          await log(agents.dependencies, `${dependency.name}@${dependency.version}: affected version confirmed by authoritative sources.`, "warning");

          await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "writing_remediations" });
          try {
            const remediation = await generateRemediation(grounding, auditAsOf);
            await log(agents.remediation, `${dependency.name}: remediation proposal generated at ${Math.round(remediation.confidence * 100)}% confidence.`);
            await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "verifying" });
            const qa = await verifyRemediation(grounding, remediation, auditAsOf);
            if (qa.approved && validateRemediationPatch(remediation.remediationPatch, dependency.name, dependency.version, grounding.fixedVersions)) {
              await ctx.runMutation(internal.mutations.attachPatchToFinding, {
                findingId: storedFindingId,
                remediationPatch: remediation.remediationPatch,
              });
              await log(agents.qa, `${dependency.name}: patch approved. ${qa.verdict}`, "success");
            } else {
              await log(agents.qa, `${dependency.name}: patch withheld by model or deterministic package/version validation. ${qa.verdict}`, "warning");
            }
          } catch (error) {
            workflowFailures += 1;
            await log(agents.qa, `${dependency.name}: remediation failed safely (${error instanceof Error ? error.message : "unknown error"}).`, "warning");
          }
          await ctx.runMutation(internal.mutations.renewScanLease, { scanId: args.scanId });
          await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "auditing_dependencies" });
        }
      }

      if (workflowFailures > 0) {
        throw new Error(`Audit incomplete: ${workflowFailures} required provider workflow(s) failed safely.`);
      }
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "verifying" });
      await log(agents.qa, "Workflow checks completed; all findings and patches remain subject to human review.", "success");
      await log(agents.lead, `Audit completed with ${findingCount} finding(s). Human review is required before applying patches.`, "success");
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "completed" });
      return { findingCount };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Audit failed unexpectedly.";
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "failed", errorMessage: message });
      await log(agents.lead, message, "error");
      throw error;
    }
  },
});
