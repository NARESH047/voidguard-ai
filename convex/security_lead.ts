import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import { createOpenAIClient, lookupDependencyVulnerabilities, type GroundedVulnerability } from "./grounding";
import { loadRepositoryFiles } from "./github";
import { detectSecrets, extractDependencies, validateRemediationPatch } from "./lib/security";

const agents = {
  lead: "SecurityLead" as const,
  secrets: "SecretsScanner" as const,
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

async function generateRemediation(grounding: GroundedVulnerability) {
  const client = createOpenAIClient();
  const model = process.env.VOIDGUARD_REMEDIATION_MODEL ?? "gpt-5.2";
  const response = await client.responses.create({
    model,
    input: [
      "You are the RemediationWriter for a security audit.",
      `Package: ${grounding.packageName}@${grounding.version}`,
      `Advisory: ${grounding.summary}`,
      `Fixed versions from authoritative sources: ${grounding.fixedVersions.join(", ") || "none confirmed"}`,
      "Generate a minimal package.json unified diff only when a fixed version is explicitly supported by the evidence.",
      "Never invent a version. If no fixed version is confirmed, return an empty remediationPatch and explain why.",
    ].join("\n"),
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

async function verifyRemediation(grounding: GroundedVulnerability, remediation: Remediation) {
  if (!remediation.remediationPatch) return { approved: false, verdict: remediation.reason };
  const client = createOpenAIClient();
  const model = process.env.VOIDGUARD_QA_MODEL ?? process.env.VOIDGUARD_REMEDIATION_MODEL ?? "gpt-5.2";
  const response = await client.responses.create({
    model,
    input: [
      "You are the independent QA Verifier. Reject unsafe or unsupported dependency patches.",
      `Package: ${grounding.packageName}@${grounding.version}`,
      `Confirmed fixed versions: ${grounding.fixedVersions.join(", ")}`,
      `Proposed patch:\n${remediation.remediationPatch}`,
      "Approve only when the patch changes the exact package, uses a confirmed fixed version, and is a syntactically plausible unified diff.",
    ].join("\n"),
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
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity?.tokenIdentifier) throw new Error("Authentication required.");
    const scan = await ctx.runQuery(internal.mutations.requireOwnedScan, {
      scanId: args.scanId,
      ownerTokenIdentifier: identity.tokenIdentifier,
    });
    if (!scan) throw new Error("Scan not found.");

    const log = (agent: Agent, message: string, level: LogLevel = "info") =>
      ctx.runMutation(internal.mutations.appendScanLog, { scanId: args.scanId, agent, message, level });

    const claimed = await ctx.runMutation(internal.mutations.claimScanRun, { scanId: args.scanId });
    if (!claimed) throw new Error("Scan has already been started or completed.");

    let findingCount = 0;
    let groundingFailures = 0;
    try {
      await log(agents.lead, `Opening bounded read-only audit for ${scan.repoUrl}.`);
      const repository = await loadRepositoryFiles(scan.repoUrl);
      await log(agents.lead, `Loaded ${repository.files.length} eligible files from ${repository.owner}/${repository.repo}@${repository.branch}.`);

      for (const file of repository.files) {
        const matches = detectSecrets(file.content);
        for (const match of matches) {
          await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: file.path,
            type: "leaked_secret",
            severity: match.severity,
            description: match.description,
            evidence: match.evidence,
            status: "open",
          });
          findingCount += 1;
          await log(agents.secrets, `Redacted credential-like material detected in ${file.path}.`, "error");
        }
      }
      await log(
        agents.secrets,
        findingCount > 0 ? `Bounded secrets pass produced ${findingCount} redacted finding(s).` : "Bounded secrets pass completed without credential findings.",
        findingCount > 0 ? "warning" : "success",
      );

      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "auditing_dependencies" });
      const packageFile = repository.files.find((file) => file.path === "package.json");
      if (!packageFile) {
        await log(agents.dependencies, "No package.json found; dependency grounding was skipped.", "warning");
      } else {
        const packageLock = repository.files.find((file) => file.path === "package-lock.json")?.content;
        const dependencies = extractDependencies(packageFile.content, 12, packageLock);
        await log(agents.dependencies, `Grounding ${dependencies.length} prioritized dependencies with OpenAI web search.`);
        for (const dependency of dependencies) {
          let grounding: GroundedVulnerability;
          try {
            grounding = await lookupDependencyVulnerabilities(dependency.name, dependency.version);
          } catch (error) {
            groundingFailures += 1;
            await log(
              agents.dependencies,
              `${dependency.name}@${dependency.version}: grounding failed safely (${error instanceof Error ? error.message : "unknown error"}).`,
              "warning",
            );
            continue;
          }
          if (!grounding.affected) {
            await log(agents.dependencies, `${dependency.name}@${dependency.version}: no authoritative affected-version evidence found.`, "success");
            continue;
          }

          const findingId = await ctx.runMutation(internal.mutations.createFinding, {
            scanId: args.scanId,
            filePath: packageFile.path,
            type: "vulnerable_dependency",
            severity: grounding.severity === "NONE" ? "MEDIUM" : grounding.severity,
            description: grounding.summary,
            evidence: grounding.cveIds.join(", ") || "Authoritative advisory without CVE identifier",
            cveId: grounding.cveIds[0],
            citations: grounding.citations,
            status: "open",
          });
          findingCount += 1;
          await log(agents.dependencies, `${dependency.name}@${dependency.version}: affected version confirmed by authoritative sources.`, "warning");

          await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "writing_remediations" });
          try {
            const remediation = await generateRemediation(grounding);
            await log(agents.remediation, `${dependency.name}: remediation proposal generated at ${Math.round(remediation.confidence * 100)}% confidence.`);
            await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "verifying" });
            const qa = await verifyRemediation(grounding, remediation);
            if (qa.approved && validateRemediationPatch(remediation.remediationPatch, dependency.name, grounding.fixedVersions)) {
              await ctx.runMutation(internal.mutations.attachPatchToFinding, {
                findingId,
                remediationPatch: remediation.remediationPatch,
              });
              await log(agents.qa, `${dependency.name}: patch approved. ${qa.verdict}`, "success");
            } else {
              await log(agents.qa, `${dependency.name}: patch withheld by model or deterministic package/version validation. ${qa.verdict}`, "warning");
            }
          } catch (error) {
            await log(agents.qa, `${dependency.name}: remediation failed safely (${error instanceof Error ? error.message : "unknown error"}).`, "warning");
          }
          await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "auditing_dependencies" });
        }
      }

      if (groundingFailures > 0) {
        throw new Error(`Audit incomplete: ${groundingFailures} dependency grounding request(s) failed safely.`);
      }
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "verifying" });
      await log(agents.qa, "Workflow checks completed; all findings and patches remain subject to human review.", "success");
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "completed" });
      await log(agents.lead, `Audit completed with ${findingCount} finding(s). Human review is required before applying patches.`, "success");
      return { findingCount };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Audit failed unexpectedly.";
      await ctx.runMutation(internal.mutations.updateScanStatus, { scanId: args.scanId, status: "failed", errorMessage: message });
      await log(agents.lead, message, "error");
      throw error;
    }
  },
});
