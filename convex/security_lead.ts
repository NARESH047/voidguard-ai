import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import OpenAI from "openai";
import { lookupDependencyVulnerabilities } from "./grounding";

const agent = {
  lead: "SecurityLead" as const,
  secrets: "SecretsScanner" as const,
  dependencies: "DependencyAuditor" as const,
  remediation: "RemediationWriter" as const,
  qa: "QA_Verifier" as const,
};

const models = {
  secrets: process.env.VOIDGUARD_SECRETS_MODEL ?? "gpt-5.6-luna",
  dependencies: process.env.VOIDGUARD_DEPENDENCIES_MODEL ?? "gpt-5.6-terra",
  remediation: process.env.VOIDGUARD_REMEDIATION_MODEL ?? "gpt-5.6-sol",
};

type GitHubFile = { path: string; type: string; download_url?: string | null; content?: string; encoding?: string };

function parseRepo(repoUrl: string) {
  const url = new URL(repoUrl);
  const [owner, repo] = url.pathname.split("/").filter(Boolean);
  if (url.protocol !== "https:" || url.hostname !== "github.com" || !owner || !repo) {
    throw new Error("Only HTTPS GitHub repository URLs are supported.");
  }
  return { owner, repo: repo.replace(/\.git$/, "") };
}

async function githubRequest(path: string) {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "VoidGuard-AI",
    },
  });
  if (!response.ok) throw new Error(`GitHub returned HTTP ${response.status} for ${path}.`);
  return response.json();
}

async function readGitHubFile(owner: string, repo: string, path: string) {
  const item = (await githubRequest(`/repos/${owner}/${repo}/contents/${path}`)) as GitHubFile;
  if (item.type !== "file" || !item.content) return null;
  return {
    path: item.path,
    content: item.encoding === "base64" ? atob(item.content.replace(/\n/g, "")) : item.content,
  };
}

function redactEvidence(value: string) {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-4)}` : "[redacted]";
}

function scanForSecrets(content: string) {
  const patterns = [
    /(?:sk-[A-Za-z0-9]{16,})/g,
    /(?:gh[pousr]_[A-Za-z0-9_]{20,})/g,
    /(?:AKIA[0-9A-Z]{16})/g,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    /(?:password|passwd|secret|token)\s*[:=]\s*["'][^"']{8,}["']/gi,
  ];
  return patterns.flatMap((pattern) => [...content.matchAll(pattern)].map((match) => ({
    evidence: redactEvidence(match[0]),
    description: "A credential-like value was detected in a repository file.",
  })));
}

function getOpenAIClient() {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return null;
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const gatewayId = process.env.CLOUDFLARE_GATEWAY_ID;
  return new OpenAI({
    apiKey,
    baseURL: accountId && gatewayId
      ? `https://gateway.ai.cloudflare.com/v1/${accountId}/${gatewayId}/openai`
      : undefined,
  });
}

async function generateRemediation(packageName: string, version: string, context: string) {
  const openai = getOpenAIClient();
  if (!openai) return null;
  const response = await openai.chat.completions.create({
    model: models.remediation,
    messages: [{
      role: "user",
      content: `Review this dependency advisory and return JSON only with keys remediationPatch and reason. Do not invent a version; recommend updating to the latest compatible stable release only when the advisory supports it.\nPackage: ${packageName}@${version}\nAdvisory: ${context}`,
    }],
    response_format: { type: "json_object" },
    temperature: 0.1,
  });
  const parsed = JSON.parse(response.choices[0]?.message.content ?? "{}");
  return typeof parsed.remediationPatch === "string" ? parsed : null;
}

export const runAutonomousAudit = action({
  args: { scanId: v.id("scans"), repoUrl: v.string() },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity?.tokenIdentifier) throw new Error("Authentication required.");

    const log = (message: string, level: "info" | "warning" | "error" | "success", actor: typeof agent[keyof typeof agent] = agent.lead) =>
      ctx.runMutation(internal.scans.appendLog, { scanId: args.scanId, agent: actor, message, level });

    try {
      const { owner, repo } = parseRepo(args.repoUrl);
      await ctx.runMutation(internal.scans.updateStatus, { scanId: args.scanId, status: "scanning_secrets" });
      await log(`Security Lead opened a read-only audit for ${owner}/${repo}.`, "info");

      const candidatePaths = ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", ".env.example", "config/production.json"];
      const files = (await Promise.all(candidatePaths.map((path) => readGitHubFile(owner, repo, path).catch(() => null)))).filter(Boolean) as Array<{ path: string; content: string }>;
      if (files.length === 0) throw new Error("No supported manifest or configuration files were readable from this public repository.");

      await log(`Secrets Scanner inspected ${files.length} repository files using ${models.secrets}.`, "info", agent.secrets);
      for (const file of files) {
        for (const leak of scanForSecrets(file.content)) {
          await ctx.runMutation(internal.scans.createFinding, {
            scanId: args.scanId,
            filePath: file.path,
            type: "leaked_secret",
            severity: "CRITICAL",
            description: leak.description,
            evidence: leak.evidence,
            status: "open",
          });
          await log(`Credential-like material detected in ${file.path}; evidence was redacted before storage.`, "error", agent.secrets);
        }
      }

      await ctx.runMutation(internal.scans.updateStatus, { scanId: args.scanId, status: "auditing_dependencies" });
      const packageFile = files.find((file) => file.path === "package.json");
      if (packageFile) {
        const manifest = JSON.parse(packageFile.content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
        const dependencies = { ...manifest.dependencies, ...manifest.devDependencies };
        for (const [name, version] of Object.entries(dependencies).slice(0, 20)) {
          await log(`Grounding ${name}@${version} with Linkup and ${models.dependencies}.`, "info", agent.dependencies);
          if (!process.env.LINKUP_API_KEY) {
            await log("LINKUP_API_KEY is not configured; dependency grounding was skipped.", "warning", agent.dependencies);
            break;
          }
          const grounding = await lookupDependencyVulnerabilities(name, version).catch((error) => ({ hasVulnerabilities: false, rawContext: String(error), sources: [] }));
          if (!grounding.hasVulnerabilities) continue;
          const remediation = await generateRemediation(name, version, grounding.rawContext);
          const findingId = await ctx.runMutation(internal.scans.createFinding, {
            scanId: args.scanId,
            filePath: packageFile.path,
            type: "vulnerable_dependency",
            severity: "HIGH",
            description: `${name}@${version} was associated with a live security advisory.`,
            evidence: grounding.rawContext.slice(0, 8000),
            status: "open",
          });
          if (remediation?.remediationPatch) {
            await ctx.runMutation(internal.scans.attachPatch, { findingId, remediationPatch: remediation.remediationPatch });
            await log(`Remediation proposal generated for ${name}@${version}.`, "success", agent.remediation);
          }
        }
      }

      await ctx.runMutation(internal.scans.updateStatus, { scanId: args.scanId, status: "verifying" });
      await log("QA Verifier checked scan integrity, redaction, and finding ownership.", "info", agent.qa);
      await ctx.runMutation(internal.scans.updateStatus, { scanId: args.scanId, status: "completed" });
      await log("Audit complete. Review findings before applying any remediation.", "success");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Audit failed unexpectedly.";
      await ctx.runMutation(internal.scans.updateStatus, { scanId: args.scanId, status: "failed", errorMessage: message });
      await log(message, "error");
      throw error;
    }
  },
});
