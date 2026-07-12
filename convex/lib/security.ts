export type SecretKind = "api_key" | "github_token" | "aws_access_key" | "private_key" | "credential_assignment";

export type SecretMatch = {
  kind: SecretKind;
  severity: "CRITICAL" | "HIGH";
  evidence: string;
  description: string;
};

const PLACEHOLDER_MARKERS = ["your-", "example", "placeholder", "changeme", "xxxx", "testfixture"];

const SECRET_PATTERNS: Array<{ kind: SecretKind; severity: "CRITICAL" | "HIGH"; pattern: RegExp }> = [
  { kind: "api_key", severity: "CRITICAL", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "github_token", severity: "CRITICAL", pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g },
  { kind: "aws_access_key", severity: "CRITICAL", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "private_key", severity: "CRITICAL", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  {
    kind: "credential_assignment",
    severity: "HIGH",
    pattern: /["']?\b(?:api[_-]?key|password|passwd|secret|token)\b["']?\s*[:=]\s*["']?([^\s"']{12,})["']?/gi,
  },
];

export function parseGitHubRepoUrl(input: string) {
  try {
    const url = new URL(input.trim());
    const parts = url.pathname.split("/").filter(Boolean);
    if (
      url.protocol !== "https:" ||
      !["github.com", "www.github.com"].includes(url.hostname.toLowerCase()) ||
      parts.length !== 2
    ) {
      throw new Error("invalid");
    }
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/, "");
    if (!owner || !repo || !/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
      throw new Error("invalid");
    }
    return { owner, repo, canonicalUrl: `https://github.com/${owner}/${repo}` };
  } catch {
    throw new Error("Enter a valid HTTPS GitHub repository URL.");
  }
}

function isPlaceholder(value: string) {
  const lower = value.toLowerCase();
  return PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker));
}

export function detectSecrets(content: string): SecretMatch[] {
  const findings: SecretMatch[] = [];
  const seen = new Set<string>();
  for (const definition of SECRET_PATTERNS) {
    definition.pattern.lastIndex = 0;
    for (const match of content.matchAll(definition.pattern)) {
      const raw = match[0];
      if (isPlaceholder(raw)) continue;
      const key = `${definition.kind}:${match.index ?? 0}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const label = definition.kind.replaceAll("_", " ");
      findings.push({
        kind: definition.kind,
        severity: definition.severity,
        evidence: `[REDACTED] ${definition.kind} at character ${match.index ?? 0}`,
        description: `Potential ${label} detected. Raw credential material was not persisted.`,
      });
    }
  }
  return findings;
}

export function extractDependencies(packageJson: string, limit: number) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(packageJson);
  } catch {
    throw new Error("Repository manifest is not a valid package.json file.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Repository manifest is not a valid package.json file.");
  }
  const manifest = parsed as { dependencies?: unknown; devDependencies?: unknown };
  const toEntries = (group: unknown) => {
    if (!group || typeof group !== "object" || Array.isArray(group)) return [];
    return Object.entries(group)
      .filter((entry): entry is [string, string] => typeof entry[1] === "string")
      .sort(([a], [b]) => a.localeCompare(b));
  };
  const production = toEntries(manifest.dependencies);
  const productionNames = new Set(production.map(([name]) => name));
  const development = toEntries(manifest.devDependencies).filter(([name]) => !productionNames.has(name));
  return [...production, ...development]
    .slice(0, Math.max(0, limit))
    .map(([name, version]) => ({ name, version: version.replace(/^[~^<>=\s]+/, "") }));
}
