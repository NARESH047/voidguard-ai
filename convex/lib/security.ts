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

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function lockfileVersions(packageLock: string | undefined) {
  const versions = new Map<string, string>();
  if (!packageLock) return versions;
  try {
    const parsed = JSON.parse(packageLock) as { packages?: Record<string, { version?: unknown }>; dependencies?: Record<string, { version?: unknown }> };
    for (const [path, entry] of Object.entries(parsed.packages ?? {})) {
      if (!path.startsWith("node_modules/") || typeof entry.version !== "string") continue;
      const name = path.slice("node_modules/".length);
      if (PACKAGE_NAME.test(name) && EXACT_VERSION.test(entry.version)) versions.set(name, entry.version);
    }
    for (const [name, entry] of Object.entries(parsed.dependencies ?? {})) {
      if (PACKAGE_NAME.test(name) && typeof entry.version === "string" && EXACT_VERSION.test(entry.version) && !versions.has(name)) {
        versions.set(name, entry.version);
      }
    }
  } catch {
    throw new Error("Repository lockfile is not a valid package-lock.json file.");
  }
  return versions;
}

export function extractDependencies(packageJson: string, limit: number, packageLock?: string) {
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
  const installed = lockfileVersions(packageLock);
  const production = toEntries(manifest.dependencies);
  const productionNames = new Set(production.map(([name]) => name));
  const development = toEntries(manifest.devDependencies).filter(([name]) => !productionNames.has(name));
  return [...production, ...development]
    .filter(([name, declared]) =>
      PACKAGE_NAME.test(name)
      && detectSecrets(`${name}:${declared}:${installed.get(name) ?? ""}`).length === 0
      && (installed.has(name) || EXACT_VERSION.test(declared)),
    )
    .slice(0, Math.max(0, limit))
    .map(([name, declared]) => ({ name, version: installed.get(name) ?? declared }));
}

export function validateRemediationPatch(patch: string, packageName: string, fixedVersions: string[]) {
  if (!patch || patch.length > 20_000 || !PACKAGE_NAME.test(packageName)) return false;
  const lines = patch.split("\n");
  const oldFiles = lines.filter((line) => line.startsWith("--- "));
  const newFiles = lines.filter((line) => line.startsWith("+++ "));
  if (oldFiles.length !== 1 || newFiles.length !== 1 || oldFiles[0] !== "--- a/package.json" || newFiles[0] !== "+++ b/package.json") return false;
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const removed = lines.some((line) => new RegExp(`^-\\s*"${escapedName}"\\s*:`).test(line));
  const addedVersions = lines
    .map((line) => line.match(new RegExp(`^\\+\\s*"${escapedName}"\\s*:\\s*"([^"]+)"`))?.[1])
    .filter((value): value is string => Boolean(value));
  return removed && addedVersions.length === 1 && fixedVersions.includes(addedVersions[0]);
}
