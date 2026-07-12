export type SecretKind = "api_key" | "github_token" | "aws_access_key" | "private_key" | "npm_token" | "slack_token" | "stripe_live_key" | "google_api_key" | "gitlab_token" | "credential_url" | "credential_assignment";

export type SecretMatch = {
  kind: SecretKind;
  severity: "CRITICAL" | "HIGH";
  evidence: string;
  description: string;
};

const PLACEHOLDER_MARKERS = ["your-", "example", "placeholder", "changeme", "xxxx", "testfixture"];

const SECRET_PATTERNS: Array<{ kind: SecretKind; severity: "CRITICAL" | "HIGH"; pattern: RegExp; suppressPlaceholders?: boolean }> = [
  { kind: "api_key", severity: "CRITICAL", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "github_token", severity: "CRITICAL", pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g },
  { kind: "aws_access_key", severity: "CRITICAL", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "private_key", severity: "CRITICAL", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { kind: "npm_token", severity: "CRITICAL", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: "slack_token", severity: "CRITICAL", pattern: /\bxox[baprs]-[A-Za-z0-9-]{30,}\b/g },
  { kind: "stripe_live_key", severity: "CRITICAL", pattern: /\bsk_live_[A-Za-z0-9]{20,}\b/g },
  { kind: "google_api_key", severity: "CRITICAL", pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g },
  { kind: "gitlab_token", severity: "CRITICAL", pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "credential_url", severity: "CRITICAL", pattern: /https?:\/\/[^/\s:@]+:[^/\s@]{8,}@[^\s/]+/gi },
  {
    kind: "credential_assignment",
    severity: "HIGH",
    pattern: /["']?\b(?:api[_-]?key|password|passwd|secret|token)\b["']?\s*[:=]\s*["']?([^\s"']{12,})["']?/gi,
    suppressPlaceholders: true,
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
      if (definition.suppressPlaceholders && isPlaceholder(raw)) continue;
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

export type StaticSecurityKind =
  | "dynamic_code_execution"
  | "command_execution"
  | "cross_site_scripting"
  | "tls_verification_disabled"
  | "weak_cryptography"
  | "client_side_authentication"
  | "permissive_cors"
  | "privileged_ci_workflow"
  | "overbroad_ci_permissions"
  | "build_validation_disabled";

export type StaticSecurityIssue = {
  kind: StaticSecurityKind;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
  evidence: string;
};

type StaticRule = Omit<StaticSecurityIssue, "evidence"> & { pattern: RegExp; requires?: RegExp };

const STATIC_RULES: StaticRule[] = [
  { kind: "dynamic_code_execution", severity: "CRITICAL", pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/g, description: "Dynamic code execution can run attacker-controlled JavaScript." },
  { kind: "command_execution", severity: "CRITICAL", pattern: /(?<![\w.])(?:exec(?:Sync)?|spawn(?:Sync)?|execFile(?:Sync)?)\s*\(/g, requires: /(?:node:)?child_process/, description: "Shell command execution requires strict argument separation and untrusted-input controls." },
  { kind: "cross_site_scripting", severity: "HIGH", pattern: /\bdangerouslySetInnerHTML\s*=/g, description: "Raw HTML rendering can introduce cross-site scripting when content is not strongly sanitized." },
  { kind: "tls_verification_disabled", severity: "HIGH", pattern: /\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b/g, description: "TLS certificate verification is explicitly disabled." },
  { kind: "weak_cryptography", severity: "MEDIUM", pattern: /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']/gi, description: "MD5 or SHA-1 is unsuitable for security-sensitive integrity or password operations." },
  { kind: "client_side_authentication", severity: "HIGH", pattern: /\blocalStorage\.(?:getItem|setItem)\s*\(\s*["'](?:isLoggedIn|auth(?:Token)?|token|session|userEmail)["']/gi, description: "Client-controlled localStorage is being used as an authentication or session authority." },
  { kind: "permissive_cors", severity: "HIGH", pattern: /Access-Control-Allow-Origin["']?\s*,\s*["']\*["']|Access-Control-Allow-Origin\s*[:=]\s*["']\*["']/gi, description: "Wildcard CORS permits every origin and may expose sensitive browser-accessible responses." },
  { kind: "build_validation_disabled", severity: "MEDIUM", pattern: /\b(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true\b/g, description: "Build configuration suppresses TypeScript or lint failures, allowing known defects to ship." },
];

function withoutComments(content: string) {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, " "))
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/(^|[^:"'])\/\/.*$/gm, "$1");
}

function lineNumber(content: string, index: number) {
  return content.slice(0, index).split("\n").length;
}

export function detectStaticSecurityIssues(path: string, content: string): StaticSecurityIssue[] {
  const inspected = withoutComments(content);
  const rules = [...STATIC_RULES];
  if (/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) {
    rules.push(
      { kind: "privileged_ci_workflow", severity: "HIGH", pattern: /^\s*pull_request_target\s*:/gim, description: "pull_request_target runs with base-repository privileges and must not execute untrusted pull-request code." },
      { kind: "overbroad_ci_permissions", severity: "HIGH", pattern: /^\s*permissions\s*:\s*write-all\s*$/gim, description: "The workflow grants write access to every available GitHub token scope." },
    );
  }
  const issues: StaticSecurityIssue[] = [];
  const seen = new Set<string>();
  for (const rule of rules) {
    if (rule.requires && !rule.requires.test(inspected)) continue;
    rule.pattern.lastIndex = 0;
    for (const match of inspected.matchAll(rule.pattern)) {
      const line = lineNumber(inspected, match.index ?? 0);
      const key = rule.kind;
      if (seen.has(key)) continue;
      seen.add(key);
      issues.push({ kind: rule.kind, severity: rule.severity, description: rule.description, evidence: `${rule.kind} pattern at line ${line}` });
    }
  }
  return issues;
}

export type DependencyIntegrityIssue = {
  kind: "missing_lockfile" | "incomplete_lockfile" | "mutable_dependency_version" | "unproven_dependency_range" | "invalid_manifest";
  severity: "HIGH" | "MEDIUM";
  description: string;
  evidence: string;
};

function lockfileProvesVersions(lockfiles: Record<string, string>) {
  const packageLock = lockfiles["package-lock.json"];
  if (packageLock) {
    try {
      const parsed = JSON.parse(packageLock) as { packages?: Record<string, unknown>; dependencies?: Record<string, unknown> };
      if (Object.keys(parsed.packages ?? {}).length > 0 || Object.keys(parsed.dependencies ?? {}).length > 0) return true;
    } catch {
      return false;
    }
  }
  return false;
}

export function detectDependencyIntegrityIssues(packageJson: string, lockfiles: Record<string, string>): DependencyIntegrityIssue[] {
  let parsed: { dependencies?: unknown; devDependencies?: unknown };
  try {
    parsed = JSON.parse(packageJson) as typeof parsed;
  } catch {
    return [{ kind: "invalid_manifest", severity: "HIGH", description: "The dependency manifest is not valid JSON.", evidence: "package.json could not be parsed" }];
  }
  const groups = [parsed.dependencies, parsed.devDependencies]
    .filter((group): group is Record<string, unknown> => Boolean(group && typeof group === "object" && !Array.isArray(group)));
  const entries = groups.flatMap((group) => Object.entries(group).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
  const mutable = entries.filter(([, version]) => /^(?:latest|next|\*|https?:|git(?:\+|:)|github:|file:|link:|workspace:)/i.test(version));
  const mutableVersions = new Set(mutable.map(([, version]) => version));
  const ranged = entries.filter(([, version]) => !isExactSemver(version) && !mutableVersions.has(version));
  const hasLockfile = Object.keys(lockfiles).length > 0;
  const proven = lockfileProvesVersions(lockfiles);
  const issues: DependencyIntegrityIssue[] = [];
  if (entries.length && !hasLockfile) issues.push({ kind: "missing_lockfile", severity: "MEDIUM", description: "No supported dependency lockfile is committed, so transitive versions are not reproducible.", evidence: "No package-lock.json, pnpm-lock.yaml, or yarn.lock was observed" });
  if (hasLockfile && !proven) issues.push({ kind: "incomplete_lockfile", severity: "HIGH", description: "The committed lockfile does not prove installed dependency versions.", evidence: "Lockfile contains no resolved package entries" });
  if (mutable.length) issues.push({ kind: "mutable_dependency_version", severity: "HIGH", description: "Mutable dependency selectors can resolve to different code without a manifest change.", evidence: `${mutable.length} mutable dependency selector(s) detected` });
  if (ranged.length && !proven) issues.push({ kind: "unproven_dependency_range", severity: "MEDIUM", description: "Dependency ranges are present without a lockfile that proves exact installed versions.", evidence: `${ranged.length} dependency range(s) lack exact lockfile evidence` });
  return issues;
}

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const EXACT_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function isExactSemver(value: string) {
  return EXACT_SEMVER.test(value);
}

function isValidPackageName(value: string) {
  return value.length <= 214 && PACKAGE_NAME.test(value);
}

function hasCredentialShape(value: string) {
  return SECRET_PATTERNS.some(({ pattern }) => new RegExp(pattern.source, pattern.flags).test(value));
}

function lockfileVersions(packageLock: string | undefined) {
  const versions = new Map<string, string>();
  const invalid = new Set<string>();
  if (!packageLock) return { versions, invalid };
  const consider = (name: string, version: unknown) => {
    if (!isValidPackageName(name)) return;
    if (typeof version !== "string" || hasCredentialShape(`${name}:${version}`) || !isExactSemver(version)) {
      invalid.add(name);
      versions.delete(name);
      return;
    }
    if (!invalid.has(name)) versions.set(name, version);
  };
  try {
    const parsed = JSON.parse(packageLock) as { packages?: Record<string, { version?: unknown }>; dependencies?: Record<string, { version?: unknown }> };
    for (const [path, entry] of Object.entries(parsed.packages ?? {})) {
      if (path.startsWith("node_modules/")) consider(path.slice("node_modules/".length), entry.version);
    }
    for (const [name, entry] of Object.entries(parsed.dependencies ?? {})) consider(name, entry.version);
  } catch {
    throw new Error("Repository lockfile is not a valid package-lock.json file.");
  }
  return { versions, invalid };
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
  const { versions: installed, invalid: invalidLockEntries } = lockfileVersions(packageLock);
  const production = toEntries(manifest.dependencies);
  const productionNames = new Set(production.map(([name]) => name));
  const development = toEntries(manifest.devDependencies).filter(([name]) => !productionNames.has(name));
  return [...production, ...development]
    .filter(([name, declared]) =>
      isValidPackageName(name)
      && !invalidLockEntries.has(name)
      && !hasCredentialShape(`${name}:${declared}:${installed.get(name) ?? ""}`)
      && (installed.has(name) || isExactSemver(declared)),
    )
    .slice(0, Math.max(0, limit))
    .map(([name, declared]) => ({ name, version: installed.get(name) ?? declared }));
}

export function validateRemediationPatch(patch: string, packageName: string, expectedCurrentVersion: string, fixedVersions: string[]) {
  if (!patch || patch.length > 20_000 || !isValidPackageName(packageName)) return false;
  const lines = patch.split("\n");
  const oldFiles = lines.filter((line) => line.startsWith("--- "));
  const newFiles = lines.filter((line) => line.startsWith("+++ "));
  if (oldFiles.length !== 1 || newFiles.length !== 1 || oldFiles[0] !== "--- a/package.json" || newFiles[0] !== "+++ b/package.json") return false;
  const removedLines = lines.filter((line) => line.startsWith("-") && !line.startsWith("---"));
  const addedLines = lines.filter((line) => line.startsWith("+") && !line.startsWith("+++"));
  if (removedLines.length !== 1 || addedLines.length !== 1) return false;
  const escapedName = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const removedVersion = removedLines[0].match(new RegExp(`^-\\s*"${escapedName}"\\s*:\\s*"([^"]+)"\\s*,?\\s*$`))?.[1];
  if (removedVersion !== expectedCurrentVersion) return false;
  const addedVersion = addedLines[0].match(new RegExp(`^\\+\\s*"${escapedName}"\\s*:\\s*"([^"]+)"\\s*,?\\s*$`))?.[1];
  return Boolean(addedVersion && isExactSemver(addedVersion) && fixedVersions.includes(addedVersion));
}
