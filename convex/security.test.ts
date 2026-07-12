import { describe, expect, it } from "vitest";
import { detectDependencyIntegrityIssues, detectSecrets, detectStaticSecurityIssues, extractDependencies, isExactSemver, parseGitHubRepoUrl, validateRemediationPatch } from "./lib/security";

describe("parseGitHubRepoUrl", () => {
  it("normalizes an HTTPS repository URL", () => {
    expect(parseGitHubRepoUrl("https://github.com/Acme/widget.git/")).toEqual({
      owner: "Acme",
      repo: "widget",
      canonicalUrl: "https://github.com/Acme/widget",
    });
  });

  it.each([
    "http://github.com/acme/widget",
    "https://example.com/acme/widget",
    "https://github.com/acme",
    "https://github.com/acme/widget/issues",
  ])("rejects unsupported repository URL %s", (url) => {
    expect(() => parseGitHubRepoUrl(url)).toThrow("valid HTTPS GitHub repository URL");
  });
});

describe("detectSecrets", () => {
  it("detects and redacts credential-like values", () => {
    const raw = "sk-fixtureSecret1234567890abcdefgh";
    const findings = detectSecrets(`OPENAI_API_KEY=${raw}`);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("api_key");
    expect(findings[0].evidence).not.toContain(raw);
    expect(findings[0].evidence).toContain("[REDACTED]");
  });

  it("does not flag obvious placeholders", () => {
    expect(detectSecrets('OPENAI_API_KEY="your-api-key-here"')).toEqual([]);
  });

  it("detects credentials assigned to quoted JSON keys", () => {
    const findings = detectSecrets('{"password":"synthetic-only-password-1234"}');
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("credential_assignment");
    expect(findings[0].evidence).not.toContain("synthetic-only-password-1234");
  });
  it("detects provider signatures even near placeholder-like names and redacts every value", () => {
    const values = [
      `npm_${"a".repeat(36)}`,
      `xoxb-${"1".repeat(12)}-${"2".repeat(12)}-${"a".repeat(24)}`,
      `sk_live_${"a".repeat(24)}`,
      `AIza${"a".repeat(35)}`,
      `glpat-${"a".repeat(20)}`,
    ];
    const findings = detectSecrets(values.map((value, index) => `example_${index} = "${value}"`).join("\n"));
    expect(new Set(findings.map((finding) => finding.kind))).toEqual(new Set(["npm_token", "slack_token", "stripe_live_key", "google_api_key", "gitlab_token"]));
    for (const value of values) expect(findings.every((finding) => !finding.evidence.includes(value))).toBe(true);
  });

  it("detects and redacts credentials embedded in URLs", () => {
    const findings = detectSecrets("https://synthetic-user:synthetic-password-123@example.invalid/resource");
    expect(findings).toEqual([expect.objectContaining({ kind: "credential_url" })]);
    expect(findings[0].evidence).not.toContain("synthetic-password-123");
  });
});

describe("detectStaticSecurityIssues", () => {
  it("flags high-signal issues across MECE code and configuration categories", () => {
    const source = `
      import { exec } from "node:child_process";
      eval(userInput);
      exec(command);
      const matches = regex.exec(input);
      const html = { __html: userHtml };
      <div dangerouslySetInnerHTML={html} />;
      const agent = { rejectUnauthorized: false };
      createHash("sha1");
      localStorage.setItem("isLoggedIn", "true");
    `;
    const kinds = detectStaticSecurityIssues("src/app.tsx", source).map((issue) => issue.kind);
    expect(kinds).toEqual(expect.arrayContaining([
      "dynamic_code_execution",
      "command_execution",
      "cross_site_scripting",
      "tls_verification_disabled",
      "weak_cryptography",
      "client_side_authentication",
    ]));
  });

  it("does not flag examples that exist only inside comments", () => {
    const source = `// eval(userInput)\nconst safe = true; // rejectUnauthorized: false\n/* dangerouslySetInnerHTML={x} */`;
    expect(detectStaticSecurityIssues("src/safe.ts", source)).toEqual([]);
  });

  it("flags privileged workflow triggers and wildcard CORS", () => {
    expect(detectStaticSecurityIssues(".github/workflows/review.yml", "on:\n  pull_request_target:\npermissions: write-all"))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ kind: "privileged_ci_workflow" }),
        expect.objectContaining({ kind: "overbroad_ci_permissions" }),
      ]));
    expect(detectStaticSecurityIssues("server.ts", `res.setHeader("Access-Control-Allow-Origin", "*")`))
      .toEqual(expect.arrayContaining([expect.objectContaining({ kind: "permissive_cors" })]));
    expect(detectStaticSecurityIssues("next.config.mjs", "typescript: { ignoreBuildErrors: true }, eslint: { ignoreDuringBuilds: true }"))
      .toEqual(expect.arrayContaining([expect.objectContaining({ kind: "build_validation_disabled" })]));
  });
});

describe("detectDependencyIntegrityIssues", () => {
  it("flags unproven ranges and mutable dependency selectors", () => {
    const manifest = JSON.stringify({ dependencies: { next: "15.1.0", react: "^19", "date-fns": "latest" } });
    const issues = detectDependencyIntegrityIssues(manifest, { "pnpm-lock.yaml": "lockfileVersion: '6.0'\nsettings:\n  autoInstallPeers: true" });
    expect(issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "incomplete_lockfile" }),
      expect.objectContaining({ kind: "mutable_dependency_version" }),
      expect.objectContaining({ kind: "unproven_dependency_range" }),
    ]));
  });

  it("flags a missing lockfile even when direct dependencies are exact", () => {
    const manifest = JSON.stringify({ dependencies: { next: "15.1.0" } });
    expect(detectDependencyIntegrityIssues(manifest, {})).toEqual([
      expect.objectContaining({ kind: "missing_lockfile" }),
    ]);
  });
});

describe("isExactSemver", () => {
  it("accepts build metadata and rejects malformed exact versions", () => {
    expect(isExactSemver("1.2.3+build.7")).toBe(true);
    expect(isExactSemver("01.2.3")).toBe(false);
    expect(isExactSemver("1.2.3-alpha..1")).toBe(false);
    expect(isExactSemver("1.2.3-01")).toBe(false);
  });
});

describe("extractDependencies", () => {
  it("combines production and development dependencies with a deterministic cap", () => {
    const manifest = JSON.stringify({
      dependencies: { zod: "4.0.0", axios: "0.21.1" },
      devDependencies: { vitest: "4.0.0" },
    });
    expect(extractDependencies(manifest, 2)).toEqual([
      { name: "axios", version: "0.21.1" },
      { name: "zod", version: "4.0.0" },
    ]);
  });

  it("rejects malformed package manifests", () => {
    expect(() => extractDependencies("not-json", 10)).toThrow("valid package.json");
  });

  it("uses exact installed versions from package-lock.json", () => {
    const manifest = JSON.stringify({ dependencies: { axios: "^0.21.0" } });
    const lockfile = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/axios": { version: "0.21.1" } } });
    expect(extractDependencies(manifest, 10, lockfile)).toEqual([{ name: "axios", version: "0.21.1" }]);
  });

  it("skips dependency ranges when no lockfile proves an installed version", () => {
    const manifest = JSON.stringify({ dependencies: { axios: "^0.21.0", lodash: "4.17.15" } });
    expect(extractDependencies(manifest, 10)).toEqual([{ name: "lodash", version: "4.17.15" }]);
  });

  it("rejects credential-shaped dependency metadata", () => {
    const manifest = JSON.stringify({ dependencies: { "sk-proj-abcdefghijklmnopqrstuvwxyz123456": "1.0.0", lodash: "4.17.15" } });
    expect(extractDependencies(manifest, 10)).toEqual([{ name: "lodash", version: "4.17.15" }]);
  });

  it("rejects placeholder-shaped credential names and unsafe package names", () => {
    const longName = `a${"b".repeat(214)}`;
    const manifest = JSON.stringify({ dependencies: { "sk-example-abcdefghijklmnopqrstuvwxyz123456": "1.0.0", UpperCase: "1.0.0", [longName]: "1.0.0", safe: "1.2.3+build.7" } });
    expect(extractDependencies(manifest, 10)).toEqual([{ name: "safe", version: "1.2.3+build.7" }]);
  });

  it("fails closed when lockfile metadata for a dependency is credential-shaped", () => {
    const manifest = JSON.stringify({ dependencies: { axios: "1.2.3" } });
    const lockfile = JSON.stringify({ packages: { "node_modules/axios": { version: "sk-proj-abcdefghijklmnopqrstuvwxyz123456" } } });
    expect(extractDependencies(manifest, 10, lockfile)).toEqual([]);
  });
});

describe("validateRemediationPatch", () => {
  const patch = `--- a/package.json\n+++ b/package.json\n@@ -1,3 +1,3 @@\n-  "lodash": "4.17.15"\n+  "lodash": "4.17.21"`;

  it("accepts a package-only patch using a confirmed fixed version", () => {
    expect(validateRemediationPatch(patch, "lodash", "4.17.15", ["4.17.21"])).toBe(true);
  });

  it("rejects an unsupported replacement version", () => {
    expect(validateRemediationPatch(patch.replace("4.17.21", "9.9.9"), "lodash", "4.17.15", ["4.17.21"])).toBe(false);
  });

  it("rejects a patch that removes a version other than the audited version", () => {
    expect(validateRemediationPatch(patch.replace("4.17.15", "4.17.14"), "lodash", "4.17.15", ["4.17.21"])).toBe(false);
  });

  it("rejects patches that modify another file", () => {
    expect(validateRemediationPatch(patch.replaceAll("package.json", "src/index.ts"), "lodash", "4.17.15", ["4.17.21"])).toBe(false);
  });

  it("rejects unrelated package.json changes", () => {
    const unrelated = `${patch}\n-  "scripts": {}\n+  "scripts": { "postinstall": "curl example.com" }`;
    expect(validateRemediationPatch(unrelated, "lodash", "4.17.15", ["4.17.21"])).toBe(false);
  });
});
