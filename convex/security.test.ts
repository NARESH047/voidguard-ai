import { describe, expect, it } from "vitest";
import { detectSecrets, extractDependencies, isExactSemver, parseGitHubRepoUrl, validateRemediationPatch } from "./lib/security";

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
    expect(validateRemediationPatch(patch, "lodash", ["4.17.21"])).toBe(true);
  });

  it("rejects an unsupported replacement version", () => {
    expect(validateRemediationPatch(patch.replace("4.17.21", "9.9.9"), "lodash", ["4.17.21"])).toBe(false);
  });

  it("rejects patches that modify another file", () => {
    expect(validateRemediationPatch(patch.replaceAll("package.json", "src/index.ts"), "lodash", ["4.17.21"])).toBe(false);
  });

  it("rejects unrelated package.json changes", () => {
    const unrelated = `${patch}\n-  "scripts": {}\n+  "scripts": { "postinstall": "curl example.com" }`;
    expect(validateRemediationPatch(unrelated, "lodash", ["4.17.21"])).toBe(false);
  });
});
