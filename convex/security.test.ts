import { describe, expect, it } from "vitest";
import { detectSecrets, extractDependencies, parseGitHubRepoUrl } from "./lib/security";

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

describe("extractDependencies", () => {
  it("combines production and development dependencies with a deterministic cap", () => {
    const manifest = JSON.stringify({
      dependencies: { zod: "^4.0.0", axios: "0.21.1" },
      devDependencies: { vitest: "^4.0.0" },
    });
    expect(extractDependencies(manifest, 2)).toEqual([
      { name: "axios", version: "0.21.1" },
      { name: "zod", version: "4.0.0" },
    ]);
  });

  it("rejects malformed package manifests", () => {
    expect(() => extractDependencies("not-json", 10)).toThrow("valid package.json");
  });
});
