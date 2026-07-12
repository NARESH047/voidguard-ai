import { describe, expect, it } from "vitest";
import { buildGroundingQuery, parseGroundingOutput } from "./grounding";

const citationUrl = "https://github.com/advisories/GHSA-cph5-m8f7-6c5x";
const validSources = new Set([citationUrl]);
const validPayload = JSON.stringify({
  packageName: "axios",
  version: "0.21.1",
  assessment: "AFFECTED",
  severity: "HIGH",
  cveIds: ["CVE-2021-3749"],
  summary: "The requested version is affected by a published advisory.",
  fixedVersions: ["0.21.2"],
  citations: [{ title: "GitHub Advisory", url: citationUrl }],
  confidence: 0.94,
});

describe("buildGroundingQuery", () => {
  it("requires current, exact-version evidence and explicit unknown conclusions", () => {
    const query = buildGroundingQuery("axios", "0.21.1", "2026-07-12");
    expect(query).toContain("axios@0.21.1");
    expect(query).toContain("2026-07-12");
    expect(query).toContain("fresh web search");
    expect(query).toContain("UNKNOWN");
    expect(query).toContain("Absence of evidence is not evidence of safety");
    expect(query).not.toContain("Return an unaffected result when authoritative evidence is absent");
  });
});

describe("parseGroundingOutput", () => {
  it("accepts an exact package result with observed authoritative citations", () => {
    const result = parseGroundingOutput(validPayload, "axios", "0.21.1", validSources);
    expect(result.assessment).toBe("AFFECTED");
    expect(result.cveIds).toEqual(["CVE-2021-3749"]);
  });

  it("rejects mismatched package or version claims", () => {
    expect(() => parseGroundingOutput(validPayload, "lodash", "4.17.15", validSources)).toThrow("did not match");
  });

  it("rejects claims without authoritative citations", () => {
    const payload = JSON.parse(validPayload);
    payload.citations = [{ title: "Random blog", url: "https://example.com/post" }];
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", new Set(["https://example.com/post"]))).toThrow("authoritative citation");
  });

  it("rejects generic pages on otherwise authoritative domains", () => {
    const payload = JSON.parse(validPayload);
    payload.citations = [{ title: "NVD home", url: "https://nvd.nist.gov/" }];
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", new Set(["https://nvd.nist.gov/"]))).toThrow("advisory record");
  });

  it("rejects affected claims with NONE severity", () => {
    const payload = JSON.parse(validPayload);
    payload.severity = "NONE";
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", validSources)).toThrow("NONE severity");
  });

  it("preserves uncertainty instead of treating missing evidence as safe", () => {
    const payload = JSON.parse(validPayload);
    payload.assessment = "UNKNOWN";
    payload.severity = "NONE";
    payload.cveIds = [];
    payload.fixedVersions = [];
    payload.summary = "Fresh authoritative sources did not establish exact-version status.";
    payload.citations = [];
    const result = parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", new Set());
    expect(result.assessment).toBe("UNKNOWN");
  });

  it("allows unknown conclusions to cite an observed primary package source without calling it an advisory", () => {
    const payload = JSON.parse(validPayload);
    payload.assessment = "UNKNOWN";
    payload.severity = "NONE";
    payload.cveIds = [];
    payload.fixedVersions = [];
    payload.citations = [{ title: "npm package", url: "https://www.npmjs.com/package/axios" }];
    const result = parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", new Set(["https://www.npmjs.com/package/axios"]));
    expect(result.assessment).toBe("UNKNOWN");
  });

  it("filters non-semver fixed-version output", () => {
    const payload = JSON.parse(validPayload);
    payload.fixedVersions = ["github:attacker/repo", "0.21.2"];
    const result = parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", validSources);
    expect(result.fixedVersions).toEqual(["0.21.2"]);
  });

  it("drops citations that are not authoritative observed sources", () => {
    const payload = JSON.parse(validPayload);
    payload.citations.push({ title: "Unverified", url: "https://example.com/post" });
    const result = parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", validSources);
    expect(result.citations).toEqual([{ title: "GitHub Advisory", url: citationUrl }]);
  });

  it("rejects model-authored citations absent from observed web-search sources", () => {
    expect(() => parseGroundingOutput(validPayload, "axios", "0.21.1", new Set())).toThrow("observed web-search source");
  });

  it("rejects legacy binary affected fields", () => {
    const payload = JSON.parse(validPayload);
    payload.affected = true;
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1", validSources)).toThrow("unexpected fields");
  });

  it("rejects malformed model output", () => {
    expect(() => parseGroundingOutput("not-json", "axios", "0.21.1", validSources)).toThrow("valid JSON");
  });
});
