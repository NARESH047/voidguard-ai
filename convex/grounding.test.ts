import { describe, expect, it } from "vitest";
import { buildGroundingQuery, parseGroundingOutput } from "./grounding";

const validPayload = JSON.stringify({
  packageName: "axios",
  version: "0.21.1",
  affected: true,
  severity: "HIGH",
  cveIds: ["CVE-2021-3749"],
  summary: "The requested version is affected by a published advisory.",
  fixedVersions: ["0.21.2"],
  citations: [{ title: "GitHub Advisory", url: "https://github.com/advisories/GHSA-cph5-m8f7-6c5x" }],
  confidence: 0.94,
});

describe("buildGroundingQuery", () => {
  it("requests exact-version evidence from authoritative sources", () => {
    const query = buildGroundingQuery("axios", "0.21.1");
    expect(query).toContain("axios@0.21.1");
    expect(query).toContain("exact version");
    expect(query).toContain("NVD");
  });
});

describe("parseGroundingOutput", () => {
  it("accepts an exact package result with authoritative citations", () => {
    const result = parseGroundingOutput(validPayload, "axios", "0.21.1");
    expect(result.affected).toBe(true);
    expect(result.cveIds).toEqual(["CVE-2021-3749"]);
  });

  it("rejects mismatched package or version claims", () => {
    expect(() => parseGroundingOutput(validPayload, "lodash", "4.17.15")).toThrow("did not match");
  });

  it("rejects affected claims without authoritative citations", () => {
    const payload = JSON.parse(validPayload);
    payload.citations = [{ title: "Random blog", url: "https://example.com/post" }];
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1")).toThrow("authoritative citation");
  });

  it("rejects affected claims with NONE severity", () => {
    const payload = JSON.parse(validPayload);
    payload.severity = "NONE";
    expect(() => parseGroundingOutput(JSON.stringify(payload), "axios", "0.21.1")).toThrow("NONE severity");
  });

  it("rejects malformed model output", () => {
    expect(() => parseGroundingOutput("not-json", "axios", "0.21.1")).toThrow("valid JSON");
  });
});
