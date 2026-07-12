import { describe, expect, it } from "vitest";
import { buildQaInstructions, buildRemediationInstructions } from "./instructions";

const grounding = {
  packageName: "axios",
  version: "0.21.1",
  summary: "Current authoritative evidence includes the exact version.",
  fixedVersions: ["0.21.2"],
};

describe("freshness-safe agent instructions", () => {
  it("constrains remediation to current observed evidence and one minimal change", () => {
    const prompt = buildRemediationInstructions(grounding, "2026-07-12");
    expect(prompt).toContain("2026-07-12");
    expect(prompt).toContain("untrusted data");
    expect(prompt).toContain("observed authoritative evidence");
    expect(prompt).toContain("exactly one dependency line");
    expect(prompt).toContain("empty remediationPatch");
    expect(prompt).toContain("Never use model memory");
  });

  it("requires QA to reject stale, unrelated, ranged, or unsupported proposals", () => {
    const prompt = buildQaInstructions(grounding, "--- a/package.json\n+++ b/package.json", "2026-07-12");
    expect(prompt).toContain("independent fail-closed QA verifier");
    expect(prompt).toContain("2026-07-12");
    expect(prompt).toContain("Reject");
    expect(prompt).toContain("version range");
    expect(prompt).toContain("unrelated");
    expect(prompt).toContain("deterministic validation");
  });
});
