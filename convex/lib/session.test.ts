import { beforeAll, describe, expect, it } from "vitest";
import { anonymousOwnerKey, verifyAuditProof } from "./session";

const token = "11111111-1111-4111-8111-111111111111";

beforeAll(() => {
  process.env.ANONYMOUS_SESSION_SECRET = "test-anonymous-session-secret";
});

describe("anonymous session security", () => {
  it("stores a secret-derived digest rather than the bearer token", async () => {
    const ownerKey = await anonymousOwnerKey(token);
    expect(ownerKey).toMatch(/^anonymous:[0-9a-f]{64}$/);
    expect(ownerKey).not.toContain(token);
  });

  it("verifies a bounded browser proof-of-work challenge", async () => {
    const scanId = "synthetic-scan-id";
    let validNonce: string | null = null;
    for (let nonce = 0; nonce < 100_000; nonce += 1) {
      if (await verifyAuditProof(token, scanId, String(nonce))) {
        validNonce = String(nonce);
        break;
      }
    }
    expect(validNonce).not.toBeNull();
    if (!validNonce) throw new Error("Expected a valid proof nonce.");
    expect(await verifyAuditProof(token, scanId, validNonce)).toBe(true);
    expect(await verifyAuditProof(token, `${scanId}-other`, validNonce)).toBe(false);
  });
});
