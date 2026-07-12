/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");
process.env.ANONYMOUS_SESSION_SECRET = "test-anonymous-session-secret";
const sessionToken = "11111111-1111-4111-8111-111111111111";

describe("anonymous public scans", () => {
  it("creates and reads a scan without authentication", async () => {
    const t = convexTest(schema, modules);
    const scanId = await t.mutation(api.mutations.createScan, {
      repoUrl: "https://github.com/acme/widget",
      sessionToken,
    });
    const scan = await t.query(api.mutations.getScan, { scanId, sessionToken });
    expect(scan?.repoUrl).toBe("https://github.com/acme/widget");
    expect(scan).not.toHaveProperty("ownerTokenIdentifier");
  });
});
