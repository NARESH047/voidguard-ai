/// <reference types="vite/client" />
import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import { api } from "./_generated/api";
import schema from "./schema";

const modules = import.meta.glob("./**/*.ts");

describe("scan authorization", () => {
  it("creates a canonical scan owned by the authenticated user", async () => {
    const t = convexTest(schema, modules).withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const scanId = await t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/Acme/widget.git" });
    const scan = await t.query(api.mutations.getScan, { scanId });
    expect(scan?.repoUrl).toBe("https://github.com/Acme/widget");
    expect(scan?.status).toBe("initialized");
  });

  it("does not expose a scan to another user", async () => {
    const t = convexTest(schema, modules);
    const alice = t.withIdentity({ subject: "alice", issuer: "https://auth.test" });
    const bob = t.withIdentity({ subject: "bob", issuer: "https://auth.test" });
    const scanId = await alice.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" });
    expect(await bob.query(api.mutations.getScan, { scanId })).toBeNull();
  });

  it("requires authentication to create scans", async () => {
    const t = convexTest(schema, modules);
    await expect(t.mutation(api.mutations.createScan, { repoUrl: "https://github.com/acme/widget" })).rejects.toThrow("Authentication required");
  });
});
