import { describe, expect, it, vi } from "vitest";
import { decodeBoundedBase64, loadRepositoryFiles } from "./github";

describe("decodeBoundedBase64", () => {
  it("decodes content at the exact byte limit", () => {
    expect(decodeBoundedBase64(btoa("hello"), 5)).toEqual({ content: "hello", size: 5 });
  });

  it("rejects decoded content one byte above the limit", () => {
    expect(decodeBoundedBase64(btoa("hello"), 4)).toBeNull();
  });

  it("ignores bounded whitespace and counts multibyte UTF-8 bytes", () => {
    const encoded = Buffer.from("€", "utf8").toString("base64");
    expect(decodeBoundedBase64(`  ${encoded.slice(0, 2)}\n${encoded.slice(2)}  `, 3)).toEqual({ content: "€", size: 3 });
  });

  it("rejects malformed and allocation-amplifying input", () => {
    expect(decodeBoundedBase64("%%%", 100)).toBeNull();
    expect(decodeBoundedBase64("A".repeat(10_000), 4)).toBeNull();
  });
});

describe("public repository eligibility", () => {
  it("probes repository metadata without ambient private authority", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("not found", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("GITHUB_TOKEN", "synthetic-test-token");
    try {
      await expect(loadRepositoryFiles("https://github.com/acme/private-repo")).rejects.toThrow("not publicly accessible");
      const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
      expect((request.headers as Record<string, string>).Authorization).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });
});
