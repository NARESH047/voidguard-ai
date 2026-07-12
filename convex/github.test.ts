import { describe, expect, it, vi } from "vitest";
import { decodeBoundedBase64, loadRepositoryFiles, selectRepositoryCandidates } from "./github";

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

describe("bounded repository selection", () => {
  it("prioritizes security-sensitive files over generated UI components", () => {
    const tree = [
      { path: "package.json", type: "blob", size: 100 },
      { path: "contexts/auth-context.tsx", type: "blob", size: 100 },
      { path: "lib/ai-utils.ts", type: "blob", size: 100 },
      { path: ".env.production", type: "blob", size: 100 },
      { path: "Dockerfile", type: "blob", size: 100 },
      ...Array.from({ length: 45 }, (_, index) => ({ path: `components/ui/generated-${String(index).padStart(2, "0")}.tsx`, type: "blob", size: 100 })),
    ];
    const selected = selectRepositoryCandidates(tree).map((item) => item.path);
    expect(selected).toHaveLength(40);
    expect(selected).toContain("contexts/auth-context.tsx");
    expect(selected).toContain("lib/ai-utils.ts");
    expect(selected).toContain(".env.production");
    expect(selected).toContain("Dockerfile");
  });
});

describe("public repository eligibility", () => {
  it("proves public readability before using ambient API authority", async () => {
    const packageJson = JSON.stringify({ dependencies: { lodash: "4.17.21" } });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("git advertisement", { status: 200, headers: { "content-type": "application/x-git-upload-pack-advertisement" } }))
      .mockResolvedValueOnce(Response.json({ default_branch: "main", private: false, size: 1 }))
      .mockResolvedValueOnce(Response.json({ sha: "abc123" }))
      .mockResolvedValueOnce(Response.json({ truncated: false, tree: [{ path: "package.json", type: "blob", size: packageJson.length }] }))
      .mockResolvedValueOnce(Response.json({ type: "file", size: packageJson.length, content: btoa(packageJson), encoding: "base64" }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("GITHUB_TOKEN", "synthetic-test-token");
    try {
      const repository = await loadRepositoryFiles("https://github.com/acme/public-repo");
      expect(repository.files).toHaveLength(1);
      expect(String(fetchMock.mock.calls[0]?.[0])).toContain("public-repo.git/info/refs?service=git-upload-pack");
      const publicProbe = fetchMock.mock.calls[0]?.[1] as RequestInit;
      const metadataRequest = fetchMock.mock.calls[1]?.[1] as RequestInit;
      expect((publicProbe.headers as Record<string, string>).Authorization).toBeUndefined();
      expect((metadataRequest.headers as Record<string, string>).Authorization).toContain("synthetic-test-token");
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });

  it("rejects repositories that are not anonymously readable before API access", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("not found", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(loadRepositoryFiles("https://github.com/acme/private-repo")).rejects.toThrow("not publicly accessible");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
