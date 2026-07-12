import { parseGitHubRepoUrl } from "./lib/security";

export type RepositoryFile = { path: string; content: string; size: number };

type RepositoryMetadata = { default_branch: string; private: boolean; size: number };
type TreeResponse = { truncated: boolean; tree: Array<{ path: string; type: string; size?: number }> };
type ContentResponse = { type: string; size: number; content?: string; encoding?: string };

const MAX_FILES = 40;
const MAX_FILE_BYTES = 120_000;
const MAX_REPOSITORY_KB = 250_000;
const INCLUDED_NAMES = new Set(["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", ".env.example", ".env.sample"]);
const INCLUDED_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml", ".ini", ".conf"];
const EXCLUDED_PREFIXES = ["node_modules/", ".git/", "dist/", "build/", ".next/", "out/", "vendor/"];

function githubHeaders() {
  const token = process.env.GITHUB_TOKEN;
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "VoidGuard-AI",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function githubJson<T>(path: string): Promise<T> {
  const response = await fetch(`https://api.github.com${path}`, { headers: githubHeaders() });
  if (!response.ok) {
    const hint = response.status === 404 ? "Repository not found or not accessible." : `GitHub API returned HTTP ${response.status}.`;
    throw new Error(hint);
  }
  return response.json() as Promise<T>;
}

function shouldRead(path: string, size: number) {
  if (size <= 0 || size > MAX_FILE_BYTES || EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix))) return false;
  const name = path.split("/").at(-1) ?? path;
  return INCLUDED_NAMES.has(name) || INCLUDED_EXTENSIONS.some((extension) => name.endsWith(extension));
}

function decodeBase64(value: string) {
  return atob(value.replace(/\s/g, ""));
}

export async function loadRepositoryFiles(repoUrl: string) {
  const { owner, repo, canonicalUrl } = parseGitHubRepoUrl(repoUrl);
  const metadata = await githubJson<RepositoryMetadata>(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
  if (metadata.private) throw new Error("Repository not found or not publicly accessible.");
  if (metadata.size > MAX_REPOSITORY_KB) throw new Error("Repository exceeds the current 250 MB audit limit.");

  const branch = metadata.default_branch;
  const tree = await githubJson<TreeResponse>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  );
  if (tree.truncated) throw new Error("Repository tree is too large for a complete bounded audit.");

  const candidates = tree.tree
    .filter((item) => item.type === "blob" && shouldRead(item.path, item.size ?? 0))
    .sort((a, b) => {
      const aPriority = INCLUDED_NAMES.has(a.path.split("/").at(-1) ?? "") ? 0 : 1;
      const bPriority = INCLUDED_NAMES.has(b.path.split("/").at(-1) ?? "") ? 0 : 1;
      return aPriority - bPriority || a.path.localeCompare(b.path);
    })
    .slice(0, MAX_FILES);

  const files: RepositoryFile[] = [];
  for (const candidate of candidates) {
    const encodedPath = candidate.path.split("/").map(encodeURIComponent).join("/");
    const item = await githubJson<ContentResponse>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}?ref=${encodeURIComponent(branch)}`,
    );
    if (item.type !== "file" || item.encoding !== "base64" || !item.content) continue;
    files.push({ path: candidate.path, content: decodeBase64(item.content), size: item.size });
  }
  if (files.length === 0) throw new Error("No supported source, configuration, or manifest files were found.");
  return { owner, repo, canonicalUrl, branch, files };
}
