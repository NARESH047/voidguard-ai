import { parseGitHubRepoUrl } from "./lib/security";

export type RepositoryFile = { path: string; content: string; size: number };

type RepositoryMetadata = { default_branch: string; private: boolean; size: number };
type CommitResponse = { sha: string };
type TreeResponse = { truncated: boolean; tree: Array<{ path: string; type: string; size?: number }> };
type ContentResponse = { type: string; size: number; content?: string; encoding?: string };

const MAX_FILES = 40;
const MAX_FILE_BYTES = 120_000;
const MAX_REPOSITORY_KB = 250_000;
const INCLUDED_NAMES = new Set(["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", ".env", ".env.example", ".env.sample", ".npmrc", ".pypirc", "Dockerfile"]);
const INCLUDED_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".json", ".yml", ".yaml", ".toml", ".ini", ".conf", ".py", ".rb", ".go", ".java", ".cs", ".php", ".sh", ".bash", ".zsh", ".pem", ".key"];
const EXCLUDED_PREFIXES = ["node_modules/", ".git/", "dist/", "build/", ".next/", "out/", "vendor/"];

function githubHeaders(authenticated: boolean) {
  const token = authenticated ? process.env.GITHUB_TOKEN : undefined;
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "VoidGuard-AI",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function githubJson<T>(path: string, authenticated = true): Promise<T> {
  const response = await fetch(`https://api.github.com${path}`, { headers: githubHeaders(authenticated) });
  if (!response.ok) throw new Error(`GitHub API unavailable (HTTP ${response.status}). Try again later.`);
  return response.json() as Promise<T>;
}

async function assertPublicRepository(owner: string, repo: string) {
  const publicGitUrl = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}.git/info/refs?service=git-upload-pack`;
  const response = await fetch(publicGitUrl, {
    headers: {
      Accept: "application/x-git-upload-pack-advertisement",
      "User-Agent": "VoidGuard-AI",
    },
  });
  if (!response.ok || !response.headers.get("content-type")?.includes("application/x-git-upload-pack-advertisement")) {
    throw new Error("Repository not found or not publicly accessible.");
  }
}

function shouldRead(path: string, size: number) {
  if (size <= 0 || size > MAX_FILE_BYTES || EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix))) return false;
  const name = path.split("/").at(-1) ?? path;
  return INCLUDED_NAMES.has(name) || name.startsWith(".env.") || INCLUDED_EXTENSIONS.some((extension) => name.endsWith(extension));
}

function securityPriority(path: string) {
  const name = path.split("/").at(-1) ?? path;
  if ((name === "package.json" || name === "package-lock.json" || name === "pnpm-lock.yaml" || name === "yarn.lock") && !path.includes("/")) return 0;
  if (
    name.startsWith(".env.")
    || name === ".npmrc"
    || name === ".pypirc"
    || /\.(?:pem|key)$/i.test(name)
    || path.startsWith(".github/workflows/")
    || /^(?:contexts|lib|server|api|config|security|middleware|auth|routes?)\//i.test(path)
    || /(?:^|\/)(?:auth|session|security|crypto|middleware|route|server|config|ai)[^/]*\.[^.]+$/i.test(path)
  ) return 1;
  if (path.startsWith("components/ui/") || path.startsWith("public/")) return 3;
  return 2;
}

export function selectRepositoryCandidates(tree: Array<{ path: string; type: string; size?: number }>) {
  return tree
    .filter((item) => item.type === "blob" && shouldRead(item.path, item.size ?? 0))
    .sort((a, b) => securityPriority(a.path) - securityPriority(b.path) || a.path.localeCompare(b.path))
    .slice(0, MAX_FILES);
}

export function decodeBoundedBase64(value: string, maxBytes: number) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) return null;
  const maxEncodedLength = Math.ceil(maxBytes / 3) * 4;
  let compact = "";
  for (const character of value) {
    if (/\s/.test(character)) continue;
    compact += character;
    if (compact.length > maxEncodedLength) return null;
  }
  try {
    const binary = atob(compact);
    if (binary.length > maxBytes) return null;
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return { content: new TextDecoder().decode(bytes), size: bytes.byteLength };
  } catch {
    return null;
  }
}

export async function loadRepositoryFiles(repoUrl: string) {
  const { owner, repo, canonicalUrl } = parseGitHubRepoUrl(repoUrl);
  await assertPublicRepository(owner, repo);
  const metadata = await githubJson<RepositoryMetadata>(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
  if (metadata.private) throw new Error("Repository not found or not publicly accessible.");
  if (metadata.size > MAX_REPOSITORY_KB) throw new Error("Repository exceeds the current 250 MB audit limit.");

  const branch = metadata.default_branch;
  const commit = await githubJson<CommitResponse>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits/${encodeURIComponent(branch)}`,
  );
  const tree = await githubJson<TreeResponse>(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(commit.sha)}?recursive=1`,
  );
  if (tree.truncated) throw new Error("Repository tree is too large for a complete bounded audit.");

  const eligibleFileCount = tree.tree.filter((item) => item.type === "blob" && shouldRead(item.path, item.size ?? 0)).length;
  const candidates = selectRepositoryCandidates(tree.tree);

  const files: RepositoryFile[] = [];
  for (const candidate of candidates) {
    const encodedPath = candidate.path.split("/").map(encodeURIComponent).join("/");
    const item = await githubJson<ContentResponse>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${encodedPath}?ref=${encodeURIComponent(commit.sha)}`,
    );
    if (item.type !== "file" || item.encoding !== "base64" || !item.content || item.size > MAX_FILE_BYTES) continue;
    const decoded = decodeBoundedBase64(item.content, MAX_FILE_BYTES);
    if (!decoded) continue;
    files.push({ path: candidate.path, content: decoded.content, size: decoded.size });
  }
  if (files.length === 0) throw new Error("No supported source, configuration, or manifest files were found.");
  return { owner, repo, canonicalUrl, branch, commitSha: commit.sha, files, eligibleFileCount, omittedFileCount: Math.max(0, eligibleFileCount - files.length) };
}
