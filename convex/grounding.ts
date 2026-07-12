import OpenAI from "openai";

export type GroundedCitation = { title: string; url: string };
export type GroundedVulnerability = {
  packageName: string;
  version: string;
  affected: boolean;
  severity: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  cveIds: string[];
  summary: string;
  fixedVersions: string[];
  citations: GroundedCitation[];
  confidence: number;
};

const AUTHORITATIVE_DOMAINS = ["nvd.nist.gov", "github.com", "osv.dev", "npmjs.com"];
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

export function buildGroundingQuery(packageName: string, version: string) {
  return [
    `Determine whether the exact version ${packageName}@${version} is affected by a published security advisory.`,
    "Use authoritative sources only: NVD, GitHub Advisory Database, OSV, or the package maintainer registry.",
    "Do not treat a vulnerability in a different version range as affecting the exact version.",
    "Return an unaffected result when authoritative evidence is absent or ambiguous.",
  ].join(" ");
}

function assertStringArray(value: unknown, field: string) {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`Grounding output field ${field} must be an array of strings.`);
  }
  return value as string[];
}

function isAuthoritativeUrl(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") return false;
    if (url.hostname === "github.com") {
      return url.pathname.startsWith("/advisories/") || url.pathname.includes("/security/advisories/");
    }
    return AUTHORITATIVE_DOMAINS.filter((domain) => domain !== "github.com")
      .some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`));
  } catch {
    return false;
  }
}

function normalizeSourceUrl(value: string) {
  try {
    const url = new URL(value);
    url.hash = "";
    url.search = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return "";
  }
}

export function extractObservedSourceUrls(output: unknown) {
  const urls = new Set<string>();
  if (!Array.isArray(output)) return urls;
  for (const item of output) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    if (record.type !== "web_search_call" || !record.action || typeof record.action !== "object") continue;
    const sources = (record.action as Record<string, unknown>).sources;
    if (!Array.isArray(sources)) continue;
    for (const source of sources) {
      if (!source || typeof source !== "object" || Array.isArray(source)) continue;
      const url = (source as Record<string, unknown>).url;
      if (typeof url !== "string") continue;
      const normalized = normalizeSourceUrl(url);
      if (normalized) urls.add(normalized);
    }
  }
  return urls;
}

export function parseGroundingOutput(raw: string, packageName: string, version: string, observedSourceUrls: Set<string>): GroundedVulnerability {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Grounding model did not return valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Grounding model returned an invalid object.");
  }
  const record = value as Record<string, unknown>;
  if (record.packageName !== packageName || record.version !== version) {
    throw new Error("Grounding result did not match the requested package and version.");
  }
  if (typeof record.affected !== "boolean" || typeof record.summary !== "string") {
    throw new Error("Grounding result is missing required fields.");
  }
  const severities = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
  if (!severities.includes(record.severity as (typeof severities)[number])) {
    throw new Error("Grounding result has an invalid severity.");
  }
  if (record.affected && record.severity === "NONE") {
    throw new Error("Affected claims cannot use NONE severity.");
  }
  const confidence = record.confidence;
  if (typeof confidence !== "number" || confidence < 0 || confidence > 1) {
    throw new Error("Grounding result confidence must be between 0 and 1.");
  }
  if (!Array.isArray(record.citations)) throw new Error("Grounding result citations must be an array.");
  const citations = record.citations.map((citation) => {
    if (!citation || typeof citation !== "object" || Array.isArray(citation)) {
      throw new Error("Grounding result contains an invalid citation.");
    }
    const item = citation as Record<string, unknown>;
    if (typeof item.title !== "string" || typeof item.url !== "string") {
      throw new Error("Grounding result contains an invalid citation.");
    }
    return { title: item.title, url: item.url };
  });
  const normalizedObserved = new Set([...observedSourceUrls].map(normalizeSourceUrl).filter(Boolean));
  const verifiedCitations = citations.filter((citation) =>
    isAuthoritativeUrl(citation.url) && normalizedObserved.has(normalizeSourceUrl(citation.url)),
  );
  if (!verifiedCitations.length) {
    throw new Error("Grounding claims require an authoritative citation matching an observed web-search source.");
  }
  return {
    packageName,
    version,
    affected: record.affected,
    severity: record.severity as GroundedVulnerability["severity"],
    cveIds: assertStringArray(record.cveIds, "cveIds").filter((id) => /^CVE-\d{4}-\d{4,}$/i.test(id)),
    summary: record.summary.slice(0, 4000),
    fixedVersions: assertStringArray(record.fixedVersions, "fixedVersions").filter((candidate) => EXACT_VERSION.test(candidate)).slice(0, 20),
    citations: verifiedCitations.slice(0, 12),
    confidence,
  };
}

export function createOpenAIClient() {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error("OPENAI_API_KEY is not configured.");
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const gatewayId = process.env.CLOUDFLARE_GATEWAY_ID;
  const gatewayToken = process.env.CLOUDFLARE_API_TOKEN;
  return new OpenAI({
    apiKey,
    baseURL: accountId && gatewayId ? `https://gateway.ai.cloudflare.com/v1/${accountId}/${gatewayId}/openai` : undefined,
    defaultHeaders: gatewayToken ? { "cf-aig-authorization": `Bearer ${gatewayToken}` } : undefined,
    timeout: 30_000,
    maxRetries: 2,
  });
}

const groundingSchema = {
  type: "object",
  additionalProperties: false,
  required: ["packageName", "version", "affected", "severity", "cveIds", "summary", "fixedVersions", "citations", "confidence"],
  properties: {
    packageName: { type: "string" },
    version: { type: "string" },
    affected: { type: "boolean" },
    severity: { type: "string", enum: ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    cveIds: { type: "array", items: { type: "string" } },
    summary: { type: "string" },
    fixedVersions: { type: "array", items: { type: "string" } },
    citations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["title", "url"],
        properties: { title: { type: "string" }, url: { type: "string" } },
      },
    },
    confidence: { type: "number", minimum: 0, maximum: 1 },
  },
} as const;

export async function lookupDependencyVulnerabilities(packageName: string, version: string) {
  const client = createOpenAIClient();
  const model = process.env.VOIDGUARD_GROUNDING_MODEL ?? "gpt-5.2";
  const response = await client.responses.create({
    model,
    input: buildGroundingQuery(packageName, version),
    tools: [{
      type: "web_search",
      search_context_size: "low",
      filters: { allowed_domains: AUTHORITATIVE_DOMAINS },
    }],
    include: ["web_search_call.action.sources"],
    text: {
      format: {
        type: "json_schema",
        name: "dependency_vulnerability",
        strict: true,
        schema: groundingSchema,
      },
    },
  });
  return parseGroundingOutput(response.output_text, packageName, version, extractObservedSourceUrls(response.output));
}
