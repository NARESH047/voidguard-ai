type LinkupResponse = {
  sourcedAnswer?: string;
  answer?: string;
  sources?: Array<{ name?: string; url?: string; snippet?: string }>;
};

function getApiKey() {
  const apiKey = process.env.LINKUP_API_KEY;
  if (!apiKey) throw new Error("LINKUP_API_KEY is not configured.");
  return apiKey;
}

export async function lookupDependencyVulnerabilities(packageName: string, version: string) {
  const query = `Check ${packageName}@${version} for active CVEs or security advisories. Prefer official NVD, GitHub Advisory Database, and package-maintainer sources.`;
  const response = await fetch("https://api.linkup.so/v1/search", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${getApiKey()}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, depth: "standard", outputType: "sourcedAnswer" }),
  });

  if (!response.ok) throw new Error(`Linkup request failed with HTTP ${response.status}.`);
  const result = (await response.json()) as LinkupResponse;
  const rawContext = result.sourcedAnswer ?? result.answer ?? "";
  const lower = rawContext.toLowerCase();
  return {
    hasVulnerabilities: /cve-\d{4}-\d{4,}|security advisory|vulnerable|exploit/.test(lower),
    rawContext,
    sources: result.sources ?? [],
  };
}
