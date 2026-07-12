# VoidGuard AI

Evidence-first, no-login security triage for public GitHub repositories.

**Live demo:** https://voidguard-ai.pages.dev/

**Synthetic test repository:** https://github.com/NARESH047/voidguard-fixture

VoidGuard accepts a public GitHub URL, pins the audit to one immutable commit, selects a risk-prioritized bounded file set, runs deterministic checks, searches current primary advisory sources for exact dependency versions, and presents redacted evidence plus review-only remediation proposals.

## Why it exists

Security tools are often powerful but fragmented: secret scanning, SAST, dependency alerts, CI policy checks, and remediation live in separate products or repository-integrated workflows. VoidGuard is a fast, public, evidence-oriented triage surface that makes the investigation legible in one place.

It is intentionally **not** a replacement for production CodeQL/Semgrep deployments, GitHub Advanced Security, Snyk, Trivy, OSV-Scanner, or Socket. Those products provide deeper language coverage, private-repository integration, reachability, containers/IaC, policy management, pull-request enforcement, or package-behavior intelligence. VoidGuard's utility is immediate public-repository review, transparent evidence, explicit uncertainty, and tightly constrained autonomous proposals.

## What it checks

| MECE area | Current bounded checks |
| --- | --- |
| Credentials | OpenAI-, npm-, Slack-, Stripe-, Google-, GitHub-, GitLab-, and AWS-shaped keys/tokens, private keys, credential URLs, and credential assignments; raw values are never persisted |
| Code execution | Dynamic JavaScript evaluation and shell-command execution surfaces |
| Browser injection | Raw HTML rendering surfaces requiring sanitizer review |
| Transport and crypto | Disabled TLS certificate verification; MD5/SHA-1 security usage |
| Authentication/session | Client-controlled localStorage used as authentication authority |
| Cross-origin policy | Wildcard CORS response configuration |
| CI/CD privilege | `pull_request_target` and `permissions: write-all` workflows |
| Release controls | TypeScript or lint failures suppressed during production builds |
| Supply-chain integrity | Missing/incomplete lockfiles, mutable dependency selectors, unproven ranges |
| Published dependencies | Exact installed-version status from a fresh search of NVD, GitHub Advisory Database, OSV, and registry evidence |

Findings are evidence-backed issues or review surfaces, not automatic proof of exploitability. See the full implemented/planned MECE boundary in [`SECURITY_COVERAGE.md`](./SECURITY_COVERAGE.md).

## Freshness contract

Every provider request receives the current assessment date at runtime.

- Model memory is never evidence.
- Grounding performs fresh web search for every exact package/version.
- Conclusions are `AFFECTED`, `UNAFFECTED`, or `UNKNOWN`.
- Missing, stale, ambiguous, or conflicting evidence is `UNKNOWN`, never “safe.”
- Citations are persisted only when the URL appeared in the current OpenAI Responses web-search source records and matches an authoritative advisory host/path.
- Fixed versions must be exact SemVer values explicitly supported by current observed evidence.
- Remediation and independent QA use centralized, dated, fail-closed instruction contracts.
- Deterministic patch validation remains authoritative.

## Trust and safety boundaries

- Public repositories only. Private repositories are unsupported; do not publish sensitive code solely to scan it.
- Public eligibility is proved without ambient private GitHub authority.
- Branches are resolved to immutable commit SHAs before tree/content reads.
- Repository size, tree completeness, file count, path types, encoded content, decoded bytes, and total outputs are bounded.
- The current audit selects at most 40 risk-prioritized eligible files.
- Anonymous browser capabilities are stored server-side only as secret-derived digests.
- Expensive work requires proof of work, atomic global capacity claiming, per-session quotas, renewable leases, and stale-run cleanup.
- Provider or required workflow failures cannot be reported as completed.
- Generated patches remain unapplied proposals and never auto-merge.

## Architecture

```text
Browser capability session
        |
        v
Convex scan state machine ----> immutable public GitHub snapshot
        |                                  |
        |                                  v
        |                      bounded deterministic scanners
        |                                  |
        v                                  v
OpenAI Responses web search --> source-bound exact-version evidence
        |
        v
RemediationWriter --> independent QA --> deterministic patch validator
        |
        v
Live logs, findings, citations, risk decisions
```

- Next.js static frontend on Cloudflare Pages
- Convex state, actions, queries, mutations, leases, and real-time updates
- OpenAI Responses API web search, optionally through Cloudflare AI Gateway
- GitHub API reads pinned to a commit

## Comparison with established tools

| Tool/category | Where it is stronger | VoidGuard's distinct utility |
| --- | --- | --- |
| GitHub Dependabot / secret scanning / CodeQL | Native repository integration, PR automation, broad CodeQL dataflow, push protection | No-login public triage with one evidence timeline and explicit uncertainty |
| Semgrep | Large rule ecosystem, custom rules, CI and editor integration | Turnkey public URL flow with live advisory grounding and constrained proposals |
| Snyk | Commercial developer workflows across code, dependencies, containers, IaC | Open demo surface and transparent source-bound reasoning without account setup |
| OSV-Scanner / Trivy | Fast deterministic CLI coverage across ecosystems, containers, SBOMs, IaC | Human-readable autonomous investigation and citations in a browser workspace |
| Socket | Rich package behavior and supply-chain intelligence | Repository-level synthesis across code/config signals and exact advisory evidence |

Official references:
- GitHub code security: https://docs.github.com/en/code-security
- Semgrep documentation: https://semgrep.dev/docs/
- Snyk documentation: https://docs.snyk.io/
- OSV-Scanner: https://google.github.io/osv-scanner/
- Trivy: https://trivy.dev/latest/
- Socket: https://docs.socket.dev/

## Honest limitations

VoidGuard currently does not provide complete SAST, whole-program dataflow, DAST, runtime reachability, exploitability proof, malware analysis, container/SBOM/IaC coverage, private-repository authorization, or automatic patch application. Regex-backed static findings are high-signal review surfaces and require human validation. The 40-file bound is disclosed in the UI and logs.

## Local development

```bash
npm install
npx convex dev
npm run dev
```

Required deployment configuration names:

- `NEXT_PUBLIC_CONVEX_URL`
- `OPENAI_API_KEY`
- `GITHUB_TOKEN` (used only after anonymous public-read eligibility is established)
- `ANONYMOUS_SESSION_SECRET`
- Optional Cloudflare AI Gateway identifiers/token
- Optional `VOIDGUARD_GROUNDING_MODEL`, `VOIDGUARD_REMEDIATION_MODEL`, and `VOIDGUARD_QA_MODEL`

Never commit environment values.

## Verification

```bash
npm test
npm run lint
npm run typecheck
NEXT_PUBLIC_CONVEX_URL=https://calculating-husky-954.convex.cloud npm run build
```

CI runs the same core gates on pushes and pull requests.
