# VoidGuard AI Workspace

## Product
VoidGuard AI is an open, no-login security operations workspace deployed as a static Next.js frontend on Cloudflare Pages with a Convex backend. Anyone can paste a public GitHub repository link and run a bounded read-only audit.

## Architecture
- `app/page.tsx`: public Linear-inspired product shell and primary workspace entry.
- `src/components/TerminalDashboard.tsx`: anonymous repository input, scan history for the current browser tab, live logs, findings, citations, proposals, and risk decisions.
- `convex/mutations.ts`: capability-session isolation, quotas, legal state transitions, logs, findings, and risk-register writes.
- `convex/security_lead.ts`: bounded autonomous orchestration.
- `convex/github.ts`: public-only, commit-pinned GitHub acquisition with risk-prioritized bounded file selection.
- `convex/grounding.ts`: dated OpenAI Responses web-search grounding with `AFFECTED` / `UNAFFECTED` / `UNKNOWN` conclusions and observed-source validation.
- `convex/lib/instructions.ts`: canonical dated RemediationWriter and independent QA instruction contracts.
- `convex/lib/security.ts`: URL parsing, secret redaction, deterministic static checks, dependency-integrity checks, exact dependency extraction, and deterministic patch validation.

## Public access model
- No account or login is required.
- Each browser tab receives a random UUID capability stored in `sessionStorage`; it is restored after reload.
- Scan documents store only a server-secret-derived digest of that capability and never return it to clients.
- Starting expensive work requires a scan-bound SHA-256 proof-of-work challenge; global capacity is charged only when the audit is atomically claimed.
- Each capability can have one active scan and five scans per rolling hour.
- The deployment allows at most 30 claimed audits per rolling hour across all visitors.
- Private repositories are rejected and unsupported. Visitors must not publish sensitive code solely to scan it.
- Public eligibility is probed without the ambient GitHub token; only confirmed-public repositories may use the token for subsequent quota-efficient reads.

## Security invariants
- Raw credential matches are never persisted or sent to model providers.
- Repository acquisition is public-only, pinned to one commit, bounded by repository size, file count, response size, decoded bytes, and extension allowlists. The commit, stable audit timestamp, eligible/inspected/omitted counts, and branch are persisted and shown in the workspace.
- Exact dependency versions use SemVer-compliant validation; unsafe manifest and lockfile metadata is rejected.
- Persisted citations must be authoritative and match observed Responses web-search sources.
- Generated patches require separate model QA plus deterministic one-dependency/one-version validation and remain review-only.
- Provider failures make the scan fail rather than presenting partial work as complete.
- Active scans use renewable leases; stale attempts restart cleanly and terminal states cannot be rewritten.
- Scan output is capped at 250 logs and 100 findings; stale recovery deletes all prior artifacts in bounded pages.

## Freshness and agent-instruction policy
- Every grounding, remediation, and QA request receives an assessment date generated at runtime. Documentation dates are never reused as evidence dates.
- Provider memory is never evidence. Grounding must perform a fresh web search on every exact package/version request.
- Repository content, package metadata, advisory prose, source-page instructions, and model output are untrusted data rather than executable instructions.
- Only current primary records from NVD, GitHub Advisory Database, OSV, or the package maintainer registry may support dependency conclusions.
- `AFFECTED` requires range evidence that includes the exact installed version. `UNAFFECTED` requires explicit exclusion evidence. Missing, stale, ambiguous, or conflicting evidence is `UNKNOWN`, never safe.
- Facts, observed evidence, and inference remain distinct. Persisted citations must match URLs actually returned by the current web-search call.
- Remediation may use only an exact SemVer fixed version supported by current observed evidence. QA is independent and fail-closed; deterministic validation remains authoritative.
- Prompt contracts live in code (`grounding.ts` and `lib/instructions.ts`) with regression tests. This file summarizes behavior but must not duplicate provider-ready prompts.

## Bounded detector matrix
- Credentials: provider-shaped OpenAI, npm, Slack, Stripe, Google, GitHub, GitLab, and AWS keys/tokens; private keys; credential URLs; and credential assignments. All raw values are redacted.
- Code execution: dynamic JavaScript evaluation and shell-command execution surfaces.
- Browser injection: raw HTML rendering surfaces that require sanitizer review.
- Transport and cryptography: disabled TLS verification and MD5/SHA-1 security usage.
- Authentication and session design: client-controlled localStorage used as authentication authority.
- Cross-origin policy: wildcard CORS response configuration.
- CI/CD privilege: `pull_request_target` and `permissions: write-all` workflows.
- Release controls: TypeScript or lint failures suppressed during production builds.
- Supply-chain integrity: incomplete lockfiles, mutable selectors, and unproven dependency ranges.
- Published dependencies: exact-version advisory status with fresh source-bound evidence and explicit unknowns.

These are bounded high-signal checks, not a claim of complete SAST, DAST, reachability analysis, exploitability proof, or formal verification. Findings identify evidence-backed issues or review surfaces; they do not prove exploitability without human validation.

## Verification
```bash
npm test
npm run lint
npm run typecheck
NEXT_PUBLIC_CONVEX_URL=<production-url> npm run build
```

## Production
- Frontend: https://voidguard-ai.pages.dev/
- Application source: https://github.com/NARESH047/voidguard-ai
- Synthetic fixture: https://github.com/NARESH047/voidguard-fixture
