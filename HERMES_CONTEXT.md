# VoidGuard AI Workspace

## Product
VoidGuard AI is an authenticated security operations workspace deployed as a static Next.js frontend on Cloudflare Pages with a Convex backend. It performs bounded, read-only GitHub repository acquisition, local secret-pattern detection with evidence redaction, OpenAI web-grounded dependency analysis, remediation generation, independent QA verification, and auditable risk acceptance.

## Core architecture
- `app/page.tsx` — focused marketing shell and authenticated workspace entry.
- `src/components/AuthDialog.tsx` — Convex Auth email/password signup and login.
- `src/components/TerminalDashboard.tsx` — real-time scan history, agent logs, findings, citations, patches, and risk decisions.
- `convex/schema.ts` — auth, waitlist, scans, scan logs, findings, and risk-register tables.
- `convex/mutations.ts` — authorized scan/read/write functions and internal orchestration mutations.
- `convex/security_lead.ts` — bounded multi-agent orchestration action.
- `convex/github.ts` — bounded GitHub API repository acquisition.
- `convex/grounding.ts` — OpenAI Responses API web-search grounding with authoritative-domain validation.
- `convex/lib/security.ts` — repository URL validation, dependency extraction, and redacted secret detection.

## Security invariants
- Secrets and provider credentials live only in Convex environment variables.
- Raw credential matches are never written to Convex or sent to model providers.
- Scan, log, finding, and risk-register access is checked against the authenticated identity.
- Repository acquisition is limited to public repositories and bounded by file count, file size, repository size, and extension allowlists. Private repositories require future per-user GitHub App authorization.
- GitHub reads are pinned to one commit and decoded content is rechecked against the byte limit.
- Dependency findings require exact-version output and authoritative HTTPS citations.
- Citation URLs must match source records emitted by the Responses web-search tool.
- Dependency versions come from package-lock.json when available; unproven ranges are skipped.
- Generated patches require a separate QA verdict, deterministic package/version validation, and remain review-only.
- Provider or grounding failures mark the scan failed rather than presenting a partial audit as complete.
- Each account is limited to one active scan and five scans per rolling hour.
- Production environment values must never be copied into repository files.

## Verification
- `npm test`
- `npm run lint`
- `npm run typecheck`
- `npm run build`
