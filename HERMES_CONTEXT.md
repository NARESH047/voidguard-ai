# VoidGuard AI Workspace

## Product
VoidGuard AI is an open, no-login security operations workspace deployed as a static Next.js frontend on Cloudflare Pages with a Convex backend. Anyone can paste a public GitHub repository link and run a bounded read-only audit.

## Architecture
- `app/page.tsx`: public Linear-inspired product shell and primary workspace entry.
- `src/components/TerminalDashboard.tsx`: anonymous repository input, scan history for the current browser tab, live logs, findings, citations, proposals, and risk decisions.
- `convex/mutations.ts`: capability-session isolation, quotas, legal state transitions, logs, findings, and risk-register writes.
- `convex/security_lead.ts`: bounded autonomous orchestration.
- `convex/github.ts`: public-only, commit-pinned GitHub acquisition.
- `convex/grounding.ts`: OpenAI Responses API web-search grounding with observed-source validation.
- `convex/lib/security.ts`: URL parsing, redaction, exact dependency extraction, and deterministic patch validation.

## Public access model
- No account or login is required.
- Each browser tab receives a random UUID capability stored in `sessionStorage` when its first scan starts.
- Scan documents never expose the stored capability owner key.
- Each capability can have one active scan and five scans per rolling hour.
- The deployment allows at most 30 new scans per rolling hour across all visitors.
- Private repositories are rejected. Visitors must make a repository public on GitHub before sharing its link.

## Security invariants
- Raw credential matches are never persisted or sent to model providers.
- Repository acquisition is public-only, pinned to one commit, bounded by repository size, file count, response size, decoded bytes, and extension allowlists.
- Exact dependency versions use SemVer-compliant validation; unsafe manifest and lockfile metadata is rejected.
- Persisted citations must be authoritative and match observed Responses web-search sources.
- Generated patches require separate model QA plus deterministic one-dependency/one-version validation and remain review-only.
- Provider failures make the scan fail rather than presenting partial work as complete.
- Active scans use renewable leases; stale attempts restart cleanly and terminal states cannot be rewritten.

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
