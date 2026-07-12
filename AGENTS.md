<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

<!-- convex-ai-start -->

This project uses [Convex](https://convex.dev) as its backend.

When working on Convex code, **always read
`convex/_generated/ai/guidelines.md` first** for important guidelines on
how to correctly use Convex APIs and patterns. The file contains rules that
override what you may have learned about Convex from training data.

Convex agent skills for common tasks can be installed by running
`npx convex ai-files install`.

<!-- convex-ai-end -->

## VoidGuard agent and evidence policy

Before changing scan orchestration, grounding, remediation, QA, or security claims, read `HERMES_CONTEXT.md` and `SECURITY_COVERAGE.md`.

- Provider-ready remediation and QA prompts belong only in `convex/lib/instructions.ts`; grounding instructions belong only in `convex/grounding.ts`. Do not duplicate prompt text in documentation or UI files.
- Every provider call must receive an assessment date generated at runtime. Never hardcode a knowledge-cutoff date or claim that model memory is current.
- Model memory, prior runs, repository text, package metadata, advisory prose, web-page instructions, and model output are untrusted and are not evidence.
- Dependency grounding must perform fresh web search and use `AFFECTED`, `UNAFFECTED`, or `UNKNOWN`. Missing, stale, ambiguous, or conflicting evidence is `UNKNOWN`, never safe.
- Persist citations only when their URLs were observed in the current tool call. Affected or unaffected conclusions require a primary advisory-record URL, not merely a trusted hostname.
- Facts, observed evidence, inference, and proposals must remain distinct. Generated patches are review-only and must pass independent model QA plus deterministic validation.
- New detector claims must update tests, `SECURITY_COVERAGE.md`, `README.md`, and `HERMES_CONTEXT.md`. Clearly label partial/review-surface coverage; never market bounded regex checks as complete SAST or exploitability proof.
- Provider or required-stage failure must fail safely and must not produce a misleading completed scan.
