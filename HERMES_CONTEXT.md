# Hermes Hackathon Workspace Blueprint

## 1. System Stack
* **Frontend Architecture:** Next.js framework (App Router, Tailwind CSS layout, dark theme optimization).
* **Database Runtime:** Convex Serverless Cloud Architecture (Reactive data streams, real-time client mutations).
* **Routing Pipeline:** Cloudflare AI Gateway proxy infrastructure ("hermes-build") handling request mapping.
* **Core Inference Brain:** Nous Research Hermes 3 405B model parameters (routed via OpenRouter API hooks).

---

## 2. Code Map
* `components/Provider.tsx` — Connects the Next.js application layer to the Convex backend context.
* `app/layout.tsx` — Top-level styling wrapper provisioning the global database state provider.
* `convex/ai.ts` — Serverless execution file housing the infrastructure validation check, real-time logging mutations, and a three-tier Multi-Agent pipeline (Web Search Tool Integration -> Hermes Writer Agent -> Hermes Critic Agent).
* `convex/projects.ts` — Data operations file mapping campaign session creation records and streaming live agent logs reactively by descending order.
* `app/page.tsx` — Interactive command panel frontend dashboard streaming database operation updates natively to the browser view via reactive server hooks.

---

## 3. Non-Sensitive Notes
* **Variable Safety:** All routing keys, API connection endpoints, and provider tokens are locked inside the isolated Convex online dashboard environment vault. No plaintext access codes, secret tokens, or raw credentials exist anywhere inside local repository workspace files.
* **TypeScript Settings:** The workspace includes an explicit global environmental injection layout block (`declare var process`) ensuring compiler compatibility inside cloud edge runtime boundaries.
* **Pipeline Status:** Verified green across all metrics. The core integration diagnostic, endpoint proxy connection parameters, and terminal agent auto-execution overrides are completely operational.