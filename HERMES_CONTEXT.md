# Hermes Hackathon Workspace Context File

## 1. Project Overview & Architecture
* **Project Name:** `hermes-hack-speedrun`
* **Frontend:** Next.js (App Router, Tailwind CSS, Dark Mode theme optimized).
* **Backend Database:** Convex Serverless Runtime (Reactive client hooks, real-time data push engine).
* **AI Routing Layer:** Cloudflare AI Gateway proxy (`hermes-build`) configured with Authenticated Gateway enabled for secure infrastructure protection.
* **Core Thinking Engine:** Nous Research Hermes 3 405B (via OpenRouter edge credentials).

---

## 2. Current Infrastructure Status
* ✅ Frontend-to-Backend handshake verified and operational.
* ✅ Cloudflare Edge Proxy handshake verified with live `401 -> 200` security resolution.
* ✅ Live integration test passed completely through the network stack (`OpenAI Response: "Pong!"`).
* ✅ Terminal AI environment activated via global CLI hooks (`gpt-5.4-mini` target selected for high-speed workspace manipulation).

---

## 3. Secure Environment Configurations (Stored Natively in Convex Vault)
* `CLOUDFLARE_ACCOUNT_ID` -> `986881b81dc08bfce4036726679e4005`
* `CLOUDFLARE_GATEWAY_ID` -> `hermes-build`
* `OPENAI_API_KEY` -> Active / Validated (Stored via Provider Keys + Dashboard)
* `CLOUDFLARE_API_TOKEN` -> Active (Authorizing custom headers securely)
* `OPENROUTER_API_KEY` -> Target execution allocation token configured

---

## 4. Completed File Inventory & Code Maps

### A. Core Database Provider (`components/Provider.tsx`)
Binds the Next.js component tree to the real-time serverless client runtime.

### B. Root Layout Wrapper (`app/layout.tsx`)
Houses global CSS states and provisions the `DatabaseProvider` to the global application layout context.

### C. Serverless Multi-Agent Orchestration Backend (`convex/ai.ts`)
* Implements explicit TypeScript global object injection parameters via `declare var process`.
* Contains `runLiveDiagnostic` action (OpenAI pipeline integration validator).
* Contains `writeAgentLog` mutation (Real-time tracking layer writing directly to database).
* Contains `executeAgencyWorkflow` framework (A three-tier autonomous pipeline using **Linkup Web Search API**, a **Hermes 3 Writer**, and a **Hermes 3 Critic** agent step).

### D. Data Mutation Pipeline (`convex/projects.ts`)
* `startNewCampaign` -> Initializes background execution workflow context records.
* `streamLiveLogs` -> Queries and exports operational sequences reactively ordered by descending timeline metrics.

### E. Agent Control Panel Fronted UI (`app/page.tsx`)
A dark-mode layout providing text input hooks to fire the full background Multi-Agent loops, streaming logs instantly to the browser canvas via Convex `useQuery` bindings without reloading pages.

---

## 5. Next Execution Strategy
We are prepared to target one of the primary hackathon tracks:
1. **Virality Track:** Auto-generating looping "build in public" social hooks.
2. **Revenue Track:** Tying dynamic value delivery straight to real-time transactional webhooks.
3. **AI Agency Track:** Expanding the `convex/ai.ts` multi-agent loops into deeply custom, autonomous roleplay workflows.