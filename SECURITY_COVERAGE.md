# Security Coverage Matrix

VoidGuard is a bounded public-repository triage system. This matrix separates what is implemented from what is possible, avoiding the misleading claim that regex checks or an LLM constitute complete security analysis.

Status:
- **Implemented** — deterministic or source-bound behavior runs today.
- **Partial** — selected high-signal patterns run, but complete analysis requires deeper semantics.
- **Planned** — not currently flagged; listed to define the product boundary.

| MECE domain | Vulnerability classes | Status | Current / required evidence |
| --- | --- | --- | --- |
| 1. Identity and access control | Client-side auth, missing authorization, IDOR/BOLA, privilege escalation, insecure session lifecycle, weak recovery | Partial | Client-controlled localStorage auth is deterministic. Endpoint-level authorization and object-level access require framework-aware route/dataflow analysis and authenticated tests. |
| 2. Secrets and credentials | API keys, cloud keys, SCM tokens, private keys, passwords, credential assignments, secret history | Implemented / Partial | Current-file credential patterns are redacted. Git history, entropy analysis, provider verification, and push protection are not implemented. |
| 3. Injection and unsafe execution | Code/command injection, SQL/NoSQL injection, XSS, template injection, path traversal, SSRF, unsafe deserialization, XXE, open redirects | Partial | Dynamic JS, child-process execution, and raw HTML surfaces are flagged. Taint/dataflow confirmation for source-to-sink exploitability is planned. |
| 4. Cryptography and transport | Disabled TLS verification, weak hashes/ciphers, insecure randomness, key/nonce reuse, certificate validation | Partial | Explicit TLS bypass and MD5/SHA-1 use are flagged. Cryptographic protocol correctness requires semantic review. |
| 5. Data protection and privacy | PII exposure, insecure browser storage, sensitive logging, missing encryption, over-retention, unsafe telemetry | Planned / Partial | Credential evidence is never persisted raw. General PII classification, dataflow, retention, and log-sink analysis are planned. |
| 6. Security configuration | Wildcard CORS, debug/admin exposure, unsafe headers, framework bypasses, permissive uploads, insecure defaults | Partial | Wildcard CORS and disabled build validation are flagged. Framework-specific header/CSP/cookie/upload policies are planned. |
| 7. Dependencies and software supply chain | Known CVEs, missing/incomplete lockfiles, mutable selectors, dependency confusion, typosquatting, malicious packages, provenance/signature gaps | Implemented / Partial | Exact versions receive fresh source-bound advisory searches; integrity gaps are deterministic. Package behavior, provenance, reachability, and confusion analysis require dedicated registries/tools. |
| 8. CI/CD and repository governance | Privileged PR workflows, overbroad tokens, unpinned actions, artifact poisoning, unsafe checkout, branch/ruleset gaps | Partial | `pull_request_target` and `write-all` are flagged. Action-SHA pinning, untrusted checkout/dataflow, environment protection, and ruleset API analysis are planned. |
| 9. Cloud, infrastructure, containers, and IaC | Public storage, open security groups, IAM privilege, exposed services, vulnerable images, Kubernetes policy, Terraform drift | Planned | Requires Dockerfile/SBOM/image, Terraform/CloudFormation, Kubernetes, and cloud-control-plane analyzers. |
| 10. Application and business logic | Race conditions, replay, payment/account abuse, workflow bypass, state-machine flaws, tenant isolation | Planned | Requires product-specific invariants, authenticated scenario tests, and often runtime instrumentation. |
| 11. Availability and resource abuse | ReDoS, decompression bombs, unbounded loops/queries/uploads, rate-limit gaps, algorithmic complexity, queue exhaustion | Partial | VoidGuard itself enforces repository/output bounds, quotas, claims, proof of work, and leases. Target-repository DoS analysis is planned. |
| 12. AI/LLM-specific security | Prompt injection, tool abuse, unsafe output handling, data exfiltration, model denial of wallet, poisoning, ungrounded claims | Partial | VoidGuard treats repository/source/model text as untrusted, binds citations to observed search records, constrains patches, and fails closed. Target-repository AI flows require dedicated source/sink analysis and adversarial evaluation. |
| 13. Client and platform security | DOM clobbering, postMessage misuse, service-worker scope, extension/mobile IPC, deep links, native storage | Planned | Requires platform-specific AST and runtime rules. |
| 14. Runtime validation | Exploitability, reachability, deployed headers, live endpoints, auth behavior, network exposure | Planned | Requires DAST, IAST, sandbox execution, or an authorized deployed target. Repository evidence alone cannot prove runtime behavior. |

## Severity and claim policy

- **Confirmed issue:** deterministic evidence directly establishes the unsafe construct or authoritative exact-version evidence establishes affected status.
- **Review surface:** the construct can be safe with additional controls; human validation is required.
- **Unknown:** current evidence cannot prove affected or unaffected status. Unknown is never represented as safe.
- **Not inspected:** outside file, size, language, repository, or runtime bounds. Absence of a finding is not proof of absence.

## Prioritized roadmap

1. AST-backed JavaScript/TypeScript rules with source-to-sink taint for injection, SSRF, traversal, redirect, and auth checks.
2. GitHub Actions analyzer for untrusted checkout, expression injection, action SHA pinning, token scopes, and artifact trust.
3. OSV-Scanner/SBOM integration for deterministic multi-ecosystem advisory coverage and reachability metadata.
4. Semgrep or CodeQL adapter for broader language/dataflow coverage while retaining VoidGuard's evidence timeline.
5. IaC/container analyzers (for example Trivy) with normalized findings.
6. Authorized DAST mode for deployed URLs, explicit consent, safe request budgets, and no destructive tests.
7. GitHub App authorization for tenant-safe private-repository support and pull-request delivery.
8. Rule identifiers, CWE/OWASP mappings, suppression/baseline workflows, SARIF export, and CI enforcement.

## Non-goals today

VoidGuard does not claim formal verification, complete SAST, exploitability proof, malware detection, secret-history scanning, private-repository coverage, or automatic remediation. It is a transparent triage and evidence-synthesis layer designed to complement established scanners.
