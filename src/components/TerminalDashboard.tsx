"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleDotDashed,
  ExternalLink,
  GitBranch,
  Globe2,
  History,
  ScanLine,
  ShieldAlert,
  Terminal,
} from "lucide-react";

const DEFAULT_REPO = "https://github.com/NARESH047/voidguard-fixture";
const SESSION_KEY = "voidguard-anonymous-session";
const SESSION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const statusCopy: Record<string, string> = {
  initialized: "Queued",
  scanning_secrets: "Bounded secrets pass",
  auditing_dependencies: "Dependency recon",
  writing_remediations: "Drafting proposal",
  verifying: "Independent verification",
  completed: "Complete",
  failed: "Failed",
};

function isGitHubRepositoryUrl(value: string) {
  try {
    const url = new URL(value.trim());
    const segments = url.pathname.split("/").filter(Boolean);
    return url.protocol === "https:" && url.hostname.toLowerCase() === "github.com" && segments.length === 2;
  } catch {
    return false;
  }
}

function browserSessionToken() {
  const existing = sessionStorage.getItem(SESSION_KEY);
  if (existing && SESSION_PATTERN.test(existing)) return existing;
  const token = crypto.randomUUID();
  sessionStorage.setItem(SESSION_KEY, token);
  return token;
}

async function solveAuditProof(sessionToken: string, scanId: string) {
  const encoder = new TextEncoder();
  const batchSize = 256;
  for (let batchStart = 0; batchStart < 1_000_000; batchStart += batchSize) {
    const candidates = Array.from({ length: batchSize }, (_, index) => batchStart + index);
    const digests = await Promise.all(candidates.map((nonce) => crypto.subtle.digest("SHA-256", encoder.encode(`${sessionToken}:${scanId}:${nonce}`))));
    const match = digests.findIndex((digest) => {
      const bytes = new Uint8Array(digest);
      return bytes[0] === 0 && bytes[1] < 64;
    });
    if (match >= 0) return String(candidates[match]);
  }
  throw new Error("Unable to complete the audit challenge.");
}

export function TerminalDashboard() {
  const createScan = useMutation(api.mutations.createScan);
  const acceptRisk = useMutation(api.mutations.acceptRisk);
  const runAudit = useAction(api.security_lead.runAutonomousAudit);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  useEffect(() => {
    const stored = sessionStorage.getItem(SESSION_KEY);
    if (stored && SESSION_PATTERN.test(stored)) queueMicrotask(() => setSessionToken(stored));
  }, []);
  const recentScans = useQuery(api.mutations.listRecentScans, sessionToken ? { sessionToken } : "skip");
  const [repoUrl, setRepoUrl] = useState(DEFAULT_REPO);
  const [activeScanId, setActiveScanId] = useState<Id<"scans"> | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [riskFindingId, setRiskFindingId] = useState<Id<"findings"> | null>(null);
  const [riskReason, setRiskReason] = useState("");
  const [riskError, setRiskError] = useState("");
  const logViewport = useRef<HTMLDivElement>(null);

  const selectedScanId = activeScanId && recentScans?.some((item) => item._id === activeScanId)
    ? activeScanId
    : recentScans?.[0]?._id ?? null;
  const queryArgs = sessionToken && selectedScanId ? { scanId: selectedScanId, sessionToken } : "skip";
  const scan = useQuery(api.mutations.getScan, queryArgs);
  const logs = useQuery(api.mutations.getScanLogs, queryArgs);
  const findings = useQuery(api.mutations.getScanFindings, queryArgs);

  useEffect(() => {
    if (logViewport.current) logViewport.current.scrollTop = logViewport.current.scrollHeight;
  }, [logs]);

  const repoLabel = useMemo(() => {
    try {
      const url = new URL(repoUrl);
      return `${url.hostname}${url.pathname.replace(/\/$/, "")}`;
    } catch {
      return repoUrl || "github.com/owner/repository";
    }
  }, [repoUrl]);

  const startAudit = async () => {
    if (running) return;
    if (!isGitHubRepositoryUrl(repoUrl)) {
      setError("Enter a valid public GitHub repository URL, for example https://github.com/owner/repository.");
      return;
    }
    setRunning(true);
    setError("");
    try {
      const token = sessionToken ?? browserSessionToken();
      if (!sessionToken) setSessionToken(token);
      const scanId = await createScan({ repoUrl, sessionToken: token });
      setActiveScanId(scanId);
      const proofNonce = await solveAuditProof(token, scanId);
      await runAudit({ scanId, sessionToken: token, proofNonce });
    } catch (caught) {
      const message = caught instanceof Error ? caught.message.toLowerCase() : "";
      if (message.includes("capacity")) setError("VoidGuard is at hourly capacity. Please try again later.");
      else if (message.includes("active scan")) setError("This tab already has an active scan. Let it finish before starting another.");
      else if (message.includes("valid https github")) setError("Enter a valid public GitHub repository URL, for example https://github.com/owner/repository.");
      else if (message.includes("publicly accessible") || message.includes("not accessible") || message.includes("not found")) setError("Repository unavailable. If it is private, make it public on GitHub, then paste its public link.");
      else setError("The audit could not start. Verify the public GitHub URL and try again.");
    } finally {
      setRunning(false);
    }
  };

  const submitRisk = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!riskFindingId || !sessionToken) return;
    setRiskError("");
    try {
      await acceptRisk({ findingId: riskFindingId, reason: riskReason, sessionToken });
      setRiskFindingId(null);
      setRiskReason("");
    } catch (caught) {
      setRiskError(caught instanceof Error ? caught.message : "Unable to record this decision.");
    }
  };

  return (
    <div className="workspace-shell">
      <div className="workspace-toolbar">
        <div className="flex items-center gap-2"><span className="window-dot bg-[#ff6b6b]" /><span className="window-dot bg-[#e8b84c]" /><span className="window-dot bg-[#43c887]" /></div>
        <span className="flex items-center gap-2 text-xs text-[#8a8f98]"><Terminal size={14} /> voidguard / public operations</span>
        <span className="flex items-center gap-2 text-xs text-[#9da4ff]"><Globe2 size={13} /> open access</span>
      </div>

      <div className="border-b border-white/[0.06] p-5 md:p-7">
        <div className="mb-5 flex flex-col justify-between gap-3 md:flex-row md:items-end">
          <div><div className="workspace-kicker">Repository target</div><h3 className="mt-1 text-xl font-medium tracking-[-0.025em] text-[#f7f8f8]">Start a public security audit</h3></div>
          <div className="public-repo-pill"><Globe2 size={13} /> Public GitHub repositories only</div>
        </div>
        <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
          <label className="repo-input" htmlFor="repo-target">
            <GitBranch size={17} className="shrink-0 text-[#8d8cff]" />
            <input id="repo-target" aria-label="Public GitHub repository URL" value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} placeholder="https://github.com/owner/repository" />
          </label>
          <button onClick={() => void startAudit()} disabled={running} className="primary-button justify-center px-5 py-3 text-sm disabled:cursor-not-allowed disabled:opacity-60">
            {running ? <><Activity size={15} className="animate-pulse" /> Crew investigating</> : <><ScanLine size={15} /> Run public audit <ArrowUpRight size={14} /></>}
          </button>
        </div>
        <div className="mt-3 flex flex-col justify-between gap-2 text-xs text-[#8a8f98] sm:flex-row">
          <span>{repoLabel}</span>
          <span>Private repository? Make it public first, then share its GitHub link.</span>
        </div>
        {error && <p role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-[#ff7272]/20 bg-[#ff7272]/[0.06] px-3 py-2.5 text-sm text-[#ffaaaa]"><AlertTriangle size={15} className="mt-0.5 shrink-0" /> {error}</p>}
      </div>

      <div className={`grid transition-[min-height] ${scan ? "min-h-[610px]" : "min-h-[430px]"} lg:grid-cols-[220px_1fr_370px]`}>
        <aside className="border-b border-white/[0.06] p-4 lg:border-b-0 lg:border-r">
          <div className="mb-4 flex items-center gap-2 px-2 text-[11px] uppercase tracking-[0.14em] text-[#8a8f98]"><History size={13} /> This tab</div>
          <div className="flex gap-2 overflow-x-auto lg:flex-col lg:overflow-visible">
            {sessionToken && recentScans === undefined ? <p className="px-2 text-xs leading-5 text-[#8a8f98]">Restoring this tab’s scans…</p> : recentScans?.length ? recentScans.map((item) => (
              <button key={item._id} onClick={() => setActiveScanId(item._id)} className={`min-w-44 rounded-lg border px-3 py-3 text-left transition lg:min-w-0 ${selectedScanId === item._id ? "border-[#7170ff]/40 bg-[#7170ff]/[0.08]" : "border-transparent hover:bg-white/[0.03]"}`}>
                <div className="truncate text-xs text-[#d0d6e0]">{item.repoUrl.replace("https://github.com/", "")}</div>
                <div className="mt-2 flex items-center justify-between text-[10px] text-[#8a8f98]"><span>{statusCopy[item.status]}</span><ChevronRight size={12} /></div>
              </button>
            )) : <p className="px-2 text-xs leading-5 text-[#8a8f98]">Your scans appear here after you run one.</p>}
          </div>
        </aside>

        <section className="border-b border-white/[0.06] p-5 lg:border-b-0 lg:border-r lg:p-6">
          <div className="mb-4 flex items-center justify-between border-b border-white/[0.06] pb-4">
            <div><div className="workspace-kicker">Live agent stream</div><div className="mt-1 text-sm text-[#f7f8f8]">{scan?.repoUrl.replace("https://github.com/", "") ?? "Awaiting a public repository"}</div></div>
            <span role="status" aria-live="polite" className={`rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${scan?.status === "completed" ? "border-[#43c887]/30 text-[#72dca0]" : scan?.status === "failed" ? "border-[#ff7272]/30 text-[#ff9a9a]" : "border-[#7170ff]/30 text-[#9da4ff]"}`}>{scan ? statusCopy[scan.status] : "waiting"}</span>
          </div>
          <div ref={logViewport} aria-live="polite" aria-busy={Boolean(selectedScanId && logs === undefined)} className={`${scan ? "h-[460px]" : "h-[280px]"} overflow-y-auto pr-2 font-mono text-xs leading-6 transition-[height]`}>
            {selectedScanId && logs === undefined ? <div className="flex h-full items-center justify-center text-[#8a8f98]">Loading agent stream…</div> : logs?.length ? logs.map((log, index) => (
              <div key={log._id} className="agent-log flex gap-3" style={{ animationDelay: `${Math.min(index, 12) * 35}ms` }}>
                <span className="w-28 shrink-0 truncate text-[#8a8f98]">{log.agent}</span>
                <span className={log.level === "error" ? "text-[#ff9a9a]" : log.level === "success" ? "text-[#72dca0]" : log.level === "warning" ? "text-[#e8b84c]" : "text-[#aeb4bd]"}>{log.message}</span>
              </div>
            )) : <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-[#8a8f98]"><CircleDotDashed size={24} /><span>Paste any public GitHub repository and launch the crew.</span></div>}
          </div>
        </section>

        <aside className="p-5 lg:p-6">
          <div className="mb-4 flex items-center justify-between"><div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.14em] text-[#8a8f98]"><ShieldAlert size={14} /> Findings</div><span aria-live="polite" className="text-2xl font-medium text-[#f7f8f8]">{findings?.length ?? "—"}</span></div>
          <div className="max-h-[520px] space-y-3 overflow-y-auto pr-1">
            {findings?.length ? findings.map((finding) => (
              <article key={finding._id} className="finding-card">
                <div className="flex items-center justify-between gap-3"><SeverityBadge severity={finding.severity} /><span className="truncate text-[10px] text-[#8a8f98]">{finding.filePath}</span></div>
                <h3 className="mt-3 text-sm font-medium leading-5 text-[#e2e4e7]">{finding.description}</h3>
                <p className="mt-2 rounded-md bg-black/25 p-2 font-mono text-[10px] leading-5 text-[#9da4ab]">{finding.evidence}</p>
                {finding.citations?.length ? <div className="mt-3 space-y-1">{finding.citations.map((citation) => <a key={citation.url} href={citation.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[10px] text-[#9da4ff] hover:text-[#b8b7ff]"><ExternalLink size={10} /> {citation.title}</a>)}</div> : null}
                {finding.remediationPatch ? <details className="mt-3"><summary className="cursor-pointer text-[11px] text-[#9da4ff]">Verified remediation proposal</summary><pre className="mt-2 max-h-48 overflow-auto rounded-md bg-black/35 p-2 text-[10px] leading-5 text-[#b7bad9]">{finding.remediationPatch}</pre></details> : null}
                {finding.status === "open" && scan?.status === "completed" && <button onClick={() => { setRiskFindingId(finding._id); setRiskReason(""); setRiskError(""); }} className="mt-2 -ml-2 rounded-md px-2 py-2 text-xs text-[#8a8f98] hover:bg-white/[0.04] hover:text-[#e8b84c]">Document accepted risk</button>}
                {finding.status === "accepted_risk" && <div className="mt-3 flex items-center gap-1 text-[10px] text-[#e8b84c]"><CheckCircle2 size={11} /> Accepted risk</div>}
              </article>
            )) : selectedScanId && findings === undefined ? <div className="flex min-h-56 items-center justify-center text-xs text-[#8a8f98]">Loading findings…</div> : !selectedScanId ? <div className="flex min-h-56 flex-col items-center justify-center gap-3 text-center text-xs leading-5 text-[#8a8f98]"><CircleDotDashed size={24} /><span>Run an audit to see findings.</span></div> : <div className="flex min-h-56 flex-col items-center justify-center gap-3 text-center text-xs leading-5 text-[#8a8f98]"><CheckCircle2 size={24} /><span>No findings in this scan.</span></div>}
          </div>
        </aside>
      </div>

      {riskFindingId && sessionToken && <div className="border-t border-white/[0.06] bg-[#0b0c0e] p-5"><form onSubmit={submitRisk} className="mx-auto flex max-w-3xl flex-col gap-3 sm:flex-row sm:items-end"><label className="field-label flex-1">Risk acceptance reason<input required minLength={10} maxLength={1000} value={riskReason} onChange={(event) => setRiskReason(event.target.value)} placeholder="Document why this risk is acceptable…" /></label><button className="primary-button justify-center px-4 py-3 text-sm">Record decision</button><button type="button" onClick={() => setRiskFindingId(null)} className="subtle-button justify-center">Cancel</button></form>{riskError && <p role="alert" className="mx-auto mt-2 max-w-3xl text-xs text-[#ff9a9a]">{riskError}</p>}</div>}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }) {
  const className = severity === "CRITICAL" ? "severity-critical" : severity === "HIGH" ? "severity-high" : severity === "MEDIUM" ? "severity-medium" : "severity-low";
  return <span className={`rounded px-2 py-1 text-[9px] font-semibold tracking-wider ${className}`}>{severity}</span>;
}
