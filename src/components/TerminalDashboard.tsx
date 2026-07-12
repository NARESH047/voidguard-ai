"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleDotDashed,
  ExternalLink,
  GitBranch,
  History,
  LockKeyhole,
  ScanLine,
  ShieldAlert,
  Terminal,
} from "lucide-react";

const DEFAULT_REPO = "https://github.com/NARESH047/voidguard-fixture";
const statusCopy: Record<string, string> = {
  initialized: "Queued",
  scanning_secrets: "Bounded secrets pass",
  auditing_dependencies: "Dependency recon",
  writing_remediations: "Writing remediation",
  verifying: "Verifying",
  completed: "Complete",
  failed: "Failed",
};

type Props = {
  isAuthenticated: boolean;
  authLoading: boolean;
  onRequireAuth: () => void;
};

export function TerminalDashboard({ isAuthenticated, authLoading, onRequireAuth }: Props) {
  const createScan = useMutation(api.mutations.createScan);
  const acceptRisk = useMutation(api.mutations.acceptRisk);
  const runAudit = useAction(api.security_lead.runAutonomousAudit);
  const recentScans = useQuery(api.mutations.listRecentScans, isAuthenticated ? {} : "skip");

  const [repoUrl, setRepoUrl] = useState(DEFAULT_REPO);
  const [activeScanId, setActiveScanId] = useState<Id<"scans"> | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [riskFindingId, setRiskFindingId] = useState<Id<"findings"> | null>(null);
  const [riskReason, setRiskReason] = useState("");
  const [riskError, setRiskError] = useState("");
  const logViewport = useRef<HTMLDivElement>(null);

  const selectedScanId = isAuthenticated
    ? (activeScanId && recentScans?.some((item) => item._id === activeScanId) ? activeScanId : recentScans?.[0]?._id ?? null)
    : null;
  const scan = useQuery(api.mutations.getScan, selectedScanId ? { scanId: selectedScanId } : "skip");
  const logs = useQuery(api.mutations.getScanLogs, selectedScanId ? { scanId: selectedScanId } : "skip");
  const findings = useQuery(api.mutations.getScanFindings, selectedScanId ? { scanId: selectedScanId } : "skip");

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
    if (!isAuthenticated) {
      onRequireAuth();
      return;
    }
    if (running) return;
    setRunning(true);
    setError("");
    try {
      const scanId = await createScan({ repoUrl });
      setActiveScanId(scanId);
      await runAudit({ scanId });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to start the audit.");
    } finally {
      setRunning(false);
    }
  };

  const submitRisk = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!riskFindingId) return;
    setRiskError("");
    try {
      await acceptRisk({ findingId: riskFindingId, reason: riskReason });
      setRiskFindingId(null);
      setRiskReason("");
    } catch (caught) {
      setRiskError(caught instanceof Error ? caught.message : "Unable to accept this risk.");
    }
  };

  return (
    <div className="workspace-shell">
      <div className="workspace-toolbar">
        <div className="flex items-center gap-2"><span className="window-dot bg-[#ff6b6b]" /><span className="window-dot bg-[#ffc86b]" /><span className="window-dot bg-[#7bffad]" /></div>
        <span className="flex items-center gap-2 text-xs text-[#7f9089]"><Terminal size={14} /> voidguard / operations</span>
        <span className="text-xs text-[#7bffad]">{isAuthenticated ? "authenticated" : "preview mode"}</span>
      </div>

      <div className="border-b border-white/[0.08] p-5 md:p-7">
        <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
          <label className="repo-input" htmlFor="repo-target">
            <GitBranch size={17} className="shrink-0 text-[#7bffad]" />
            <input id="repo-target" value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} placeholder="https://github.com/owner/repository" />
            <span className="hidden text-xs text-[#5f7169] sm:inline">read only</span>
          </label>
          <button onClick={() => void startAudit()} disabled={running || authLoading} className="primary-button justify-center px-5 py-3 text-sm disabled:cursor-not-allowed disabled:opacity-60">
            {running ? <><Activity size={15} className="animate-pulse" /> Crew investigating</> : <><ScanLine size={15} /> Run audit</>}
          </button>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-[#61716b]">
          <span>{repoLabel}</span>
          <span>40 files max · 120 KB/file · human approval required</span>
        </div>
        {error && <p role="alert" className="mt-4 flex items-center gap-2 text-sm text-[#ff9a9a]"><AlertTriangle size={15} /> {error}</p>}
      </div>

      <div className="grid min-h-[610px] lg:grid-cols-[220px_1fr_360px]">
        <aside className="border-b border-white/[0.08] p-4 lg:border-b-0 lg:border-r">
          <div className="mb-4 flex items-center gap-2 px-2 text-[11px] uppercase tracking-[0.16em] text-[#697a73]"><History size={13} /> Recent scans</div>
          <div className="flex gap-2 overflow-x-auto lg:flex-col lg:overflow-visible">
            {recentScans?.length ? recentScans.map((item) => (
              <button key={item._id} onClick={() => setActiveScanId(item._id)} className={`min-w-44 rounded-lg border px-3 py-3 text-left transition lg:min-w-0 ${selectedScanId === item._id ? "border-[#7bffad]/40 bg-[#7bffad]/[0.06]" : "border-transparent hover:bg-white/[0.03]"}`}>
                <div className="truncate text-xs text-[#b7c5bf]">{item.repoUrl.replace("https://github.com/", "")}</div>
                <div className="mt-2 flex items-center justify-between text-[10px] text-[#62736c]"><span>{statusCopy[item.status]}</span><ChevronRight size={12} /></div>
              </button>
            )) : <p className="px-2 text-xs leading-5 text-[#53645d]">No scans yet.</p>}
          </div>
        </aside>

        <section className="border-b border-white/[0.08] p-5 lg:border-b-0 lg:border-r lg:p-6">
          <div className="mb-4 flex items-center justify-between border-b border-white/[0.08] pb-4">
            <div><div className="text-[11px] uppercase tracking-[0.16em] text-[#61716b]">Agent stream</div><div className="mt-1 text-sm text-white">{scan?.repoUrl.replace("https://github.com/", "") ?? "Awaiting target"}</div></div>
            <span className={`rounded-full border px-2.5 py-1 text-[10px] uppercase tracking-wider ${scan?.status === "completed" ? "border-[#7bffad]/30 text-[#7bffad]" : scan?.status === "failed" ? "border-[#ff7272]/30 text-[#ff8f8f]" : "border-[#ffc86b]/30 text-[#ffc86b]"}`}>{scan ? statusCopy[scan.status] : "idle"}</span>
          </div>
          <div ref={logViewport} className="h-[460px] overflow-y-auto pr-2 font-mono text-xs leading-6">
            {logs?.length ? logs.map((log, index) => (
              <div key={log._id} className="agent-log flex gap-3" style={{ animationDelay: `${Math.min(index, 12) * 35}ms` }}>
                <span className="w-28 shrink-0 truncate text-[#506159]">{log.agent}</span>
                <span className={log.level === "error" ? "text-[#ff8585]" : log.level === "success" ? "text-[#7bffad]" : log.level === "warning" ? "text-[#ffc86b]" : "text-[#a9b9b2]"}>{log.message}</span>
              </div>
            )) : <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-[#52635b]"><LockKeyhole size={24} /><span>{isAuthenticated ? "Run a scan to activate the agent crew." : "Create an account to unlock authenticated scans."}</span></div>}
          </div>
        </section>

        <aside className="p-5 lg:p-6">
          <div className="mb-4 flex items-center justify-between"><div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-[#697a73]"><ShieldAlert size={14} /> Findings</div><span className="text-2xl font-semibold text-white">{findings?.length ?? "—"}</span></div>
          <div className="max-h-[520px] space-y-3 overflow-y-auto pr-1">
            {findings?.length ? findings.map((finding) => (
              <article key={finding._id} className="finding-card">
                <div className="flex items-center justify-between gap-3"><SeverityBadge severity={finding.severity} /><span className="truncate text-[10px] text-[#66766f]">{finding.filePath}</span></div>
                <h3 className="mt-3 text-sm font-medium leading-5 text-[#e5eee9]">{finding.description}</h3>
                <p className="mt-2 rounded bg-black/30 p-2 font-mono text-[10px] leading-5 text-[#8da098]">{finding.evidence}</p>
                {finding.citations?.length ? <div className="mt-3 space-y-1">{finding.citations.map((citation) => <a key={citation.url} href={citation.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[10px] text-[#72dca0] hover:text-[#9dffc3]"><ExternalLink size={10} /> {citation.title}</a>)}</div> : null}
                {finding.remediationPatch ? <details className="mt-3"><summary className="cursor-pointer text-[11px] text-[#7bffad]">Verified remediation proposal</summary><pre className="mt-2 max-h-48 overflow-auto rounded bg-black/40 p-2 text-[10px] leading-5 text-[#9acbad]">{finding.remediationPatch}</pre></details> : null}
                {finding.status === "open" && <button onClick={() => { setRiskFindingId(finding._id); setRiskReason(""); setRiskError(""); }} className="mt-3 text-[10px] text-[#76877f] hover:text-[#ffc86b]">Accept as documented risk</button>}
                {finding.status === "accepted_risk" && <div className="mt-3 flex items-center gap-1 text-[10px] text-[#ffc86b]"><CheckCircle2 size={11} /> Accepted risk</div>}
              </article>
            )) : <div className="flex min-h-56 flex-col items-center justify-center gap-3 text-center text-xs leading-5 text-[#52635b]"><CircleDotDashed size={24} /><span>No findings in the active scan.</span></div>}
          </div>
        </aside>
      </div>

      {riskFindingId && <div className="border-t border-white/[0.08] bg-[#0a0e0f] p-5"><form onSubmit={submitRisk} className="mx-auto flex max-w-3xl flex-col gap-3 sm:flex-row sm:items-end"><label className="field-label flex-1">Risk acceptance reason<input required minLength={10} maxLength={1000} value={riskReason} onChange={(event) => setRiskReason(event.target.value)} placeholder="Document why this risk is acceptable…" /></label><button className="primary-button justify-center px-4 py-3 text-sm">Record decision</button><button type="button" onClick={() => setRiskFindingId(null)} className="subtle-button justify-center">Cancel</button></form>{riskError && <p role="alert" className="mx-auto mt-2 max-w-3xl text-xs text-[#ff9a9a]">{riskError}</p>}</div>}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" }) {
  const className = severity === "CRITICAL" ? "severity-critical" : severity === "HIGH" ? "severity-high" : severity === "MEDIUM" ? "severity-medium" : "severity-low";
  return <span className={`rounded px-2 py-1 text-[9px] font-bold tracking-wider ${className}`}>{severity}</span>;
}
