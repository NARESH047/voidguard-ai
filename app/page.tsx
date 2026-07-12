"use client";

import { FormEvent, useMemo, useState, type ReactNode } from "react";
import { useAuthActions, useConvexAuth } from "@convex-dev/auth/react";
import { useAction, useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  CircleDotDashed,
  GitBranch,
  LockKeyhole,
  LogIn,
  ScanLine,
  ShieldCheck,
  Terminal,
  UserPlus,
  X,
  Zap,
} from "lucide-react";

const DEFAULT_REPO = "https://github.com/acme/dev-tool";

type AuthMode = "signup" | "login";
type AuthState = "idle" | "working" | "error";

const statusCopy: Record<string, string> = {
  initialized: "Queued",
  scanning_secrets: "Secrets sweep",
  auditing_dependencies: "Dependency recon",
  writing_remediations: "Writing remediation",
  verifying: "Verifying",
  completed: "Complete",
  failed: "Failed",
};

export default function Home() {
  const { isAuthenticated, isLoading: authLoading } = useConvexAuth();
  const { signIn, signOut } = useAuthActions();
  const createScan = useMutation(api.scans.createScan);
  const runAudit = useAction(api.security_lead.runAutonomousAudit);

  const [repoUrl, setRepoUrl] = useState(DEFAULT_REPO);
  const [activeScanId, setActiveScanId] = useState<Id<"scans"> | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [authMode, setAuthMode] = useState<AuthMode | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authState, setAuthState] = useState<AuthState>("idle");
  const [authError, setAuthError] = useState("");
  const [auditError, setAuditError] = useState("");

  const scan = useQuery(api.scans.getScan, activeScanId ? { scanId: activeScanId } : "skip");
  const logs = useQuery(api.scans.getScanLogs, activeScanId ? { scanId: activeScanId } : "skip");
  const findings = useQuery(api.scans.getFindings, activeScanId ? { scanId: activeScanId } : "skip");

  const repoLabel = useMemo(() => {
    try {
      const url = new URL(repoUrl);
      return `${url.hostname}${url.pathname.replace(/\/$/, "")}`;
    } catch {
      return repoUrl || "github.com/owner/repository";
    }
  }, [repoUrl]);

  const openAuth = (mode: AuthMode) => {
    setAuthMode(mode);
    setAuthState("idle");
    setAuthError("");
  };

  const handleAuth = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!authMode || authState === "working") return;
    setAuthState("working");
    setAuthError("");
    try {
      await signIn("password", { flow: authMode === "signup" ? "signUp" : "signIn", email, password });
      setAuthMode(null);
      setPassword("");
    } catch (error) {
      setAuthState("error");
      setAuthError(error instanceof Error ? error.message : "Authentication failed. Check your details and try again.");
    }
  };

  const startAudit = async () => {
    if (!isAuthenticated) {
      openAuth("signup");
      return;
    }
    if (isRunning) return;
    setIsRunning(true);
    setAuditError("");
    try {
      const scanId = await createScan({ repoUrl });
      setActiveScanId(scanId);
      await runAudit({ scanId, repoUrl });
    } catch (error) {
      setAuditError(error instanceof Error ? error.message : "Unable to start the audit.");
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <main className="min-h-screen overflow-hidden bg-[#07090d] text-[#eef5f0]">
      <div className="ambient-grid pointer-events-none fixed inset-0" />
      <div className="ambient-glow pointer-events-none fixed inset-0" />

      <nav className="relative z-10 mx-auto flex w-full max-w-7xl items-center justify-between px-5 py-5 sm:px-8">
        <a href="#top" className="flex items-center gap-3" aria-label="VoidGuard AI home">
          <span className="brand-mark"><ShieldCheck size={19} /></span>
          <span className="text-sm font-semibold tracking-[0.24em] text-white">VOIDGUARD <span className="text-[#7bffad]">AI</span></span>
        </a>
        <div className="hidden items-center gap-8 text-sm text-[#8f9d99] md:flex">
          <a className="transition hover:text-white" href="#how-it-works">How it works</a>
          <a className="transition hover:text-white" href="#workspace">Workspace</a>
          <span className="flex items-center gap-2 text-[#7bffad]"><CircleDotDashed size={14} className="animate-pulse" /> Systems online</span>
        </div>
        <div className="flex items-center gap-2">
          {isAuthenticated ? (
            <button onClick={() => void signOut()} className="subtle-button">Sign out</button>
          ) : (
            <button onClick={() => openAuth("login")} className="subtle-button">Log in</button>
          )}
          <button onClick={() => openAuth("signup")} className="primary-button hidden sm:inline-flex"><UserPlus size={15} /> Join the crew</button>
        </div>
      </nav>

      <section id="top" className="relative z-10 mx-auto grid w-full max-w-7xl gap-14 px-5 pb-20 pt-12 sm:px-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:gap-20 lg:pb-28 lg:pt-20">
        <div>
          <div className="eyebrow"><span className="eyebrow-dot" /> Autonomous security for code that matters</div>
          <h1 className="hero-title mt-7 max-w-3xl">Find the breach<br /><span>before the breach</span>.</h1>
          <p className="mt-7 max-w-xl text-lg leading-8 text-[#aab7b2]">VoidGuard deploys a focused AI security crew across your repository: hunting secrets, grounding dependency risk in live advisories, and preparing fixes your team can review.</p>
          <div className="mt-9 flex flex-wrap items-center gap-4">
            <button onClick={() => openAuth("signup")} className="primary-button px-5 py-3.5 text-sm"><Zap size={16} /> Start protecting your code <ArrowUpRight size={16} /></button>
            <a href="#how-it-works" className="text-sm text-[#9aa8a3] transition hover:text-white">See the workflow <span className="ml-1">↓</span></a>
          </div>
          <div className="mt-10 flex flex-wrap gap-x-7 gap-y-3 text-xs text-[#71817b]"><span>Private by default</span><span>Read-only first pass</span><span>Human approval before fixes</span></div>
        </div>

        <div className="hero-visual relative min-h-[360px]">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="signal-core"><ShieldCheck size={38} strokeWidth={1.4} /></div>
          <div className="signal-label signal-label-top"><span className="signal-pulse" /> secrets detected</div>
          <div className="signal-label signal-label-right">CVE intelligence <span className="text-[#7bffad]">LIVE</span></div>
          <div className="signal-label signal-label-bottom">patch confidence <span className="text-white">94.8%</span></div>
          <div className="hero-caption"><Activity size={14} className="text-[#7bffad]" /> Agent mesh / 04 specialists / 01 mission</div>
        </div>
      </section>

      <section id="how-it-works" className="relative z-10 border-y border-white/[0.07] bg-white/[0.018]">
        <div className="mx-auto grid w-full max-w-7xl gap-8 px-5 py-14 sm:px-8 md:grid-cols-3 md:gap-10 md:py-20">
          <Step number="01" title="Connect" copy="Point VoidGuard at a GitHub repository. The first pass stays read-only and scoped." icon={<GitBranch size={17} />} />
          <Step number="02" title="Investigate" copy="Specialists inspect credential patterns and ground dependency findings against live security sources." icon={<ScanLine size={17} />} />
          <Step number="03" title="Review" copy="Get evidence, risk context, and an explainable patch proposal before anything changes." icon={<CheckCircle2 size={17} />} />
        </div>
      </section>

      <section id="workspace" className="relative z-10 mx-auto w-full max-w-7xl px-5 py-20 sm:px-8 lg:py-28">
        <div className="mb-10 flex flex-col justify-between gap-5 md:flex-row md:items-end">
          <div><div className="eyebrow">Your secure workspace</div><h2 className="section-title mt-3">A calm command center<br />for noisy risk.</h2></div>
          <p className="max-w-sm text-sm leading-6 text-[#879691]">Sign up to run a live, read-only repository audit. Your findings remain scoped to your account.</p>
        </div>
        <div className="workspace-shell">
          <div className="workspace-toolbar"><div className="flex items-center gap-2"><span className="window-dot bg-[#ff6b6b]" /><span className="window-dot bg-[#ffc86b]" /><span className="window-dot bg-[#7bffad]" /></div><span className="flex items-center gap-2 text-xs text-[#7f9089]"><Terminal size={14} /> voidguard / audit console</span><span className="text-xs text-[#7bffad]">{isAuthenticated ? "authenticated" : "preview mode"}</span></div>
          <div className="grid gap-8 p-5 md:p-8 lg:grid-cols-[1fr_0.72fr]">
            <div>
              <div className="mb-3 flex items-center justify-between"><label htmlFor="repo" className="text-sm font-medium text-white">Repository target</label><span className="text-xs text-[#687872]">GitHub / HTTPS</span></div>
              <div className="repo-input"><GitBranch size={17} className="shrink-0 text-[#7bffad]" /><input id="repo" value={repoUrl} onChange={(event) => setRepoUrl(event.target.value)} placeholder="https://github.com/owner/repository" /><span className="text-xs text-[#5f7169]">↵</span></div>
              <div className="mt-5 flex flex-wrap items-center gap-3"><button onClick={() => void startAudit()} disabled={isRunning || authLoading} className="primary-button px-4 py-3 text-sm disabled:cursor-not-allowed disabled:opacity-60">{isRunning ? <><Activity size={15} className="animate-pulse" /> Crew is investigating</> : <><ScanLine size={15} /> Run read-only audit</>}</button>{!isAuthenticated && <span className="text-xs text-[#71817b]">Create an account to unlock scans</span>}</div>
              {auditError && <p className="mt-4 flex items-center gap-2 text-sm text-[#ff9a9a]"><AlertTriangle size={15} /> {auditError}</p>}
              <div className="terminal-panel mt-8"><div className="mb-4 flex items-center justify-between border-b border-white/[0.08] pb-3 text-xs text-[#6f8079]"><span>live agent stream</span><span className={scan?.status === "completed" ? "text-[#7bffad]" : "text-[#ffc86b]"}>{scan ? statusCopy[scan.status] : "waiting"}</span></div>{logs?.length ? <div className="space-y-3">{logs.map((log) => <div key={log._id} className="flex gap-3 text-xs leading-5"><span className="shrink-0 text-[#4f625a]">{log.agent}</span><span className={log.level === "error" ? "text-[#ff8585]" : log.level === "success" ? "text-[#7bffad]" : log.level === "warning" ? "text-[#ffc86b]" : "text-[#a9b9b2]"}>{log.message}</span></div>)}</div> : <div className="flex min-h-40 flex-col items-center justify-center gap-3 text-center text-sm text-[#53645d]"><LockKeyhole size={22} /><span>{isAuthenticated ? "Your next audit will appear here." : "Sign up to connect your first repository."}</span></div>}</div>
            </div>
            <div className="space-y-5"><div className="metric-card"><div className="flex items-center justify-between text-xs text-[#7f9089]"><span>Target</span><GitBranch size={15} /></div><div className="mt-4 truncate text-sm font-medium text-white">{repoLabel}</div><div className="mt-2 text-xs text-[#64756e]">Read-only access / scoped session</div></div><div className="metric-card"><div className="flex items-center justify-between text-xs text-[#7f9089]"><span>Findings</span><AlertTriangle size={15} className="text-[#ffc86b]" /></div><div className="mt-3 text-4xl font-semibold tracking-tight text-white">{findings?.length ?? "—"}</div><div className="mt-2 text-xs text-[#64756e]">Evidence-backed risk register</div></div><div className="metric-card"><div className="flex items-center gap-2 text-xs text-[#7f9089]"><CircleDotDashed size={15} className="text-[#7bffad]" /> Crew status</div><div className="mt-4 flex items-center gap-2 text-sm text-[#d7e5dd]"><span className="h-2 w-2 rounded-full bg-[#7bffad] shadow-[0_0_12px_#7bffad]" /> Security Lead ready</div><div className="mt-2 text-xs text-[#64756e]">Secrets / dependencies / QA</div></div></div>
          </div>
        </div>
      </section>

      <footer className="relative z-10 border-t border-white/[0.07] px-5 py-8 sm:px-8"><div className="mx-auto flex w-full max-w-7xl flex-col justify-between gap-3 text-xs text-[#596962] sm:flex-row"><span>VOIDGUARD AI / PRIVATE SECURITY OPERATIONS</span><span>Built for teams that ship fast.</span></div></footer>

      {authMode && <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="auth-title"><div className="auth-modal"><button aria-label="Close" onClick={() => setAuthMode(null)} className="absolute right-5 top-5 text-[#71817b] transition hover:text-white"><X size={18} /></button><div className="brand-mark"><ShieldCheck size={19} /></div><h2 id="auth-title" className="mt-6 text-2xl font-semibold text-white">{authMode === "signup" ? "Join the security crew" : "Welcome back"}</h2><p className="mt-2 text-sm leading-6 text-[#8e9d97]">{authMode === "signup" ? "Create your private workspace and run your first repository audit." : "Sign in to access your audit history and findings."}</p><form onSubmit={handleAuth} className="mt-7 space-y-4"><label className="field-label">Email<input autoComplete="email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" /></label><label className="field-label">Password<input autoComplete={authMode === "signup" ? "new-password" : "current-password"} type="password" required minLength={8} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 8 characters" /></label>{authError && <p className="text-sm text-[#ff9a9a]">{authError}</p>}<button className="primary-button w-full justify-center py-3.5" disabled={authState === "working"}>{authState === "working" ? "Securing session…" : authMode === "signup" ? <><UserPlus size={16} /> Create account</> : <><LogIn size={16} /> Log in</>}</button></form><button onClick={() => { setAuthMode(authMode === "signup" ? "login" : "signup"); setAuthError(""); }} className="mt-5 w-full text-center text-sm text-[#8e9d97] hover:text-white">{authMode === "signup" ? "Already have an account? Log in" : "New to VoidGuard? Create an account"}</button></div></div>}
    </main>
  );
}

function Step({ number, title, copy, icon }: { number: string; title: string; copy: string; icon: ReactNode }) {
  return <article className="step-item"><div className="flex items-center justify-between text-xs text-[#64756e]"><span>{number}</span><span className="step-icon">{icon}</span></div><h3 className="mt-6 text-lg font-medium text-white">{title}</h3><p className="mt-3 text-sm leading-6 text-[#7f9089]">{copy}</p></article>;
}
