"use client";

import { useState, type ReactNode } from "react";
import { useAuthActions, useConvexAuth } from "@convex-dev/auth/react";
import {
  Activity,
  ArrowUpRight,
  CheckCircle2,
  CircleDotDashed,
  GitBranch,
  ScanLine,
  ShieldCheck,
  UserPlus,
  Zap,
} from "lucide-react";
import { AuthDialog, type AuthMode } from "@/src/components/AuthDialog";
import { TerminalDashboard } from "@/src/components/TerminalDashboard";

export default function Home() {
  const { isAuthenticated, isLoading } = useConvexAuth();
  const { signOut } = useAuthActions();
  const [authMode, setAuthMode] = useState<AuthMode | null>(null);

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
          <a className="transition hover:text-white" href="#workflow">Workflow</a>
          <a className="transition hover:text-white" href="#workspace">Operations</a>
          <span className="flex items-center gap-2 text-[#7bffad]"><CircleDotDashed size={14} className="animate-pulse" /> Systems online</span>
        </div>
        <div className="flex items-center gap-2">
          {isAuthenticated ? <button onClick={() => void signOut()} className="subtle-button">Sign out</button> : <button onClick={() => setAuthMode("login")} className="subtle-button">Log in</button>}
          {!isAuthenticated && <button onClick={() => setAuthMode("signup")} className="primary-button hidden sm:inline-flex"><UserPlus size={15} /> Create workspace</button>}
        </div>
      </nav>

      <section id="top" className="relative z-10 mx-auto grid w-full max-w-7xl gap-14 px-5 pb-20 pt-12 sm:px-8 lg:grid-cols-[1.08fr_0.92fr] lg:items-center lg:gap-20 lg:pb-28 lg:pt-20">
        <div>
          <div className="eyebrow"><span className="eyebrow-dot" /> Autonomous security, bounded by evidence</div>
          <h1 className="hero-title mt-7 max-w-3xl">Find the breach<br /><span>before the breach</span>.</h1>
          <p className="mt-7 max-w-xl text-lg leading-8 text-[#aab7b2]">VoidGuard coordinates a focused security crew across your repository: redacting exposed credentials, grounding dependency risk in authoritative sources, and withholding patches until an independent verifier approves them.</p>
          <div className="mt-9 flex flex-wrap items-center gap-4">
            <button onClick={() => isAuthenticated ? document.querySelector("#workspace")?.scrollIntoView() : setAuthMode("signup")} className="primary-button px-5 py-3.5 text-sm"><Zap size={16} /> {isAuthenticated ? "Open operations" : "Start protecting code"} <ArrowUpRight size={16} /></button>
            <a href="#workflow" className="text-sm text-[#9aa8a3] transition hover:text-white">Inspect the controls <span className="ml-1">↓</span></a>
          </div>
          <div className="mt-10 flex flex-wrap gap-x-7 gap-y-3 text-xs text-[#71817b]"><span>Read-only acquisition</span><span>Raw secrets never persisted</span><span>Human approval before changes</span></div>
        </div>

        <div className="hero-visual relative min-h-[360px]" aria-hidden="true">
          <div className="orbit orbit-one" /><div className="orbit orbit-two" />
          <div className="signal-core"><ShieldCheck size={38} strokeWidth={1.4} /></div>
          <div className="signal-label signal-label-top"><span className="signal-pulse" /> evidence redacted</div>
          <div className="signal-label signal-label-right">advisory grounding <span className="text-[#7bffad]">LIVE</span></div>
          <div className="signal-label signal-label-bottom">patch policy <span className="text-white">HUMAN REVIEW</span></div>
          <div className="hero-caption"><Activity size={14} className="text-[#7bffad]" /> 04 agents / 01 bounded mission</div>
        </div>
      </section>

      <section id="workflow" className="relative z-10 border-y border-white/[0.07] bg-white/[0.018]">
        <div className="mx-auto grid w-full max-w-7xl gap-8 px-5 py-14 sm:px-8 md:grid-cols-3 md:gap-10 md:py-20">
          <Step number="01" title="Acquire safely" copy="Fetch a bounded set of eligible files through the GitHub API. No repository clone and no write permissions." icon={<GitBranch size={17} />} />
          <Step number="02" title="Ground every claim" copy="Detect credential patterns locally and verify dependency impact with exact-version, authoritative web evidence." icon={<ScanLine size={17} />} />
          <Step number="03" title="Verify before action" copy="An independent QA agent rejects unsupported upgrades. Approved output remains a reviewable proposal." icon={<CheckCircle2 size={17} />} />
        </div>
      </section>

      <section id="workspace" className="relative z-10 mx-auto w-full max-w-[1440px] px-5 py-20 sm:px-8 lg:py-28">
        <div className="mb-10 flex flex-col justify-between gap-5 md:flex-row md:items-end">
          <div><div className="eyebrow">Authenticated operations</div><h2 className="section-title mt-3">One workspace.<br />Every decision traceable.</h2></div>
          <p className="max-w-md text-sm leading-6 text-[#879691]">Run bounded audits, watch specialist logs arrive in real time, inspect citations, and document accepted risk without leaving the workspace.</p>
        </div>
        <TerminalDashboard key={isAuthenticated ? "authenticated" : "preview"} isAuthenticated={isAuthenticated} authLoading={isLoading} onRequireAuth={() => setAuthMode("signup")} />
      </section>

      <footer className="relative z-10 border-t border-white/[0.07] px-5 py-8 sm:px-8"><div className="mx-auto flex w-full max-w-7xl flex-col justify-between gap-3 text-xs text-[#596962] sm:flex-row"><span>VOIDGUARD AI / SECURITY OPERATIONS</span><span>Evidence first. Human controlled.</span></div></footer>

      {authMode && <AuthDialog mode={authMode} onClose={() => setAuthMode(null)} onModeChange={setAuthMode} />}
    </main>
  );
}

function Step({ number, title, copy, icon }: { number: string; title: string; copy: string; icon: ReactNode }) {
  return <article className="step-item"><div className="flex items-center justify-between text-xs text-[#64756e]"><span>{number}</span><span className="step-icon">{icon}</span></div><h3 className="mt-6 text-lg font-medium text-white">{title}</h3><p className="mt-3 text-sm leading-6 text-[#7f9089]">{copy}</p></article>;
}
