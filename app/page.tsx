"use client";

import type { ReactNode } from "react";
import {
  ArrowDown,
  ArrowUpRight,
  CheckCircle2,

  GitBranch,
  Globe2,
  ScanLine,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { TerminalDashboard } from "@/src/components/TerminalDashboard";

export default function Home() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#08090a] text-[#f7f8f8]">
      <div className="ambient-grid pointer-events-none fixed inset-0 opacity-50" />
      <div className="linear-glow pointer-events-none fixed inset-x-0 top-0 h-[720px]" />

      <nav className="sticky top-0 z-30 border-b border-white/[0.06] bg-[#08090a]/85 backdrop-blur-xl">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-5 sm:px-8">
          <a href="#top" className="flex items-center gap-3" aria-label="VoidGuard AI home">
            <span className="brand-mark"><ShieldCheck size={18} /></span>
            <span className="text-sm font-medium tracking-[-0.01em] text-[#f7f8f8]">VoidGuard <span className="text-[#8d8cff]">AI</span></span>
          </a>
          <div className="hidden items-center gap-7 text-[13px] text-[#8a8f98] md:flex">
            <a className="transition hover:text-[#f7f8f8]" href="#workflow">How it works</a>
            <a className="transition hover:text-[#f7f8f8]" href="#workspace">Public workspace</a>
            <span>Bounded public-repository triage</span>
          </div>
          <a href="#workspace" className="primary-button px-4 py-2.5 text-xs">Scan a public repo <ArrowUpRight size={14} /></a>
        </div>
      </nav>

      <section id="top" className="relative z-10 mx-auto flex min-h-[690px] w-full max-w-6xl flex-col items-center justify-center px-5 pb-24 pt-20 text-center sm:px-8">
        <div className="public-launch-pill"><Globe2 size={13} /> Open to everyone · no account required</div>
        <h1 className="linear-hero mt-8 max-w-5xl">Bounded security triage for<br className="hidden sm:block" /> supported public repositories.</h1>
        <p className="mt-7 max-w-2xl text-base leading-7 text-[#8a8f98] sm:text-lg">Paste a repository link. VoidGuard runs a bounded, read-only investigation across secrets, dangerous code and configuration patterns, CI/auth/TLS posture, and exact dependency evidence—then withholds unsupported claims and patches.</p>
        <div className="mt-9 flex flex-col items-center gap-3 sm:flex-row">
          <a href="#workspace" className="primary-button px-5 py-3.5 text-sm"><Sparkles size={15} /> Start a public audit <ArrowDown size={14} /></a>
          <a href="#workflow" className="subtle-button px-5 py-3.5 text-sm">Review the safeguards</a>
        </div>
        <div className="mt-12 flex flex-wrap justify-center gap-x-8 gap-y-3 text-xs text-[#8a8f98]"><span>Read-only GitHub access</span><span>Risk-prioritized 40-file bound</span><span>Fresh source-bound citations</span><span>Human-controlled proposals</span></div>
      </section>

      <section id="workflow" className="relative z-10 mx-auto w-full max-w-7xl px-5 pb-20 sm:px-8 lg:pb-28">
        <div className="workflow-strip">
          <Step number="01" title="Share a public link" copy="Private repositories are unsupported. Do not publish sensitive code solely to scan it." icon={<GitBranch size={16} />} />
          <Step number="02" title="Watch the crew investigate" copy="A risk-prioritized bounded file set is checked deterministically while exact dependency versions are searched against current primary advisory sources." icon={<ScanLine size={16} />} />
          <Step number="03" title="Review evidence, not claims" copy="Raw credentials stay redacted. Patches remain proposals and pass model plus deterministic validation." icon={<CheckCircle2 size={16} />} />
        </div>
      </section>

      <section id="workspace" className="relative z-10 mx-auto w-full max-w-[1480px] px-4 pb-24 sm:px-8 lg:pb-32">
        <div className="mb-8 flex flex-col justify-between gap-5 px-1 md:flex-row md:items-end">
          <div><div className="workspace-kicker">Public operations</div><h2 className="linear-section-title mt-3">Paste a link. Follow the evidence.</h2></div>
          <p className="max-w-md text-sm leading-6 text-[#8a8f98]">No signup wall. Every browser tab gets an isolated capability session with strict per-session and global quotas.</p>
        </div>
        <TerminalDashboard />
      </section>

      <footer className="relative z-10 border-t border-white/[0.06] px-5 py-8 sm:px-8"><div className="mx-auto flex w-full max-w-7xl flex-col justify-between gap-3 text-xs text-[#8a8f98] sm:flex-row"><span>VOIDGUARD AI / PUBLIC SECURITY OPERATIONS</span><span>Evidence first. Human controlled.</span></div></footer>
    </main>
  );
}

function Step({ number, title, copy, icon }: { number: string; title: string; copy: string; icon: ReactNode }) {
  return <article className="workflow-step"><div className="flex items-center justify-between text-[11px] text-[#8a8f98]"><span>{number}</span><span className="step-icon">{icon}</span></div><h3 className="mt-7 text-base font-medium text-[#f7f8f8]">{title}</h3><p className="mt-3 text-sm leading-6 text-[#8a8f98]">{copy}</p></article>;
}
