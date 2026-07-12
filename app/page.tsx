"use client";

import { FormEvent, useMemo, useState } from "react";
import { useMutation } from "convex/react";
import { api } from "@/convex/_generated/api";
import {
  AlertTriangle,
  AudioLines,
  Bot,
  Bug,
  CheckCircle2,
  ChevronRight,
  GitBranch,
  LockKeyhole,
  Radio,
  Shield,
  Sparkles,
  Terminal,
  Wrench,
  Zap,
} from "lucide-react";

type AuditStageTone = "normal" | "warning" | "critical" | "success";
type AuditStage = {
  label: string;
  tone: AuditStageTone;
};

type AgentCard = {
  name: string;
  role: string;
  detail: string;
  icon: typeof Shield;
  tone: string;
  pulse: string;
};

const DEFAULT_REPO = "https://github.com/acme/dev-tool";

const AUDIT_STAGES: AuditStage[] = [
  {
    label: "Initializing Agent Crew: Security Lead spawned...",
    tone: "normal",
  },
  {
    label: "Scanning directory tree for high-entropy secrets...",
    tone: "normal",
  },
  {
    label: "Analyzing lockfiles. Querying Linkup live CVE database...",
    tone: "warning",
  },
  {
    label: "WARNING: Leaked OpenAI Secret Key detected in config/production.json!",
    tone: "critical",
  },
  {
    label: "VULNERABILITY DETECTED: CVE-2025-XXXX (Critical RCE) found in lodash@4.17.20",
    tone: "critical",
  },
  {
    label: "Remediation Specialist generating git patch...",
    tone: "warning",
  },
  {
    label: "QA Verifier validating compilation and build integrity... PASS.",
    tone: "success",
  },
  {
    label: "Autonomous Fix PR compiled and ready to merge.",
    tone: "success",
  },
];

const AGENT_CREW: AgentCard[] = [
  {
    name: "Secrets Specialist",
    role: "Entropy Hunter",
    detail: "Tracks leaked API keys, exposed vault material, and poisoned configs before they hit production.",
    icon: LockKeyhole,
    tone: "text-[#ff3333]",
    pulse: "shadow-[0_0_18px_rgba(255,51,51,0.4)]",
  },
  {
    name: "Dependency Auditor",
    role: "Live CVE Recon",
    detail: "Diffs lockfiles, correlates package drift, and queries live exploit intel through Linkup.",
    icon: Bug,
    tone: "text-[#ffaa00]",
    pulse: "shadow-[0_0_18px_rgba(255,170,0,0.4)]",
  },
  {
    name: "Patch Writer",
    role: "Auto-Remediator",
    detail: "Builds deterministic patches, rewrites insecure flows, and stages hardened pull requests.",
    icon: Wrench,
    tone: "text-[#00ff66]",
    pulse: "shadow-[0_0_18px_rgba(0,255,102,0.4)]",
  },
  {
    name: "QA Verifier",
    role: "Integrity Sentinel",
    detail: "Rebuilds the target repo, validates tests, and confirms the secure patch still ships cleanly.",
    icon: CheckCircle2,
    tone: "text-[#00ff66]",
    pulse: "shadow-[0_0_18px_rgba(0,255,102,0.35)]",
  },
];

const BADGES = [
  "SECURED VIA LINKUP API",
  "REALTIME REACTIVE BACKEND ON CONVEX",
  "DEPLOYED ON CLOUDFLARE EDGE",
];

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export default function Home() {
  const [repositoryUrl, setRepositoryUrl] = useState(DEFAULT_REPO);
  const [auditLog, setAuditLog] = useState<{ text: string; tone: AuditStageTone }[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [showWaitlist, setShowWaitlist] = useState(false);
  const [email, setEmail] = useState("");
  const [submitState, setSubmitState] = useState<"idle" | "submitting" | "success" | "error">("idle");
  const [submitError, setSubmitError] = useState("");
  const [audioEnabled, setAudioEnabled] = useState(false);
  const [activeMetric, setActiveMetric] = useState("Awaiting target acquisition");
  const joinWaitlist = useMutation(api.waitlist.join);

  const playAlert = () => {
    if (!audioEnabled || typeof window === "undefined") return;

    const AudioContextClass =
      window.AudioContext ||
      (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!AudioContextClass) return;

    const context = new AudioContextClass();
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.frequency.value = 660;
    gain.gain.setValueAtTime(0.04, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + 0.18);
    oscillator.connect(gain);
    gain.connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.18);
  };

  const repoPreview = useMemo(() => {
    if (!repositoryUrl.trim()) {
      return "github.com/your-org/critical-repo";
    }

    return repositoryUrl.replace(/^https?:\/\//, "");
  }, [repositoryUrl]);

  const streamStage = async (label: string, tone: AuditStageTone) => {
    setAuditLog((current) => [...current, { text: "", tone }]);

    for (let i = 0; i < label.length; i += 1) {
      await wait(tone === "critical" ? 14 : 11);
      setAuditLog((current) => {
        const next = [...current];
        const last = next[next.length - 1];
        if (!last) return current;
        next[next.length - 1] = {
          ...last,
          text: label.slice(0, i + 1),
        };
        return next;
      });
    }
  };

  const handleRunAudit = async () => {
    if (isRunning) return;

    setIsRunning(true);
    setSubmitState("idle");
    setShowWaitlist(false);
    setAuditLog([
      {
        text: `Target locked: ${repoPreview}`,
        tone: "normal",
      },
    ]);
    setActiveMetric("Spawning autonomous crew");

    for (const [index, stage] of AUDIT_STAGES.entries()) {
      setActiveMetric(stage.label.replace(/\.\.\.$/, ""));
      await wait(index === 0 ? 500 : 320);
      if (stage.tone === "critical") playAlert();
      await streamStage(stage.label, stage.tone);
    }

    setActiveMetric("Fix PR staged for operator approval");
    setShowWaitlist(true);
    setIsRunning(false);
  };

  const submitWaitlist = async () => {
    return joinWaitlist({
      email,
      repositoryUrl,
      source: "landing_page",
    });
  };

  const handleWaitlistSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!email || submitState === "submitting") return;

    setSubmitState("submitting");
    setSubmitError("");
    try {
      await submitWaitlist();
      setSubmitState("success");
    } catch (error) {
      setSubmitState("error");
      setSubmitError(error instanceof Error ? error.message : "Unable to join the waitlist.");
    }
  };

  const terminalToneClass = (tone: AuditStageTone) => {
    if (tone === "critical") return "text-[#ff3333]";
    if (tone === "warning") return "text-[#ffaa00]";
    if (tone === "success") return "text-[#00ff66]";
    return "text-[#7dffaf]";
  };

  return (
    <main className="relative min-h-screen overflow-hidden bg-black font-mono text-[#00ff66]">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(0,255,102,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,102,0.06)_1px,transparent_1px)] bg-[size:36px_36px] opacity-30" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,102,0.14),transparent_38%),radial-gradient(circle_at_bottom_right,rgba(255,170,0,0.12),transparent_28%)]" />
      <div className="crt pointer-events-none absolute inset-0 opacity-30" />
      <div className="scanline pointer-events-none absolute inset-0 opacity-40" />

      <section className="relative z-10 mx-auto flex min-h-screen w-full max-w-7xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <header className="border-double border-4 border-[#00ff66] bg-black/80 px-4 py-4 shadow-[0_0_40px_rgba(0,255,102,0.15)] backdrop-blur md:px-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-4">
              <div className="relative flex h-16 w-16 items-center justify-center border-double border-4 border-[#00ff66] bg-black shadow-[0_0_24px_rgba(0,255,102,0.25)]">
                <Shield className="h-8 w-8 text-[#00ff66]" />
                <div className="absolute -bottom-2 -right-2 border-2 border-[#ffaa00] bg-black px-1 py-0.5 text-[10px] text-[#ffaa00]">
                  VG
                </div>
              </div>
              <div>
                <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.4em] text-[#ffaa00]">
                  <Radio className="h-3.5 w-3.5 animate-pulse" />
                  VoidGuard Agency Uplink
                </div>
                <h1 className="mt-2 text-3xl font-black uppercase tracking-[0.18em] text-[#e8ffe8] sm:text-4xl">
                  VoidGuard AI
                </h1>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-[#7dffaf] sm:text-base">
                  Autonomous AI Security Agency for developers who want leaked secrets hunted,
                  lockfiles audited, live CVEs queried, and secure GitHub remediations merged without hesitation.
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-3 sm:items-end">
              <button
                type="button"
                onClick={() => setAudioEnabled((current) => !current)}
                className="inline-flex items-center gap-2 self-start border-double border-4 border-[#ffaa00] bg-[#1a1100] px-4 py-2 text-xs uppercase tracking-[0.3em] text-[#ffaa00] transition hover:bg-[#ffaa00] hover:text-black sm:self-auto"
              >
                <AudioLines className={`h-4 w-4 ${audioEnabled ? "animate-pulse" : "opacity-70"}`} />
                Audio Alerts {audioEnabled ? "Armed" : "Muted"}
              </button>
              <div className="flex flex-wrap gap-2 sm:justify-end">
                {BADGES.map((badge) => (
                  <span
                    key={badge}
                    className="border-2 border-[#00ff66]/70 bg-[#021207] px-3 py-2 text-[10px] uppercase tracking-[0.28em] text-[#9bffbf] shadow-[0_0_20px_rgba(0,255,102,0.16)]"
                  >
                    {badge}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </header>

        <div className="mt-6 grid flex-1 gap-6 xl:grid-cols-[1.35fr_0.9fr]">
          <section className="border-double border-4 border-[#00ff66] bg-black/80 p-4 shadow-[0_0_45px_rgba(0,255,102,0.18)] backdrop-blur md:p-6">
            <div className="flex flex-col gap-5 border-double border-4 border-[#124d29] bg-[#010801] p-4 md:p-5">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <div className="text-xs uppercase tracking-[0.35em] text-[#ffaa00]">Live Strike Console</div>
                  <h2 className="mt-2 text-2xl font-bold uppercase tracking-[0.16em] text-[#f1fff1]">
                    Simulate a full autonomous repo takeover
                  </h2>
                </div>
                <div className="flex items-center gap-3 border-2 border-[#ff3333] bg-[#160404] px-3 py-2 text-xs uppercase tracking-[0.2em] text-[#ff6b6b] shadow-[0_0_18px_rgba(255,51,51,0.2)]">
                  <AlertTriangle className="h-4 w-4 animate-pulse" />
                  High Severity Signals Live
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-[1.3fr_0.7fr]">
                <div className="border-double border-4 border-[#00ff66] bg-black p-4 shadow-[inset_0_0_35px_rgba(0,255,102,0.08)]">
                  <div className="flex items-center justify-between border-b-2 border-[#124d29] pb-3 text-xs uppercase tracking-[0.3em] text-[#7dffaf]">
                    <span className="flex items-center gap-2">
                      <Terminal className="h-4 w-4" />
                      voidguard-agent terminal
                    </span>
                    <span className="text-[#ffaa00]">status: {isRunning ? "engaged" : "armed"}</span>
                  </div>

                  <div className="mt-4 space-y-4">
                    <div className="space-y-2">
                      <label htmlFor="repository-url" className="text-xs uppercase tracking-[0.25em] text-[#7dffaf]">
                        voidguard-agent:~$ enter target repository url:
                      </label>
                      <div className="group flex items-center gap-2 border-double border-4 border-[#00ff66] bg-[#021207] px-3 py-3 transition hover:shadow-[0_0_22px_rgba(0,255,102,0.24)]">
                        <ChevronRight className="h-4 w-4 shrink-0 text-[#00ff66]" />
                        <input
                          id="repository-url"
                          value={repositoryUrl}
                          onChange={(event) => setRepositoryUrl(event.target.value)}
                          placeholder="https://github.com/acme/dev-tool"
                          className="w-full bg-transparent text-sm text-[#e8ffe8] outline-none placeholder:text-[#3f8f5b]"
                        />
                        <GitBranch className="h-4 w-4 shrink-0 text-[#7dffaf] transition group-hover:text-[#00ff66]" />
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={handleRunAudit}
                      disabled={isRunning}
                      className="glow-button w-full border-double border-4 border-[#ffaa00] bg-[#1b1200] px-4 py-4 text-sm font-bold uppercase tracking-[0.35em] text-[#ffaa00] transition hover:-translate-y-0.5 hover:bg-[#ffaa00] hover:text-black disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {isRunning ? "AGENTS EXECUTING..." : "RUN AUTONOMOUS AUDIT"}
                    </button>

                    <div className="border-double border-4 border-[#124d29] bg-[#010501] p-3 text-xs text-[#7dffaf]">
                      <div className="mb-3 flex items-center justify-between uppercase tracking-[0.28em]">
                        <span>agent stream</span>
                        <span className="text-[#ffaa00]">{activeMetric}</span>
                      </div>
                      <div className="h-[320px] space-y-2 overflow-y-auto pr-1 sm:h-[380px]">
                        {auditLog.length === 0 ? (
                          <div className="text-[#3f8f5b]">
                            Awaiting operator input. Feed a repository to deploy the VoidGuard agent crew.
                          </div>
                        ) : (
                          auditLog.map((line, index) => (
                            <div key={`${line.text}-${index}`} className="flex gap-2 leading-6">
                              <span className="text-[#3f8f5b]">[{String(index + 1).padStart(2, "0")}]</span>
                              <span className={terminalToneClass(line.tone)}>{line.text || "_"}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="border-double border-4 border-[#ffaa00] bg-[#120d00] p-4 shadow-[0_0_26px_rgba(255,170,0,0.12)]">
                    <div className="text-xs uppercase tracking-[0.32em] text-[#ffaa00]">Target Snapshot</div>
                    <p className="mt-4 break-all text-lg font-bold uppercase tracking-[0.08em] text-[#fff2cc]">
                      {repoPreview}
                    </p>
                    <div className="mt-5 grid grid-cols-2 gap-3 text-xs uppercase tracking-[0.18em]">
                      <div className="border border-[#ffaa00]/40 bg-black/50 p-3 text-[#ffd37a]">
                        Risk Index
                        <div className="mt-2 text-2xl font-black text-[#ff3333]">9.4</div>
                      </div>
                      <div className="border border-[#00ff66]/40 bg-black/50 p-3 text-[#8effb7]">
                        Patch ETA
                        <div className="mt-2 text-2xl font-black text-[#00ff66]">42s</div>
                      </div>
                    </div>
                  </div>

                  <div className="border-double border-4 border-[#ff3333] bg-[#140405] p-4 shadow-[0_0_24px_rgba(255,51,51,0.14)]">
                    <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-[#ff6b6b]">
                      <Zap className="h-4 w-4 animate-pulse" />
                      Live Threat Feed
                    </div>
                    <ul className="mt-4 space-y-3 text-sm text-[#ffb0b0]">
                      <li>• Secret leak probability spikes when CI config drift is detected.</li>
                      <li>• Linkup CVE lookups enrich package intel with current exploit chatter.</li>
                      <li>• GitHub patch generation preserves build health before merge.</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <aside className="flex flex-col gap-6">
            <section className="border-double border-4 border-[#00ff66] bg-black/80 p-4 shadow-[0_0_40px_rgba(0,255,102,0.16)] md:p-5">
              <div className="flex items-center gap-3 text-xs uppercase tracking-[0.32em] text-[#ffaa00]">
                <Bot className="h-4 w-4 text-[#00ff66]" />
                Agent Crew
              </div>
              <div className="mt-4 grid gap-4">
                {AGENT_CREW.map((agent) => {
                  const Icon = agent.icon;
                  return (
                    <article
                      key={agent.name}
                      className={`group border-double border-4 border-[#173d24] bg-[#020702] p-4 transition duration-300 hover:-translate-y-1 hover:border-[#00ff66] ${agent.pulse}`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.28em] text-[#7dffaf]">
                            <span className={`inline-block h-3 w-3 rounded-full border border-current ${agent.tone} animate-pulse`} />
                            {agent.role}
                          </div>
                          <h3 className="mt-2 text-lg font-bold uppercase tracking-[0.08em] text-[#f1fff1]">
                            {agent.name}
                          </h3>
                        </div>
                        <Icon className={`h-6 w-6 ${agent.tone} transition group-hover:scale-110`} />
                      </div>
                      <p className="mt-3 text-sm leading-6 text-[#a1d9b5]">{agent.detail}</p>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="border-double border-4 border-[#ffaa00] bg-black/80 p-4 shadow-[0_0_35px_rgba(255,170,0,0.12)] md:p-5">
              <div className="flex items-center gap-3 text-xs uppercase tracking-[0.32em] text-[#ffaa00]">
                <Sparkles className="h-4 w-4" />
                Why teams deploy VoidGuard
              </div>
              <div className="mt-4 space-y-4 text-sm leading-6 text-[#ffe0a0]">
                <div className="border border-[#ffaa00]/40 bg-[#150d02] p-4">
                  <div className="text-[11px] uppercase tracking-[0.25em] text-[#ffca66]">Autonomy</div>
                  Security triage, patch writing, and build verification run as one coordinated operator loop.
                </div>
                <div className="border border-[#00ff66]/35 bg-[#041108] p-4 text-[#a8ffc8]">
                  <div className="text-[11px] uppercase tracking-[0.25em] text-[#7dffaf]">Developer-native UX</div>
                  Repo-first input, terminal-grade telemetry, and PR-ready fixes your engineers can trust.
                </div>
                <div className="border border-[#ff3333]/35 bg-[#120406] p-4 text-[#ffb7b7]">
                  <div className="text-[11px] uppercase tracking-[0.25em] text-[#ff7a7a]">Immediate danger surfacing</div>
                  Hardcoded secrets, actively exploited packages, and dangerous dependency drift render in seconds.
                </div>
              </div>
            </section>
          </aside>
        </div>
      </section>

      <div
        className={`fixed inset-0 z-20 flex items-end justify-center bg-black/75 p-3 transition duration-500 sm:p-6 ${
          showWaitlist ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"
        }`}
      >
        <div
          className={`w-full max-w-3xl border-double border-4 border-[#00ff66] bg-black p-4 shadow-[0_0_60px_rgba(0,255,102,0.24)] transition duration-500 sm:p-6 ${
            showWaitlist ? "translate-y-0" : "translate-y-10"
          }`}
        >
          <div className="glitch-title text-xs uppercase tracking-[0.34em] text-[#ffaa00]">Deployment Authorization Required</div>
          <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-2xl">
              <h2 className="text-2xl font-black uppercase tracking-[0.14em] text-[#ecffec] sm:text-3xl">
                VoidGuard Crew is ready to protect your codebase.
              </h2>
              <p className="mt-3 text-sm leading-6 text-[#9bffbf]">
                Enter your email to join the operator queue. We&apos;ll store your request securely and use the repository URL to prepare your audit handoff.
              </p>
            </div>
            <div className="border-2 border-[#ffaa00] bg-[#120d00] px-4 py-3 text-xs uppercase tracking-[0.26em] text-[#ffd37a]">
              Queue node: armed
            </div>
          </div>

          <form onSubmit={handleWaitlistSubmit} className="mt-6 space-y-4">
            <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
              <div className="border-double border-4 border-[#00ff66] bg-[#021207] px-4 py-4 shadow-[0_0_24px_rgba(0,255,102,0.14)]">
                <label htmlFor="waitlist-email" className="mb-2 block text-xs uppercase tracking-[0.28em] text-[#7dffaf]">
                  operator email
                </label>
                <input
                  id="waitlist-email"
                  type="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@company.com"
                  className="w-full bg-transparent text-lg text-[#f1fff1] outline-none placeholder:text-[#3f8f5b]"
                />
              </div>
              <button
                type="submit"
                disabled={submitState === "submitting" || submitState === "success"}
                className="border-double border-4 border-[#ffaa00] bg-[#1b1200] px-6 py-4 text-sm font-bold uppercase tracking-[0.32em] text-[#ffaa00] transition hover:bg-[#ffaa00] hover:text-black disabled:cursor-not-allowed disabled:opacity-70"
              >
                {submitState === "submitting"
                  ? "DECRYPTING ACCESS KEY..."
                  : submitState === "success"
                    ? "ACCESS GRANTED"
                    : submitState === "error"
                      ? "RETRY JOIN"
                    : "JOIN WAITLIST"}
              </button>
            </div>

            <div className="border-double border-4 border-[#124d29] bg-[#010501] p-4 text-sm leading-6 text-[#a8ffc8]">
              {submitState === "success" ? (
                <div className="space-y-2">
                  <div className="text-xs uppercase tracking-[0.3em] text-[#ffaa00]">queue handshake complete</div>
                  <p className="text-base text-[#ecffec]">
                    ACCESS GRANTED. Agent {email}, your request is secured in the VoidGuard queue.
                  </p>
                </div>
              ) : submitState === "error" ? (
                <div className="space-y-2 text-[#ffb0b0]">
                  <div className="text-xs uppercase tracking-[0.3em] text-[#ff6b6b]">handshake failed</div>
                  <p>{submitError}</p>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-xs uppercase tracking-[0.3em] text-[#ffaa00]">Convex queue online</div>
                  <p>
                    The audit is simulated in the browser. Waitlist submissions are validated and stored securely in Convex.
                  </p>
                </div>
              )}
            </div>
          </form>
        </div>
      </div>

      <style jsx global>{`
        @keyframes crt-flicker {
          0%, 100% { opacity: 0.18; }
          10% { opacity: 0.22; }
          20% { opacity: 0.15; }
          30% { opacity: 0.26; }
          40% { opacity: 0.17; }
          50% { opacity: 0.23; }
          60% { opacity: 0.16; }
          70% { opacity: 0.2; }
          80% { opacity: 0.13; }
          90% { opacity: 0.24; }
        }

        @keyframes scanline-move {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }

        @keyframes glitch-shift {
          0%, 100% { text-shadow: 0 0 0 rgba(255, 51, 51, 0.7), 0 0 0 rgba(0, 255, 102, 0.6); }
          20% { text-shadow: 2px 0 0 rgba(255, 51, 51, 0.7), -2px 0 0 rgba(0, 255, 102, 0.6); }
          40% { text-shadow: -2px 0 0 rgba(255, 51, 51, 0.7), 2px 0 0 rgba(0, 255, 102, 0.6); }
          60% { text-shadow: 3px 0 0 rgba(255, 170, 0, 0.7), -3px 0 0 rgba(0, 255, 102, 0.55); }
          80% { text-shadow: -1px 0 0 rgba(255, 51, 51, 0.7), 1px 0 0 rgba(0, 255, 102, 0.6); }
        }

        .crt {
          background: radial-gradient(circle at center, rgba(0, 255, 102, 0.08), transparent 60%);
          animation: crt-flicker 0.22s infinite;
          mix-blend-mode: screen;
        }

        .scanline::before {
          content: "";
          position: absolute;
          inset: 0;
          background: linear-gradient(to bottom, transparent 0%, rgba(255, 255, 255, 0.04) 45%, rgba(255, 255, 255, 0.08) 50%, transparent 100%);
          animation: scanline-move 7s linear infinite;
        }

        .glitch-title {
          animation: glitch-shift 1.4s infinite steps(2, end);
        }

        .glow-button {
          box-shadow: 0 0 0 rgba(255, 170, 0, 0.2);
        }

        .glow-button:hover {
          box-shadow: 0 0 24px rgba(255, 170, 0, 0.36);
        }
      `}</style>
    </main>
  );
}
