"use client";

import { useState } from "react";
import { useAction } from "convex/react";
import { api } from "@/convex/_generated/api";

export default function Home() {
  const [status, setStatus] = useState<"idle" | "testing" | "success" | "error">("idle");
  const [logs, setLogs] = useState<string[]>([]);
  
  // Wire up the live server connection hook
  const triggerLiveTest = useAction(api.ai.runLiveDiagnostic);

  const runDiagnostics = async () => {
    setStatus("testing");
    setLogs(["Connecting to Convex backend...", "Routing request through Cloudflare AI Gateway..."]);
    
    try {
      const responseText = await triggerLiveTest();
      setLogs((prev) => [
        ...prev, 
        "✓ Convex Connection verified",
        "✓ Cloudflare Proxy handshake successful",
        `✓ OpenAI Response: "${responseText}"`
      ]);
      setStatus("success");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setLogs((prev) => [
        ...prev, 
        `❌ Diagnostic Failed: ${message}`
      ]);
      setStatus("error");
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6 bg-slate-950 text-slate-50">
      <div className="w-full max-w-xl p-6 rounded-2xl border border-slate-800 bg-slate-900/50 backdrop-blur-md">
        <h1 className="text-2xl font-bold tracking-tight mb-2">Hermes Core Control Panel</h1>
        <p className="text-sm text-slate-400 mb-6">Verify your network stack and agent pipelines before coding features.</p>

        <button
          onClick={runDiagnostics}
          disabled={status === "testing"}
          className="w-full py-3 px-4 rounded-xl font-medium tracking-wide transition-all bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white shadow-lg shadow-indigo-600/20"
        >
          {status === "testing" ? "Testing Infrastructure..." : "Execute Infrastructure Diagnostic"}
        </button>

        {logs.length > 0 && (
          <div className="mt-6 rounded-xl p-4 bg-slate-950/80 font-mono text-xs border border-slate-800/80 space-y-1.5 max-h-48 overflow-y-auto">
            {logs.map((log, index) => (
              <div key={index} className={log.startsWith("✓") ? "text-emerald-400" : log.startsWith("❌") ? "text-rose-400" : "text-slate-400"}>
                {log}
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}