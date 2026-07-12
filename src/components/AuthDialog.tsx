"use client";

import { FormEvent, useEffect, useState } from "react";
import { useAuthActions } from "@convex-dev/auth/react";
import { LockKeyhole, LogIn, ShieldCheck, UserPlus, X } from "lucide-react";

export type AuthMode = "signup" | "login";

export function AuthDialog({ mode, onClose, onModeChange }: {
  mode: AuthMode;
  onClose: () => void;
  onModeChange: (mode: AuthMode) => void;
}) {
  const { signIn } = useAuthActions();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (working) return;
    setWorking(true);
    setError("");
    try {
      await signIn("password", { flow: mode === "signup" ? "signUp" : "signIn", email, password });
      setPassword("");
      onClose();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Authentication failed. Check your details and try again.");
    } finally {
      setWorking(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="auth-title">
      <div className="auth-modal">
        <button aria-label="Close authentication dialog" onClick={onClose} className="absolute right-5 top-5 text-[#71817b] transition hover:text-white">
          <X size={18} />
        </button>
        <div className="brand-mark"><ShieldCheck size={19} /></div>
        <h2 id="auth-title" className="mt-6 text-2xl font-semibold text-white">
          {mode === "signup" ? "Create your secure workspace" : "Welcome back"}
        </h2>
        <p className="mt-2 text-sm leading-6 text-[#8e9d97]">
          {mode === "signup" ? "Create an account to run scoped repository audits and retain findings." : "Sign in to continue your security operations."}
        </p>
        <form onSubmit={submit} className="mt-7 space-y-4">
          <label className="field-label">Email
            <input autoFocus autoComplete="email" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" />
          </label>
          <label className="field-label">Password
            <input autoComplete={mode === "signup" ? "new-password" : "current-password"} type="password" required minLength={8} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 8 characters" />
          </label>
          <div className="flex items-start gap-2 rounded-lg border border-white/[0.08] bg-black/20 p-3 text-xs leading-5 text-[#778780]">
            <LockKeyhole size={14} className="mt-0.5 shrink-0 text-[#7bffad]" /> Passwords are hashed by Convex Auth and never stored in this frontend.
          </div>
          {error && <p role="alert" className="text-sm text-[#ff9a9a]">{error}</p>}
          <button className="primary-button w-full justify-center py-3.5" disabled={working}>
            {working ? "Securing session…" : mode === "signup" ? <><UserPlus size={16} /> Create account</> : <><LogIn size={16} /> Log in</>}
          </button>
        </form>
        <button onClick={() => { setError(""); onModeChange(mode === "signup" ? "login" : "signup"); }} className="mt-5 w-full text-center text-sm text-[#8e9d97] hover:text-white">
          {mode === "signup" ? "Already have an account? Log in" : "New to VoidGuard? Create an account"}
        </button>
      </div>
    </div>
  );
}
