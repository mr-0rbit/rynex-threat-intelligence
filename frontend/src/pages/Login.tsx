import { useState, useEffect, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Lock, Mail, ShieldAlert } from "lucide-react";
import { useAuth } from "../auth";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [utcTime, setUtcTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().slice(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed. Check credentials.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-ink-950 px-4 py-8 font-sans text-ink-100 overflow-hidden">
      {/* Background Cyber Grid & Radial Ambient Lighting */}
      <div className="absolute inset-0 cyber-grid opacity-70 pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[450px] bg-accent/5 rounded-full blur-[130px] pointer-events-none" />
      <div className="absolute bottom-0 inset-x-0 h-40 bg-gradient-to-t from-ink-950 to-transparent pointer-events-none" />

      {/* Main Terminal Card */}
      <div className="relative z-10 w-full max-w-md">
          {/* Top Telemetry / Status Pill */}
          <div className="mb-4 flex items-center justify-between text-2xs font-mono text-ink-400 border border-ink-700/60 bg-ink-900/60 px-3.5 py-1.5 backdrop-blur-sm">
            <div className="flex items-center gap-2">
              <span className="flex h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
              <span className="tracking-[0.16em] uppercase text-ink-300">SECURE ENCLAVE // NODE 01</span>
            </div>
            <span className="tabular-nums tracking-widest text-ink-400">{utcTime || "UTC TIME"}</span>
          </div>

          {/* Card Box with Hairline Border and Top Gradient */}
          <div className="relative border border-ink-600/90 bg-ink-900/95 shadow-2xl backdrop-blur-xl">
            {/* Subtle Top Cyan Accent Strip */}
            <div className="h-[2px] w-full bg-gradient-to-r from-transparent via-accent to-transparent" />

            <div className="p-7 sm:p-9">
              {/* Logo & Platform Header */}
              <div className="flex flex-col items-center text-center">
                <div className="relative mb-4 flex h-20 w-20 items-center justify-center rounded-md border border-ink-600 bg-ink-950 p-3 shadow-[0_0_25px_rgba(0,212,255,0.15)] ring-1 ring-accent/20">
                  <img
                    src="/logo.png"
                    alt="Rynex Logo"
                    className="h-full w-full object-contain drop-shadow-[0_0_10px_rgba(0,212,255,0.4)]"
                  />
                </div>

                <h1 className="text-lg font-bold uppercase tracking-[0.12em] text-white font-mono">
                  Rynex Threat Intelligence
                </h1>
                <p className="mt-1 text-2xs uppercase tracking-[0.24em] text-accent font-mono font-medium">
                  Detect · Analyze · Respond
                </p>
              </div>

              {/* Form */}
              <form onSubmit={submit} className="mt-7 space-y-4">
                <div>
                  <label className="block text-xs font-medium text-ink-200 font-mono mb-1.5">
                    Email
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-ink-400">
                      <Mail className="h-4 w-4" />
                    </div>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full rounded border border-ink-600 bg-ink-950 py-2.5 pl-9 pr-3 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-1 focus:ring-accent/40 transition-colors"
                      placeholder="analyst@rynex.tech"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-ink-200 font-mono mb-1.5">
                    Password
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-ink-400">
                      <Lock className="h-4 w-4" />
                    </div>
                    <input
                      type={showPassword ? "text" : "password"}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full rounded border border-ink-600 bg-ink-950 py-2.5 pl-9 pr-10 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-1 focus:ring-accent/40 transition-colors"
                      placeholder="••••••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 flex items-center pr-3 text-ink-400 hover:text-ink-200 transition-colors"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="flex items-start gap-2.5 rounded border border-red-500/40 bg-red-950/30 p-2.5 text-xs text-red-200 font-mono">
                    <ShieldAlert className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={busy}
                  className="w-full rounded bg-accent py-2.5 text-xs font-mono font-bold uppercase tracking-[0.18em] text-black transition-all duration-200 hover:bg-white hover:shadow-[0_0_20px_rgba(0,212,255,0.35)] disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 mt-2"
                >
                  {busy ? (
                    <>
                      <div className="h-3.5 w-3.5 animate-spin border-2 border-black border-t-transparent rounded-full" />
                      <span>Verifying Credentials…</span>
                    </>
                  ) : (
                    <span>Access Platform</span>
                  )}
                </button>
              </form>

              {/* Security Warning Notice */}
              <div className="mt-6 border-t border-ink-700/80 pt-4 text-center">
                <p className="text-[10px] leading-relaxed text-ink-400 font-mono">
                  RESTRICTED SOC SYSTEM · INTERNAL AUDITING ACTIVE
                  <br />
                  All transactions are logged with source telemetry and cryptographic hash.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
  );
}
