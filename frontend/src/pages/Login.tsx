import { useState, useEffect, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, Lock, Mail, ShieldAlert, Sparkles } from "lucide-react";
import { useAuth } from "../auth";
import { getOidcConfig, startOidcLogin } from "../api/client";

export function Login() {
  const { login, verifyMfa } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [utcTime, setUtcTime] = useState("");
  const [oidcEnabled, setOidcEnabled] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().slice(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    let active = true;
    void getOidcConfig()
      .then(({ enabled }) => {
        if (active) setOidcEnabled(enabled);
      })
      .catch(() => {
        if (active) setOidcEnabled(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const complete = () => navigate("/", { replace: true });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mfaToken) {
        // Second step: MFA code
        await verifyMfa(mfaToken, mfaCode.trim());
        complete();
        return;
      }
      const result = await login(email, password);
      if (result.status === "mfa" && result.mfaToken) {
        setMfaToken(result.mfaToken);
        return;
      }
      complete();
    } catch (err) {
      if (mfaToken) {
        setError(err instanceof Error ? err.message : "Verification failed.");
      } else {
        setError(err instanceof Error ? err.message : "Authentication failed. Check credentials.");
      }
    } finally {
      setBusy(false);
    }
  };

  const beginSso = async () => {
    setBusy(true);
    setError(null);
    try {
      await startOidcLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start SSO sign-in.");
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-ink-950 px-4 py-12 font-sans text-ink-100 overflow-hidden">
      {/* Background Cyber Ambient & Radial Gradients */}
      <div className="absolute inset-0 cyber-grid opacity-60 pointer-events-none" />
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[500px] bg-accent/8 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-0 inset-x-0 h-48 bg-gradient-to-t from-ink-950 to-transparent pointer-events-none" />

      {/* Main Terminal Card */}
      <div className="relative z-10 w-full max-w-md">
        {/* Top Telemetry / Status Pill */}
        <div className="mb-4 flex items-center justify-between rounded-xl border border-ink-700/60 bg-ink-900/70 px-4 py-2 text-2xs font-mono text-ink-400 backdrop-blur-md shadow-sm">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-accent animate-pulse shadow-[0_0_8px_#00d4ff]" />
            <span className="tracking-[0.16em] uppercase text-ink-300 font-semibold">
              SECURE ENCLAVE // NODE 01
            </span>
          </div>
          <span className="tabular-nums tracking-wider text-accent">{utcTime || "UTC TIME"}</span>
        </div>

        {/* Card Box with Specular Border and Backdrop Blur */}
        <div className="relative overflow-hidden rounded-2xl border border-ink-700/80 bg-gradient-to-b from-ink-900/95 via-ink-850/90 to-ink-900/95 shadow-2xl backdrop-blur-2xl">
          {/* Top Specular Neon Line */}
          <div className="h-[2px] w-full bg-gradient-to-r from-transparent via-accent to-transparent shadow-[0_0_12px_#00d4ff]" />

          <div className="p-8 sm:p-10">
            {/* Logo & Platform Header */}
            <div className="flex flex-col items-center text-center">
              <div className="relative mb-5 flex h-20 w-20 items-center justify-center rounded-2xl border border-accent/40 bg-gradient-to-br from-ink-900 to-ink-950 p-3.5 shadow-[0_0_30px_rgba(0,212,255,0.25)] ring-1 ring-accent/30">
                <img
                  src="/logo.png"
                  alt="Rynex Logo"
                  className="h-full w-full object-contain drop-shadow-[0_0_12px_rgba(0,212,255,0.6)]"
                />
              </div>

              <h1 className="text-xl font-bold uppercase tracking-[0.1em] text-white font-mono bg-gradient-to-r from-white via-ink-100 to-accent bg-clip-text text-transparent">
                Rynex Threat Intelligence
              </h1>
              <p className="mt-1.5 text-2xs uppercase tracking-[0.22em] text-accent font-mono font-medium flex items-center gap-1.5">
                <Sparkles className="h-3 w-3" />
                Detect · Exploit · Respond
              </p>
            </div>

            {/* Form */}
            <form onSubmit={submit} className="mt-8 space-y-4">
              {mfaToken ? (
                <div>
                  <label className="block text-xs font-semibold text-ink-200 font-mono mb-2">
                    AUTHENTICATOR TOTP CODE
                  </label>
                  <input
                    type="text"
                    required
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    autoFocus
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/[^0-9]/g, ""))}
                    className="w-full rounded-xl border border-ink-700/90 bg-ink-950 py-3 px-4 text-base text-ink-100 placeholder:text-ink-600 font-mono tracking-[0.5em] text-center focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-2 focus:ring-accent/30 transition-all shadow-inner"
                    placeholder="000000"
                  />
                  <p className="mt-2 text-[11px] text-ink-400 font-mono text-center">
                    Enter the 6-digit verification code from your authenticator device.
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-medium text-ink-300 font-mono mb-1.5">
                      OPERATOR IDENTITY / EMAIL
                    </label>
                    <div className="relative">
                      <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-ink-400">
                        <Mail className="h-4 w-4" />
                      </div>
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="w-full rounded-xl border border-ink-700/80 bg-ink-950/90 py-2.5 pl-10 pr-3.5 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-2 focus:ring-accent/25 transition-all shadow-inner"
                        placeholder="analyst@rynexsecurity.com"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-ink-300 font-mono mb-1.5">
                      ACCESS CIPHER / PASSWORD
                    </label>
                    <div className="relative">
                      <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-ink-400">
                        <Lock className="h-4 w-4" />
                      </div>
                      <input
                        type={showPassword ? "text" : "password"}
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full rounded-xl border border-ink-700/80 bg-ink-950/90 py-2.5 pl-10 pr-10 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-2 focus:ring-accent/25 transition-all shadow-inner"
                        placeholder="••••••••••••"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute inset-y-0 right-0 flex items-center pr-3.5 text-ink-400 hover:text-ink-200 transition-colors"
                        aria-label={showPassword ? "Hide password" : "Show password"}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {error && (
                <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-200 font-mono">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={busy}
                className="w-full rounded-xl bg-gradient-to-r from-accent via-cyan-400 to-accent py-3 text-xs font-mono font-bold uppercase tracking-[0.18em] text-black transition-all duration-200 hover:shadow-[0_0_25px_rgba(0,212,255,0.45)] hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 mt-4"
              >
                {busy ? (
                  <>
                    <div className="h-4 w-4 animate-spin border-2 border-black border-t-transparent rounded-full" />
                    <span>{mfaToken ? "Verifying Code…" : "Verifying Credentials…"}</span>
                  </>
                ) : (
                  <span>{mfaToken ? "Confirm Identity" : "Access Threat Platform"}</span>
                )}
              </button>
            </form>

            {oidcEnabled && !mfaToken && (
              <>
                <div className="my-6 flex items-center gap-3 text-[10px] font-mono uppercase tracking-widest text-ink-500">
                  <span className="h-px flex-1 bg-ink-700/80" />
                  <span>enterprise identity federation</span>
                  <span className="h-px flex-1 bg-ink-700/80" />
                </div>
                <button
                  type="button"
                  onClick={beginSso}
                  disabled={busy}
                  className="w-full rounded-xl border border-ink-700/90 bg-ink-950 py-2.5 text-xs font-mono font-bold uppercase tracking-[0.15em] text-ink-200 transition-all hover:border-accent hover:text-accent hover:bg-ink-900 disabled:opacity-40"
                >
                  Continue with SSO (SAML / OIDC)
                </button>
              </>
            )}

            {/* Security Warning Notice */}
            <div className="mt-8 border-t border-ink-700/70 pt-5 text-center">
              <p className="text-[10px] leading-relaxed text-ink-400 font-mono">
                RESTRICTED SOC SYSTEM · AUDIT MONITORING ENGAGED
                <br />
                All transactions are logged with cryptographic verification.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
