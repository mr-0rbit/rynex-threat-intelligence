import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Activity } from "lucide-react";
import { useAuth } from "../auth";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-rynex-bg">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center">
          <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-xl bg-rynex-accent/10 ring-1 ring-rynex-accent/30">
            <Activity className="h-7 w-7 text-rynex-accent" />
          </div>
          <h1 className="text-xl font-bold text-white">Rynex Threat Intelligence</h1>
          <p className="mt-1 text-[11px] font-medium uppercase tracking-[0.25em] text-rynex-accent">
            Detect · Analyze · Respond
          </p>
        </div>
        <form onSubmit={submit} className="rounded-lg border border-rynex-border bg-rynex-panel p-6">
          <label className="block text-xs font-medium text-slate-400">Email</label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-rynex-border bg-rynex-bg px-3 py-2 text-sm text-slate-200 focus:border-rynex-accent/50 focus:outline-none"
            placeholder="analyst@rynex.tech"
          />
          <label className="mt-4 block text-xs font-medium text-slate-400">Password</label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-rynex-border bg-rynex-bg px-3 py-2 text-sm text-slate-200 focus:border-rynex-accent/50 focus:outline-none"
            placeholder="••••••••"
          />
          {error && <p className="mt-3 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="mt-5 w-full rounded-md bg-rynex-accent py-2 text-sm font-semibold text-black transition hover:bg-cyan-300 disabled:opacity-50"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
