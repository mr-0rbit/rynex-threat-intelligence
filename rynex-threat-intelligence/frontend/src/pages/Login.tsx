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
    <div className="flex min-h-screen items-center justify-center bg-ink-950">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center">
          <div className="mb-3 flex h-14 w-14 items-center justify-center rounded-none bg-accent/10 ring-1 ring-accent/40">
            <Activity className="h-7 w-7 text-accent" />
          </div>
          <h1 className="text-xl font-bold text-white">Rynex Threat Intelligence</h1>
          <p className="mt-1 text-[11px] font-medium uppercase tracking-[0.25em] text-accent">
            Detect · Analyze · Respond
          </p>
        </div>
        <form onSubmit={submit} className="rounded-sm border border-ink-600 bg-ink-800 p-6">
          <label className="block text-xs font-medium text-ink-300">Email</label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1.5 w-full rounded-sm border border-ink-600 bg-ink-950 px-3 py-2 text-sm text-ink-100 focus:border-accent/50 focus:outline-none"
            placeholder="analyst@rynex.tech"
          />
          <label className="mt-4 block text-xs font-medium text-ink-300">Password</label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1.5 w-full rounded-sm border border-ink-600 bg-ink-950 px-3 py-2 text-sm text-ink-100 focus:border-accent/50 focus:outline-none"
            placeholder="••••••••"
          />
          {error && <p className="mt-3 rounded border border-ink-500 bg-ink-700 px-3 py-2 text-xs text-white">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="mt-5 w-full rounded-sm bg-accent py-2 text-sm font-semibold text-black transition hover:bg-white disabled:opacity-50"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
