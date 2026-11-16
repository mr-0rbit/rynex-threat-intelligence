import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "../auth";
import { Spinner } from "../components/ui";

export function OIDCCallback() {
  const { completeOidcLogin } = useAuth();
  const navigate = useNavigate();
  const handled = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const providerError = params.get("error");
    // Remove the one-use authorization code and state from browser history before
    // the network exchange; the HttpOnly state cookie remains available to fetch.
    window.history.replaceState({}, document.title, "/oidc/callback");

    if (providerError || !code || !state) {
      setError("The identity provider did not complete sign-in. Please try again.");
      return;
    }

    void completeOidcLogin(code, state)
      .then(() => navigate("/", { replace: true }))
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "SSO authentication failed.");
      });
  }, [completeOidcLogin, navigate]);

  if (error) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-ink-950 px-4 text-ink-100">
        <div className="max-w-md border border-red-500/40 bg-ink-900 p-6">
          <div className="flex items-center gap-2 text-red-300">
            <ShieldAlert className="h-5 w-5" />
            <h1 className="font-mono text-sm font-bold uppercase">SSO sign-in failed</h1>
          </div>
          <p className="mt-3 text-sm text-ink-300">{error}</p>
          <button
            className="mt-5 rounded bg-accent px-4 py-2 font-mono text-xs font-bold uppercase text-black"
            onClick={() => navigate("/login", { replace: true })}
          >
            Return to sign in
          </button>
        </div>
      </main>
    );
  }

  return <Spinner label="Completing secure SSO sign-in…" />;
}
