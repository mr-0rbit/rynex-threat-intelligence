/* Account.tsx — self-service security: password change + TOTP MFA enrollment.
 *
 * Password change bumps the server token_version, so the backend returns a
 * fresh access token which we swap into memory. MFA enrollment: /mfa/setup →
 * manual secret entry into an authenticator app → /mfa/confirm (disabled
 * until confirmed). Disable always requires a currently-valid code.
 */

import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, Lock, ShieldCheck, ShieldOff } from "lucide-react";
import { api, storeAccessToken } from "../api/client";
import { Card, CardHeader } from "../components/ui";
import { useAuth } from "../auth";

interface ChangePasswordBody {
  current_password: string;
  new_password: string;
}

interface MFASetupBody {
  secret: string;
  otpauth_uri: string;
}

export function Account() {
  const { user, refreshUser } = useAuth();

  // --- change password ---
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [pwBusy, setPwBusy] = useState(false);

  // --- MFA ---
  const [mfaBusy, setMfaBusy] = useState(false);
  const [mfaMsg, setMfaMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [enrollSecret, setEnrollSecret] = useState<string | null>(null);
  const [enrollUri, setEnrollUri] = useState<string | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [disableCode, setDisableCode] = useState("");

  useEffect(() => {
    // leave enrollment state clean on unmount secrets are short-lived anyway
    return () => setConfirmCode("");
  }, []);

  const changePassword = async (e: FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    if (newPw !== newPw2) {
      setPwMsg({ ok: false, text: "New passwords do not match." });
      return;
    }
    if (newPw === currentPw) {
      setPwMsg({ ok: false, text: "New password must differ from the current one." });
      return;
    }
    setPwBusy(true);
    try {
      const body: ChangePasswordBody = { current_password: currentPw, new_password: newPw };
      const resp = await api<{ access_token?: string }>("/auth/change-password", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (resp?.access_token) {
        // token_version was bumped server-side — swap in the fresh token
        storeAccessToken(resp.access_token);
      }
      setCurrentPw("");
      setNewPw("");
      setNewPw2("");
      setPwMsg({ ok: true, text: "Password changed. Other sessions were signed out." });
    } catch (err) {
      setPwMsg({ ok: false, text: err instanceof Error ? err.message : "Password change failed" });
    } finally {
      setPwBusy(false);
    }
  };

  const startMfa = async () => {
    setMfaMsg(null);
    setMfaBusy(true);
    try {
      const resp = await api<MFASetupBody>("/auth/mfa/setup", { method: "POST" });
      setEnrollSecret(resp.secret);
      setEnrollUri(resp.otpauth_uri);
    } catch (err) {
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "MFA setup failed" });
    } finally {
      setMfaBusy(false);
    }
  };

  const confirmMfa = async (e: FormEvent) => {
    e.preventDefault();
    setMfaMsg(null);
    setMfaBusy(true);
    try {
      await api("/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code: confirmCode.trim() }) });
      setEnrollSecret(null);
      setEnrollUri(null);
      setConfirmCode("");
      setMfaMsg({ ok: true, text: "MFA enabled. You will be asked for a code at next login." });
      refreshUser();
    } catch (err) {
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "Confirmation failed" });
    } finally {
      setMfaBusy(false);
    }
  };

  const disableMfa = async (e: FormEvent) => {
    e.preventDefault();
    setMfaMsg(null);
    setMfaBusy(true);
    try {
      await api("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code: disableCode.trim() }) });
      setDisableCode("");
      setMfaMsg({ ok: true, text: "MFA disabled." });
      refreshUser();
    } catch (err) {
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "Disable failed" });
    } finally {
      setMfaBusy(false);
    }
  };

  const inputCls =
    "w-full rounded border border-ink-600 bg-ink-950 py-2 px-3 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-1 focus:ring-accent/40 transition-colors";
  const labelCls = "block text-2xs font-medium uppercase tracking-[0.12em] text-ink-300 font-mono mb-1.5";
  const btnCls =
    "rounded bg-accent px-4 py-2 text-2xs font-bold uppercase tracking-[0.14em] text-black transition-colors hover:bg-white disabled:opacity-40 disabled:cursor-not-allowed";

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-white">Account</h1>
        <p className="text-xs text-ink-400">Credentials and multi-factor authentication</p>
      </div>

      <Card>
        <CardHeader title="Identity" />
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 px-4 py-3 text-xs">
          <dt className="text-ink-400 font-mono uppercase text-2xs tracking-wider">Email</dt>
          <dd className="text-ink-100 font-mono">{user?.email}</dd>
          <dt className="text-ink-400 font-mono uppercase text-2xs tracking-wider">Role</dt>
          <dd className="text-accent font-mono uppercase">{user?.role}</dd>
          <dt className="text-ink-400 font-mono uppercase text-2xs tracking-wider">MFA</dt>
          <dd className="font-mono">{user?.mfa_enabled ? <span className="text-accent">enabled</span> : <span className="text-ink-400">disabled</span>}</dd>
        </dl>
      </Card>

      <Card>
        <CardHeader title="Change password" subtitle="Minimum 12 characters with upper, lower and digit" />
        <form onSubmit={changePassword} className="max-w-md space-y-3 px-4 py-4">
          <div>
            <label className={labelCls}>Current password</label>
            <input type="password" required autoComplete="current-password" value={currentPw} onChange={(e) => setCurrentPw(e.target.value)} className={inputCls} />
          </div>
          <div>
            <label className={labelCls}>New password</label>
            <input type="password" required autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} className={inputCls} />
          </div>
          <div>
            <label className={labelCls}>Confirm new password</label>
            <input type="password" required autoComplete="new-password" value={newPw2} onChange={(e) => setNewPw2(e.target.value)} className={inputCls} />
          </div>
          <button type="submit" disabled={pwBusy} className={`${btnCls} inline-flex items-center gap-1.5`}>
            <KeyRound className="h-3.5 w-3.5" />
            {pwBusy ? "Updating…" : "Change password"}
          </button>
          {pwMsg && <p className={`text-xs font-mono ${pwMsg.ok ? "text-accent" : "text-ink-200 border-l-2 border-accent pl-2"}`}>{pwMsg.text}</p>}
        </form>
      </Card>

      <Card>
        <CardHeader
          title="Multi-factor authentication"
          subtitle="TOTP via any authenticator app (Google Authenticator, Aegis, 1Password…)"
        />
        <div className="px-4 py-4">
          {user?.mfa_enabled ? (
            <form onSubmit={disableMfa} className="max-w-md space-y-3">
              <p className="flex items-center gap-2 text-xs text-ink-300">
                <ShieldCheck className="h-4 w-4 text-accent" />
                MFA is active on this account. Disabling requires a currently valid code.
              </p>
              <div>
                <label className={labelCls}>Authenticator code</label>
                <input
                  type="text"
                  required
                  inputMode="numeric"
                  maxLength={6}
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/[^0-9]/g, ""))}
                  className={`${inputCls} tracking-[0.5em] text-center`}
                  placeholder="000000"
                />
              </div>
              <button type="submit" disabled={mfaBusy} className={`${btnCls} inline-flex items-center gap-1.5`}>
                <ShieldOff className="h-3.5 w-3.5" />
                {mfaBusy ? "Working…" : "Disable MFA"}
              </button>
            </form>
          ) : enrollSecret ? (
            <form onSubmit={confirmMfa} className="max-w-md space-y-3">
              <p className="text-xs text-ink-300">
                1. Add the secret below to your authenticator app (manual entry).<br />
                2. Enter the 6-digit code it generates to activate MFA.
              </p>
              <div className="rounded border border-ink-600 bg-ink-950 p-3">
                <p className={labelCls}>Secret (base32)</p>
                <p className="break-all font-mono text-sm text-accent">{enrollSecret}</p>
                {enrollUri && (
                  <>
                    <p className={`${labelCls} mt-3`}>otpauth URI (if your app supports it)</p>
                    <p className="break-all font-mono text-[10px] text-ink-400">{enrollUri}</p>
                  </>
                )}
              </div>
              <div>
                <label className={labelCls}>Verification code</label>
                <input
                  type="text"
                  required
                  inputMode="numeric"
                  autoFocus
                  maxLength={6}
                  value={confirmCode}
                  onChange={(e) => setConfirmCode(e.target.value.replace(/[^0-9]/g, ""))}
                  className={`${inputCls} tracking-[0.5em] text-center`}
                  placeholder="000000"
                />
              </div>
              <button type="submit" disabled={mfaBusy} className={`${btnCls} inline-flex items-center gap-1.5`}>
                <Lock className="h-3.5 w-3.5" />
                {mfaBusy ? "Verifying…" : "Confirm & enable MFA"}
              </button>
            </form>
          ) : (
            <div className="max-w-md space-y-3">
              <p className="text-xs text-ink-300">
                MFA is currently disabled. Add a second factor so a stolen password alone cannot access this console.
              </p>
              <button onClick={startMfa} disabled={mfaBusy} className={`${btnCls} inline-flex items-center gap-1.5`}>
                <ShieldCheck className="h-3.5 w-3.5" />
                {mfaBusy ? "Generating…" : "Set up MFA"}
              </button>
            </div>
          )}
          {mfaMsg && <p className={`mt-3 text-xs font-mono ${mfaMsg.ok ? "text-accent" : "text-ink-200 border-l-2 border-accent pl-2"}`}>{mfaMsg.text}</p>}
        </div>
      </Card>
    </div>
  );
}
