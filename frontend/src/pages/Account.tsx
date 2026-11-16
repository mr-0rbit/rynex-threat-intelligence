/* Account.tsx — self-service security: password change + TOTP MFA enrollment.
 *
 * Password change bumps the server token_version, so the backend returns a
 * fresh access token which we swap into memory. MFA enrollment: /mfa/setup →
 * manual secret entry into an authenticator app → /mfa/confirm (disabled
 * until confirmed). Disable always requires a currently-valid code.
 */

import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, Lock, ShieldCheck, ShieldOff, UserCog } from "lucide-react";
import { api, storeAccessToken } from "../api/client";
import { Badge, Card, CardHeader } from "../components/ui";
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
        storeAccessToken(resp.access_token);
      }
      setCurrentPw("");
      setNewPw("");
      setNewPw2("");
      setPwMsg({ ok: true, text: "Password changed successfully. All other active sessions terminated." });
    } catch (err) {
      setPwMsg({ ok: false, text: err instanceof Error ? err.message : "Password update failed" });
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
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "MFA enrollment failed" });
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
      setMfaMsg({ ok: true, text: "Multi-factor authentication confirmed and active." });
      refreshUser();
    } catch (err) {
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "Code confirmation failed" });
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
      setMfaMsg({ ok: true, text: "MFA disabled on this account." });
      refreshUser();
    } catch (err) {
      setMfaMsg({ ok: false, text: err instanceof Error ? err.message : "MFA disable failed" });
    } finally {
      setMfaBusy(false);
    }
  };

  const inputCls =
    "w-full rounded-xl border border-ink-700/80 bg-ink-950 py-2.5 px-3.5 text-xs text-ink-100 placeholder:text-ink-600 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-2 focus:ring-accent/25 transition-all shadow-inner";
  const labelCls = "block text-[11px] font-bold uppercase tracking-wider text-ink-300 font-mono mb-1.5";
  const btnCls =
    "rounded-xl bg-accent px-5 py-2.5 text-xs font-mono font-bold uppercase tracking-wider text-black transition-all hover:bg-white hover:shadow-[0_0_15px_rgba(0,212,255,0.4)] disabled:opacity-40 disabled:cursor-not-allowed";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      {/* Header */}
      <div className="border-b border-ink-700/60 pb-5">
        <div className="flex items-center gap-2.5">
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <UserCog className="h-5 w-5 text-accent" />
            Security &amp; Operator Profile
          </h1>
          <Badge variant="cyan">ACCOUNT PREFERENCES</Badge>
        </div>
        <p className="mt-1 text-xs text-ink-400 font-sans">
          Manage platform authentication credentials, TOTP hardware multi-factor tokens, and session authority.
        </p>
      </div>

      {/* Operator Identity Card */}
      <Card>
        <CardHeader title="Operator Identity" subtitle="Active session authorization details" />
        <div className="p-5">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <p className="text-[10px] font-mono uppercase tracking-wider text-ink-400">EMAIL ADDRESS</p>
              <p className="mt-1 text-sm font-bold text-white font-mono truncate">{user?.email}</p>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <p className="text-[10px] font-mono uppercase tracking-wider text-ink-400">ACCESS ROLE</p>
              <div className="mt-1 flex items-center gap-2">
                <Badge variant="cyan">{user?.role || "ANALYST"}</Badge>
              </div>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <p className="text-[10px] font-mono uppercase tracking-wider text-ink-400">TOTP PROTECTION</p>
              <div className="mt-1">
                {user?.mfa_enabled ? (
                  <Badge variant="success">ENFORCED &amp; ACTIVE</Badge>
                ) : (
                  <Badge variant="warning">DISABLED — RECOMMENDED</Badge>
                )}
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Change Password Card */}
      <Card>
        <CardHeader title="Update Security Credentials" subtitle="Minimum 12 characters with upper, lower, and digit combinations" />
        <form onSubmit={changePassword} className="max-w-lg space-y-4 p-5">
          <div>
            <label className={labelCls}>Current Password</label>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              className={inputCls}
              placeholder="••••••••••••"
            />
          </div>
          <div>
            <label className={labelCls}>New Password</label>
            <input
              type="password"
              required
              autoComplete="new-password"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              className={inputCls}
              placeholder="••••••••••••"
            />
          </div>
          <div>
            <label className={labelCls}>Confirm New Password</label>
            <input
              type="password"
              required
              autoComplete="new-password"
              value={newPw2}
              onChange={(e) => setNewPw2(e.target.value)}
              className={inputCls}
              placeholder="••••••••••••"
            />
          </div>

          <button type="submit" disabled={pwBusy} className={`${btnCls} inline-flex items-center gap-2`}>
            <KeyRound className="h-4 w-4" />
            <span>{pwBusy ? "Rotating Secret…" : "Change Access Password"}</span>
          </button>

          {pwMsg && (
            <div
              className={`rounded-xl border p-3 text-xs font-mono ${
                pwMsg.ok
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/40 bg-rose-500/10 text-rose-300"
              }`}
            >
              {pwMsg.text}
            </div>
          )}
        </form>
      </Card>

      {/* Multi-Factor Authentication Card */}
      <Card>
        <CardHeader
          title="Hardware Multi-Factor Authentication (TOTP)"
          subtitle="Compatible with Google Authenticator, 1Password, YubiKey, Aegis, and Bitwarden"
        />
        <div className="p-5">
          {user?.mfa_enabled ? (
            <form onSubmit={disableMfa} className="max-w-lg space-y-4">
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3.5 flex items-center gap-2.5 text-xs font-mono text-emerald-300">
                <ShieldCheck className="h-5 w-5 text-emerald-400 shrink-0" />
                <span>Multi-factor authentication is currently enforcing cryptographic session security.</span>
              </div>
              <div>
                <label className={labelCls}>Enter Current 6-Digit Authenticator Code</label>
                <input
                  type="text"
                  required
                  inputMode="numeric"
                  maxLength={6}
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/[^0-9]/g, ""))}
                  className={`${inputCls} tracking-[0.5em] text-center text-sm`}
                  placeholder="000000"
                />
              </div>
              <button
                type="submit"
                disabled={mfaBusy}
                className="rounded-xl border border-rose-500/40 bg-rose-500/15 px-5 py-2.5 text-xs font-mono font-bold uppercase tracking-wider text-rose-300 hover:bg-rose-500 hover:text-white transition-all disabled:opacity-40 flex items-center gap-2"
              >
                <ShieldOff className="h-4 w-4" />
                <span>{mfaBusy ? "Disabling…" : "Deactivate MFA"}</span>
              </button>
            </form>
          ) : enrollSecret ? (
            <form onSubmit={confirmMfa} className="max-w-lg space-y-4">
              <p className="text-xs text-ink-300 font-sans leading-relaxed">
                Scan or enter the seed key below into your authenticator app, then confirm the generated 6-digit code.
              </p>
              <div className="rounded-xl border border-ink-700/80 bg-ink-950 p-4 space-y-2">
                <p className={labelCls}>Authenticator Secret Seed (Base32)</p>
                <p className="break-all font-mono text-sm font-bold text-accent select-all bg-ink-900 p-2 rounded-lg border border-ink-800">
                  {enrollSecret}
                </p>
                {enrollUri && (
                  <>
                    <p className={`${labelCls} pt-2`}>otpauth URI</p>
                    <p className="break-all font-mono text-2xs text-ink-400 select-all bg-ink-900 p-2 rounded-lg border border-ink-800">
                      {enrollUri}
                    </p>
                  </>
                )}
              </div>
              <div>
                <label className={labelCls}>Enter 6-Digit Verification Code</label>
                <input
                  type="text"
                  required
                  inputMode="numeric"
                  autoFocus
                  maxLength={6}
                  value={confirmCode}
                  onChange={(e) => setConfirmCode(e.target.value.replace(/[^0-9]/g, ""))}
                  className={`${inputCls} tracking-[0.5em] text-center text-sm`}
                  placeholder="000000"
                />
              </div>
              <button type="submit" disabled={mfaBusy} className={`${btnCls} inline-flex items-center gap-2`}>
                <Lock className="h-4 w-4" />
                <span>{mfaBusy ? "Activating…" : "Confirm & Enable MFA"}</span>
              </button>
            </form>
          ) : (
            <div className="max-w-lg space-y-4">
              <p className="text-xs text-ink-300 font-sans leading-relaxed">
                Strengthen your threat analyst account against credential stuffing and compromised passwords with time-based one-time passcodes (TOTP).
              </p>
              <button onClick={startMfa} disabled={mfaBusy} className={`${btnCls} inline-flex items-center gap-2`}>
                <ShieldCheck className="h-4 w-4" />
                <span>{mfaBusy ? "Generating Secret…" : "Set Up MFA Protection"}</span>
              </button>
            </div>
          )}

          {mfaMsg && (
            <div
              className={`mt-4 rounded-xl border p-3 text-xs font-mono ${
                mfaMsg.ok
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                  : "border-rose-500/40 bg-rose-500/10 text-rose-300"
              }`}
            >
              {mfaMsg.text}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
