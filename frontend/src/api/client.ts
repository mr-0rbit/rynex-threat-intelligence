/** API client: in-memory access token, httpOnly-cookie refresh, auto-retry on 401.
 *
 *  Security model: the SPA keeps ONLY the short-lived access token in memory.
 *  The refresh token lives in an httpOnly cookie (scoped to /api/v1/auth);
 *  cookie-based refresh requires the `X-CSRF-Client` header to block
 *  cross-site CSRF. No tokens in localStorage.
 */

const API = "/api/v1";
const CSRF_HEADER = "X-CSRF-Client";
const CSRF_VALUE = "rtip-refresh";

let accessToken: string | null = null;
let onLogout: (() => void) | null = null;

export function setAuthCallbacks(logout: () => void) {
  onLogout = logout;
}

export function getAccessToken() {
  return accessToken;
}

export function storeAccessToken(access: string) {
  accessToken = access;
}

export function clearTokens() {
  accessToken = null;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Silent refresh via the httpOnly cookie. Returns a new access token or null. */
export async function tryRefresh(): Promise<string | null> {
  try {
    const resp = await fetch(`${API}/auth/refresh`, {
      method: "POST",
      credentials: "same-origin",
      headers: { [CSRF_HEADER]: CSRF_VALUE },
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    accessToken = data.access_token;
    return data.access_token as string;
  } catch {
    return null;
  }
}

async function raiseFor(resp: Response): Promise<never> {
  if (resp.status === 401) {
    clearTokens();
    onLogout?.();
    throw new ApiError(401, "Session expired");
  }
  let detail = `Request failed (${resp.status})`;
  try {
    const body = await resp.json();
    if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
  } catch { /* ignore parse errors */ }
  throw new ApiError(resp.status, detail);
}

export async function api<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const doFetch = () =>
    fetch(`${API}${path}`, {
      ...options,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...options.headers,
      },
    });

  let resp = await doFetch();
  if (resp.status === 401) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      accessToken = refreshed;
      resp = await doFetch();
    }
  }
  if (!resp.ok) return raiseFor(resp) as never;
  const ct = resp.headers.get("content-type") || "";
  return (ct.includes("json") ? resp.json() : resp.text()) as Promise<T>;
}

export interface LoginResult {
  role?: string;
  mfa_required?: boolean;
  mfa_token?: string;
  access_token?: string;
}

/** Password login. May return an MFA challenge instead of a session. */
export async function login(email: string, password: string): Promise<LoginResult> {
  const resp = await fetch(`${API}/auth/login`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!resp.ok) {
    const detail = resp.status === 401 ? "Invalid credentials" : `Login failed (${resp.status})`;
    throw new ApiError(resp.status, detail);
  }
  const data = (await resp.json()) as LoginResult;
  if (data.access_token) {
    storeAccessToken(data.access_token);
  }
  return data;
}

/** Complete MFA login with the authenticator code. */
export async function verifyMfa(mfaToken: string, code: string): Promise<void> {
  const resp = await fetch(`${API}/auth/mfa/verify`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  });
  if (!resp.ok) {
    let detail = resp.status === 401 ? "Invalid or expired code" : `MFA failed (${resp.status})`;
    try {
      const body = await resp.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch { /* ignore */ }
    throw new ApiError(resp.status, detail);
  }
  const data = await resp.json();
  storeAccessToken(data.access_token);
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API}/auth/logout`, { method: "POST", credentials: "same-origin" });
  } catch { /* best-effort */ }
  clearTokens();
  onLogout?.();
}

/** Download a binary endpoint (e.g. PDF report) with the Bearer token attached.
 *  A plain <a href> cannot send Authorization headers, so we fetch a blob. */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const doFetch = () =>
    fetch(`${API}${path}`, {
      credentials: "same-origin",
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
    });
  let resp = await doFetch();
  if (resp.status === 401) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      accessToken = refreshed;
      resp = await doFetch();
    }
  }
  if (!resp.ok) return raiseFor(resp) as never;
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Authenticated WebSocket for the live alert feed. */
export function createAlertSocket(): WebSocket | null {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host; // same origin; vite proxies /api in dev
  const url = `${proto}//${host}/api/v1/ws/alerts?token=${encodeURIComponent(accessToken || "")}`;
  try {
    const ws = new WebSocket(url);
    return ws;
  } catch {
    return null;
  }
}
