/** API client: token storage, auto-refresh on 401, typed helpers. */

const API = "/api/v1";

let accessToken: string | null = localStorage.getItem("rtip_access");
let refreshToken: string | null = localStorage.getItem("rtip_refresh");
let onLogout: (() => void) | null = null;

export function setAuthCallbacks(logout: () => void) {
  onLogout = logout;
}

export function getAccessToken() {
  return accessToken;
}

export function storeTokens(access: string, refresh: string) {
  accessToken = access;
  refreshToken = refresh;
  localStorage.setItem("rtip_access", access);
  localStorage.setItem("rtip_refresh", refresh);
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
  localStorage.removeItem("rtip_access");
  localStorage.removeItem("rtip_refresh");
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function tryRefresh(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const resp = await fetch(`${API}/auth/refresh?refresh_token=${encodeURIComponent(refreshToken)}`, {
      method: "POST",
    });
    if (!resp.ok) return false;
    const data = await resp.json();
    storeTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

export async function api<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const doFetch = () =>
    fetch(`${API}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...options.headers,
      },
    });

  let resp = await doFetch();
  if (resp.status === 401 && (await tryRefresh())) {
    resp = await doFetch();
  }
  if (resp.status === 401) {
    clearTokens();
    onLogout?.();
    throw new ApiError(401, "Session expired");
  }
  if (!resp.ok) {
    let detail = `Request failed (${resp.status})`;
    try {
      const body = await resp.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* ignore parse errors */ }
    throw new ApiError(resp.status, detail);
  }
  const ct = resp.headers.get("content-type") || "";
  return (ct.includes("json") ? resp.json() : resp.text()) as Promise<T>;
}

export async function login(email: string, password: string) {
  const resp = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!resp.ok) {
    const detail = resp.status === 401 ? "Invalid credentials" : `Login failed (${resp.status})`;
    throw new ApiError(resp.status, detail);
  }
  const data = await resp.json();
  storeTokens(data.access_token, data.refresh_token);
  return data as { role: string };
}
