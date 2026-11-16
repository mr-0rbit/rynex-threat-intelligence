import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import {
  api,
  clearTokens,
  getAccessToken,
  completeOidcLogin as apiCompleteOidcLogin,
  login as apiLogin,
  logout as apiLogout,
  setAuthCallbacks,
  tryRefresh,
  verifyMfa as apiVerifyMfa,
} from "./api/client";

interface User {
  id: string;
  email: string;
  role: string;
  full_name: string | null;
  mfa_enabled?: boolean;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  /** Returns mfaToken when an MFA challenge was issued (call verifyMfa next). */
  login: (email: string, password: string) => Promise<{ status: "session" | "mfa"; mfaToken?: string }>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  completeOidcLogin: (code: string, state: string) => Promise<void>;
  logout: () => void;
  /** Re-fetch /auth/me (e.g. after enabling/disabling MFA). */
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  login: async () => ({ status: "session" }),
  verifyMfa: async () => {},
  completeOidcLogin: async () => {},
  logout: async () => {},
  refreshUser: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setAuthCallbacks(() => setUser(null));
    // No access token in memory after a page load — try the httpOnly cookie.
    const boot = async () => {
      try {
        if (!getAccessToken()) {
          const refreshed = await tryRefresh();
          if (!refreshed) {
            setUser(null);
            return;
          }
        }
        const me = await api<User>("/auth/me");
        setUser(me);
      } catch {
        setUser(null);
        clearTokens();
      } finally {
        setLoading(false);
      }
    };
    boot();
  }, []);

  const login = async (email: string, password: string) => {
    const result = await apiLogin(email, password);
    if (result.mfa_required && result.mfa_token) {
      return { status: "mfa" as const, mfaToken: result.mfa_token };
    }
    const me = await api<User>("/auth/me");
    setUser(me);
    return { status: "session" as const };
  };

  const verifyMfa = async (mfaToken: string, code: string) => {
    await apiVerifyMfa(mfaToken, code);
    const me = await api<User>("/auth/me");
    setUser(me);
  };

  const completeOidcLogin = async (code: string, state: string) => {
    await apiCompleteOidcLogin(code, state);
    const me = await api<User>("/auth/me");
    setUser(me);
  };

  const logout = async () => {
    await apiLogout();
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const me = await api<User>("/auth/me");
      setUser(me);
    } catch {
      // token expired mid-flight — api() already triggered the logout callback
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, verifyMfa, completeOidcLogin, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
