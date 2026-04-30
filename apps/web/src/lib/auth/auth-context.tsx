"use client";

import type { JSX, ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { logout as apiLogout, refresh as apiRefresh } from "../api/auth-client";

import { accessTokenStore } from "./access-token-store";
import { keyStore } from "./key-store";
import { useAutoRefresh } from "./use-auto-refresh";

/**
 * AuthContext — single source of truth for `accessToken` in the React tree.
 *
 * Bootstrap behaviour: on mount, if there's no in-memory access token
 * (e.g. browser hard-refresh on /me), call /auth/refresh ONCE — if the
 * `__Host-refresh` cookie is still alive, transparently re-auth. If it
 * isn't, mark `bootstrapped: true` with `accessToken: null` so the
 * (authed) guard redirects to /login.
 *
 * NOTE: the cookie carries a refresh token but unwrapping the wrapped
 * key material requires `secret_key` + `master_password` — those are NOT
 * in the cookie. After a hard refresh we get a fresh access token but
 * the keyStore is empty until the user re-logs-in. Phase 04+ will
 * deal with this UX (e.g., partial unlock for read-only views, or
 * forced re-prompt). For Phase 02 the (authed) /me page is allowed to
 * function on access-token alone — it doesn't need master_DEK.
 */

export interface AuthContextValue {
  accessToken: string | null;
  bootstrapped: boolean;
  /** Imperative logout — wipes everything + redirects to /login. */
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readToken(): string | null {
  return accessTokenStore.get();
}

export function AuthProvider({ children }: { children: ReactNode }): JSX.Element {
  const [accessToken, setAccessToken] = useState<string | null>(() => readToken());
  const [bootstrapped, setBootstrapped] = useState(false);

  // Subscribe to store changes so login/logout from anywhere updates the tree.
  useEffect(() => {
    const unsub = accessTokenStore.subscribe(() => {
      setAccessToken(readToken());
    });
    return () => { unsub(); };
  }, []);

  // Bootstrap: if no token in memory, try /auth/refresh once. The
  // `__Host-refresh` cookie travels via credentials:include.
  useEffect(() => {
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      if (readToken() !== null) {
        if (!flag.cancelled) setBootstrapped(true);
        return;
      }
      try {
        const res = await apiRefresh();
        if (flag.cancelled) return;
        accessTokenStore.set(res.accessToken, res.expiresIn);
      } catch (e) {
        // No live session — leave token null. Don't surface an error UI here;
        // (authed) pages will redirect to /login.
        void e;
      } finally {
        if (!flag.cancelled) setBootstrapped(true);
      }
    })();
    return () => { flag.cancelled = true; };
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    // Defence in depth: try the API logout, but ALWAYS wipe locally.
    try {
      await apiLogout();
    } catch {
      // ignore — we still wipe + redirect
    }
    accessTokenStore.wipe();
    keyStore.wipe();
    window.location.assign("/login");
  }, []);

  // Auto-refresh wired here so it lives at the provider level.
  useAutoRefresh({
    onRefreshed: () => {
      // store.subscribe already updated `accessToken`; nothing else to do.
    },
    onAuthLost: () => {
      window.location.assign("/login");
    },
  });

  const value: AuthContextValue = { accessToken, bootstrapped, logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (ctx === null) {
    throw new Error("useAuth() must be called inside <AuthProvider>");
  }
  return ctx;
}
