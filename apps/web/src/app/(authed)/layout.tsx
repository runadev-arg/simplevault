"use client";

import type { JSX, ReactNode } from "react";
import { useEffect } from "react";

import { AuthProvider, useAuth } from "../../lib/auth/auth-context";
import { useAutoLock } from "../../lib/auth/use-auto-lock";

/**
 * (authed) route group — client-side guard.
 *
 * Server components can't gate on the access token because it's in
 * memory only (no cookie/header readable from RSC). So the guard is
 * a thin client wrapper that:
 *
 *   1. Mounts the AuthProvider (auto-refresh hook + bootstrap from
 *      `__Host-refresh` cookie if alive).
 *   2. While bootstrapping, renders a minimal "checking…" splash so
 *      the protected page never flashes its content to a logged-out
 *      caller.
 *   3. If post-bootstrap there's no access token, hard-redirect to
 *      /login.
 */

function AuthGate({ children }: { children: ReactNode }): JSX.Element {
  const { accessToken, bootstrapped } = useAuth();

  // Plan 04-08 — 15-min idle auto-lock. Mounted at the (authed) tree
  // root; the hook itself short-circuits on SSR (no `document`). We
  // mount it unconditionally inside `AuthGate` so the timer is armed
  // the moment the bootstrap splash renders — there is no harm if the
  // user is mid-bootstrap, since `keyStore.wipe()` is idempotent.
  useAutoLock();

  useEffect(() => {
    if (bootstrapped && accessToken === null) {
      window.location.assign("/login");
    }
  }, [bootstrapped, accessToken]);

  if (!bootstrapped) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Checking session…</p>
      </main>
    );
  }
  if (accessToken === null) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Redirecting to sign-in…</p>
      </main>
    );
  }
  return <>{children}</>;
}

export default function AuthedLayout({ children }: { children: ReactNode }): JSX.Element {
  return (
    <AuthProvider>
      <AuthGate>{children}</AuthGate>
    </AuthProvider>
  );
}
