"use client";

import type { JSX } from "react";

import { RevokeAllButton } from "./revoke-all-button";
import { SessionList } from "./session-list";

/**
 * Phase 03 Plan 11 — `/settings/sessions` route.
 *
 * Lists active sessions for the caller (Truth 11), supports per-row revoke
 * (Truth 12) and a confirm-then-execute "Sign out everywhere except this
 * device" CTA (Truth 13). The current session is pinned + visually
 * distinct; the server also stamps `current: true` for resilience (we
 * prefer the server flag to JWT-side derivation).
 *
 * Rendering is fully client-side — `useAuth()` for the access token,
 * `listSessions()` on mount, optimistic refresh after revoke. The
 * (authed) layout already runs the JWT-bootstrap guard, so this page only
 * renders for an authenticated caller.
 */
export default function SessionsPage(): JSX.Element {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col gap-6 px-6 py-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Active sessions</h1>
        <p className="mt-2 text-sm text-zinc-400">
          These are the devices currently signed in to your account. Revoking a
          session signs that device out within seconds.
        </p>
      </header>
      <SessionList />
      <RevokeAllButton />
    </main>
  );
}
