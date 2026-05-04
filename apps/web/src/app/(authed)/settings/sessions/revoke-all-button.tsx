"use client";

import type { JSX } from "react";
import { useState } from "react";

import { revokeAllSessions } from "../../../../lib/api/sessions-client";
import { accessTokenStore } from "../../../../lib/auth/access-token-store";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";

/**
 * "Sign out everywhere except this device" — confirm-then-execute. Truth 13.
 *
 * On confirm: POST /sessions/revoke-all (server bumps `users.session_epoch`
 * and clears the `__Host-refresh` cookie). Then locally wipe the
 * `accessTokenStore` + `keyStore` (zero-overwrites secret bytes) and hard-
 * navigate to /login. Defence-in-depth wipe-on-API-failure mirrors the
 * existing logout pattern (auth-context.tsx) so a transient 5xx never
 * leaves the user "still signed in" with stale secrets in memory.
 *
 * Cross-tab implication: revoke-all bumps the user's session_epoch.
 * Other open tabs of the same user lose their access token within
 * ≤ 60s (Plan 04 SessionEpochCache TTL) and the auto-refresh hook on
 * those tabs will fail and bounce them to /login.
 */
export function RevokeAllButton(): JSX.Element {
  const { accessToken } = useAuth();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  function wipeAndRedirect(): void {
    keyStore.wipe();
    accessTokenStore.wipe();
    window.location.assign("/login");
  }

  if (!confirming) {
    return (
      <button
        type="button"
        onClick={() => {
          setConfirming(true);
        }}
        className="self-start rounded-md border border-rose-500/40 bg-rose-500/5 px-4 py-2 text-sm text-rose-200 hover:bg-rose-500/10"
      >
        Sign out everywhere except this device
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-3 rounded-md border border-rose-500/40 bg-rose-500/5 p-4 text-sm">
      <p className="text-rose-100">
        This will sign you out of every device — including this one. You'll
        need to log in again here.
      </p>
      <div className="flex gap-2">
        <button
          type="button"
          disabled={busy || accessToken === null}
          onClick={() => {
            if (accessToken === null) return;
            setBusy(true);
            void (async () => {
              try {
                await revokeAllSessions(accessToken);
              } catch {
                // Defence-in-depth: ignore API failures — we still wipe + bounce.
              } finally {
                wipeAndRedirect();
              }
            })();
          }}
          className="rounded-md bg-rose-600 px-3 py-2 text-sm font-medium text-white hover:bg-rose-500 disabled:opacity-40"
        >
          {busy ? "Signing out…" : "Confirm — sign out everywhere"}
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setConfirming(false);
          }}
          className="rounded-md bg-zinc-800 px-3 py-2 text-sm hover:bg-zinc-700 disabled:opacity-40"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
