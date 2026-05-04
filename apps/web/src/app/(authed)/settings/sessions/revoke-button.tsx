"use client";

import type { JSX } from "react";
import { useState } from "react";

import { AuthClientError } from "../../../../lib/api/auth-client";
import { revokeSession } from "../../../../lib/api/sessions-client";
import { useAuth } from "../../../../lib/auth/auth-context";

interface RevokeButtonProps {
  sessionId: string;
  onRevoked: () => void;
}

/**
 * Per-row "Sign out" button. On 404 (cross-user / unknown id — anti-
 * enumeration server-side), surfaces a generic "couldn't revoke" message:
 * we never tell the user the session was actually theirs but vanished.
 */
export function RevokeButton({
  sessionId,
  onRevoked,
}: RevokeButtonProps): JSX.Element {
  const { accessToken } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        disabled={busy || accessToken === null}
        onClick={() => {
          if (accessToken === null) return;
          setBusy(true);
          setErr(null);
          void (async () => {
            try {
              await revokeSession(accessToken, sessionId);
              onRevoked();
            } catch (e) {
              if (e instanceof AuthClientError && e.status === 404) {
                setErr("Couldn't revoke this session.");
              } else if (e instanceof AuthClientError) {
                setErr(e.message);
              } else {
                setErr("Network error.");
              }
            } finally {
              setBusy(false);
            }
          })();
        }}
        className="rounded-md bg-zinc-800 px-3 py-1.5 text-xs hover:bg-zinc-700 disabled:opacity-40"
      >
        {busy ? "Signing out…" : "Sign out"}
      </button>
      {err !== null && (
        <p role="alert" className="text-xs text-red-300">
          {err}
        </p>
      )}
    </div>
  );
}
