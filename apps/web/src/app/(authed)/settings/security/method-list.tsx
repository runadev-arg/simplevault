"use client";

import type { JSX } from "react";
import { useCallback, useEffect, useState } from "react";

import { AuthClientError } from "../../../../lib/api/auth-client";
import {
  getMethods,
  removeMethod,
  type TwoFaMethodView,
} from "../../../../lib/api/twofa-client";
import { useAuth } from "../../../../lib/auth/auth-context";

/**
 * Renders the user's active 2FA methods. Truth 9 — webauthn entries first
 * (server enforces the order), then totp, both sorted by createdAt asc.
 *
 * Per-row remove button (Truth 10):
 *   - 204 success → row disappears (re-fetches list)
 *   - 404 → uniform "couldn't remove this method" (anti-enumeration)
 *   - 409 AUTH_2FA_REMOVAL_BLOCKED → forward-looking copy mentioning shared
 *     vaults. Phase 03's stub never returns this; Phase 07 flips the dep.
 */
export function MethodList(): JSX.Element {
  const { accessToken } = useAuth();
  const [methods, setMethods] = useState<TwoFaMethodView[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    if (accessToken === null) return;
    setErr(null);
    try {
      const items = await getMethods(accessToken);
      setMethods(items);
    } catch (e) {
      if (e instanceof AuthClientError) setErr(e.message);
      else setErr("Failed to load 2FA methods.");
    }
  }, [accessToken]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (err !== null) {
    return (
      <p
        role="alert"
        className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
      >
        {err}
      </p>
    );
  }
  if (methods === null) {
    return <p className="text-zinc-400">Loading…</p>;
  }
  if (methods.length === 0) {
    return (
      <p className="rounded-md border border-dashed border-zinc-800 px-4 py-3 text-sm text-zinc-400">
        No 2FA methods enrolled. Add a passkey or authenticator app below to
        require a second factor at sign-in.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-2">
      {methods.map((m) => (
        <MethodRow key={m.id} method={m} onRemoved={refresh} />
      ))}
    </ul>
  );
}

interface MethodRowProps {
  method: TwoFaMethodView;
  onRemoved: () => void | Promise<void>;
}

function MethodRow({ method, onRemoved }: MethodRowProps): JSX.Element {
  const { accessToken } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const isPasskey = method.kind === "webauthn";
  return (
    <li className="rounded-md border border-zinc-800 bg-zinc-900/40 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm">
            <span className="font-medium text-zinc-100">{method.name}</span>
            {isPasskey ? (
              <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-200">
                PASSKEY
              </span>
            ) : (
              <span className="rounded bg-amber-500/20 px-2 py-0.5 text-xs text-amber-200">
                AUTHENTICATOR APP
              </span>
            )}
          </div>
          <div className="mt-1 text-xs text-zinc-500">
            added {formatRelative(method.createdAt)}
            {" · "}
            {method.lastUsedAt
              ? `last used ${formatRelative(method.lastUsedAt)}`
              : "never used"}
          </div>
        </div>
        <button
          type="button"
          disabled={busy || accessToken === null}
          onClick={() => {
            if (accessToken === null) return;
            setBusy(true);
            setErr(null);
            void (async () => {
              try {
                await removeMethod(accessToken, method.id);
                await onRemoved();
              } catch (e) {
                if (
                  e instanceof AuthClientError &&
                  e.status === 409 &&
                  e.code === "E1018"
                ) {
                  // AUTH_2FA_REMOVAL_BLOCKED — forward-looking copy for the
                  // shared-vault case (Phase 07 flips the dep).
                  setErr(
                    "You can't remove your last 2FA method while you're a member of a shared vault.",
                  );
                } else if (
                  e instanceof AuthClientError &&
                  e.status === 404
                ) {
                  setErr("Couldn't remove this method.");
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
          {busy ? "Removing…" : "Remove"}
        </button>
      </div>
      {err !== null && (
        <p role="alert" className="mt-2 text-xs text-red-300">
          {err}
        </p>
      )}
    </li>
  );
}

function formatRelative(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const diffSec = Math.round((then - Date.now()) / 1000);
  const abs = Math.abs(diffSec);
  const fmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60) return fmt.format(diffSec, "second");
  if (abs < 3600) return fmt.format(Math.round(diffSec / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(diffSec / 3600), "hour");
  if (abs < 30 * 86400) return fmt.format(Math.round(diffSec / 86400), "day");
  if (abs < 365 * 86400)
    return fmt.format(Math.round(diffSec / (30 * 86400)), "month");
  return fmt.format(Math.round(diffSec / (365 * 86400)), "year");
}
