"use client";

import type { JSX } from "react";
import { useEffect, useState } from "react";

import {
  AuthClientError,
  me as apiMe,
  type MeResponse,
} from "../../../lib/api/auth-client";
import { useAuth } from "../../../lib/auth/auth-context";

/**
 * /me — minimal authenticated landing page.
 *
 * Renders the four fields locked by 02-09's MeResponseSchema:
 *   id, email, createdAt, argon2Params
 *
 * "Logout" button:
 *   - Calls AuthContext.logout() which POSTs /auth/logout, wipes the
 *     in-memory access token AND keyStore, then hard-redirects to /login.
 *   - On API failure we STILL wipe locally + redirect (defence in depth —
 *     never leave a user "still signed in" if logout fails).
 */

export default function MePage(): JSX.Element {
  const { accessToken, logout } = useAuth();
  const [data, setData] = useState<MeResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busyLogout, setBusyLogout] = useState(false);

  useEffect(() => {
    if (accessToken === null) return;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const res = await apiMe(accessToken);
        if (!flag.cancelled) setData(res);
      } catch (e) {
        if (flag.cancelled) return;
        if (e instanceof AuthClientError && e.status === 401) {
          setErr("Session expired. Refreshing…");
        } else if (e instanceof AuthClientError) {
          setErr(e.message);
        } else {
          setErr("Failed to load your profile.");
        }
      }
    })();
    return () => { flag.cancelled = true; };
  }, [accessToken]);

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col gap-6 px-6 py-10">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Your account</h1>
        <button
          type="button"
          disabled={busyLogout}
          onClick={() => {
            setBusyLogout(true);
            void logout();
          }}
          className="rounded-md bg-zinc-800 px-3 py-2 text-sm hover:bg-zinc-700 disabled:opacity-40"
        >
          {busyLogout ? "Signing out…" : "Logout"}
        </button>
      </header>

      {err && (
        <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          {err}
        </p>
      )}

      {data && (
        <dl className="space-y-3 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 text-sm">
          <div className="flex items-baseline gap-3">
            <dt className="w-32 text-zinc-400">User ID</dt>
            <dd className="font-mono text-zinc-200">{data.id}</dd>
          </div>
          <div className="flex items-baseline gap-3">
            <dt className="w-32 text-zinc-400">Email</dt>
            <dd className="text-zinc-200">{data.email}</dd>
          </div>
          <div className="flex items-baseline gap-3">
            <dt className="w-32 text-zinc-400">Created</dt>
            <dd className="text-zinc-200">{data.createdAt}</dd>
          </div>
          <div className="flex items-baseline gap-3">
            <dt className="w-32 text-zinc-400">Argon2id</dt>
            <dd className="font-mono text-xs text-zinc-300">
              memoryKiB={data.argon2Params.memoryKiB}, iterations={data.argon2Params.iterations}, parallelism={data.argon2Params.parallelism}
            </dd>
          </div>
        </dl>
      )}

      {!data && !err && (
        <p className="text-zinc-400">Loading…</p>
      )}
    </main>
  );
}
