"use client";

import type { JSX } from "react";
import { useCallback, useEffect, useState } from "react";

import { AuthClientError } from "../../../../lib/api/auth-client";
import {
  listSessions,
  type Session,
} from "../../../../lib/api/sessions-client";
import { useAuth } from "../../../../lib/auth/auth-context";

import { RevokeButton } from "./revoke-button";

/**
 * Renders the session list. Pulls `GET /sessions` once on mount + after a
 * successful revoke. Server returns rows with `current: true` for the
 * caller's session; we render that row pinned at the top, visually
 * distinct, and without a revoke button.
 */
export function SessionList(): JSX.Element {
  const { accessToken } = useAuth();
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    if (accessToken === null) return;
    setErr(null);
    try {
      const items = await listSessions(accessToken);
      setSessions(items);
    } catch (e) {
      if (e instanceof AuthClientError) setErr(e.message);
      else setErr("Failed to load sessions.");
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
  if (sessions === null) {
    return <p className="text-zinc-400">Loading…</p>;
  }

  // Truth 11 — current session pinned at top.
  const ordered = [...sessions].sort((a, b) => {
    if (a.current && !b.current) return -1;
    if (!a.current && b.current) return 1;
    return a.createdAt.localeCompare(b.createdAt);
  });
  const otherCount = ordered.filter((s) => !s.current).length;

  return (
    <ul className="flex flex-col gap-3">
      {ordered.map((s) => (
        <li
          key={s.id}
          className={
            s.current
              ? "rounded-md border border-emerald-500/40 bg-emerald-500/5 p-4"
              : "rounded-md border border-zinc-800 bg-zinc-900/40 p-4"
          }
        >
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium text-zinc-100">
                  {s.userAgentFamily}
                </span>
                {s.current && (
                  <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-200">
                    This device
                  </span>
                )}
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                fp: <span className="font-mono">{s.ipHashB64Prefix}</span>
                {" · "}
                created {formatRelative(s.createdAt)}
                {" · "}
                last used {formatRelative(s.lastUsedAt)}
              </div>
            </div>
            {!s.current && (
              <RevokeButton
                sessionId={s.id}
                onRevoked={() => {
                  void refresh();
                }}
              />
            )}
          </div>
        </li>
      ))}
      {otherCount === 0 && (
        <li className="rounded-md border border-dashed border-zinc-800 px-4 py-3 text-sm text-zinc-400">
          You have no other active sessions.
        </li>
      )}
    </ul>
  );
}

/**
 * Tiny relative-time formatter — avoids pulling `date-fns` (~40 KB) for one
 * use site. Intl.RelativeTimeFormat is a browser built-in and produces
 * locale-aware strings.
 */
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
