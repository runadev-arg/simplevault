"use client";

/**
 * useAutoLock — 15-minute idle auto-lock for the (authed) tree.
 *
 * INVARIANTS (REQ-WEBSEC-007 + Phase 04 Key Link 4):
 *   - PURE CLIENT. Server is unaware: no network call on lock, no log line,
 *     no DB column. The user's refresh cookie is NOT revoked — auto-lock
 *     means "wipe master_DEK from RAM and bounce to /login", not "remote
 *     logout". Operator-confirmed default (Plan 04-08).
 *   - Activity events tracked: `pointerdown`, `keydown`, `visibilitychange`.
 *     Note `pointerdown` (not `pointermove`): mouse drift across pixels
 *     would mask actual idleness.
 *   - `visibilitychange` is treated as ACTIVITY (timer reset), NOT as a
 *     trigger. Tab-switching back is the user signalling presence; we do
 *     NOT lock immediately on visibility-hidden either — operator wants
 *     the same 15-min idle window regardless of tab focus.
 *   - On idle expiry: `keyStore.wipe()` zeroes the in-memory master_DEK +
 *     other Uint8Array material; `accessTokenStore.wipe()` drops the JWT;
 *     `router.replace('/login?reason=auto_lock')` shows the banner.
 *
 * Configurable via `NEXT_PUBLIC_AUTO_LOCK_IDLE_MS` (build-time). Default
 * 900_000 ms (15 min). Operator override per-deployment via Next.js env;
 * documented in `.env.example` + RUNBOOK (Plan 04-12 finalises).
 */

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { accessTokenStore } from "./access-token-store";
import { keyStore } from "./key-store";

const DEFAULT_IDLE_MS = 900_000;

function parseIdleMs(): number {
  const raw = process.env.NEXT_PUBLIC_AUTO_LOCK_IDLE_MS;
  if (typeof raw !== "string" || raw === "") return DEFAULT_IDLE_MS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_IDLE_MS;
}

export const AUTO_LOCK_IDLE_MS = parseIdleMs();

/** Activity events that reset the idle timer. */
export const AUTO_LOCK_EVENTS: readonly (keyof DocumentEventMap)[] = [
  "pointerdown",
  "keydown",
  "visibilitychange",
];

export interface AutoLockRouter {
  replace(href: string): void;
}

export interface AttachAutoLockOptions {
  /** Override the idle window (ms). Defaults to `AUTO_LOCK_IDLE_MS`. */
  idleMs?: number;
  /** Document-like event target. Defaults to global `document`. */
  doc?: Pick<Document, "addEventListener" | "removeEventListener">;
  /** Test seam — overrides `keyStore.wipe()`. */
  onWipe?: () => void;
  /** Test seam — overrides `accessTokenStore.wipe()`. */
  onClearToken?: () => void;
}

/**
 * Imperative core, extracted so it can be unit-tested without a DOM
 * runtime. The React hook below is a thin `useEffect` wrapper.
 *
 * Returns a cleanup function that detaches listeners + clears the timer.
 */
export function attachAutoLock(
  router: AutoLockRouter,
  options: AttachAutoLockOptions = {},
): () => void {
  const idleMs = options.idleMs ?? AUTO_LOCK_IDLE_MS;
  const doc = options.doc ?? (typeof document !== "undefined" ? document : undefined);
  if (!doc) {
    // SSR / non-browser — nothing to attach.
    return (): void => {
      /* no-op */
    };
  }
  const wipe = options.onWipe ?? ((): void => { keyStore.wipe(); });
  const clearToken = options.onClearToken ?? ((): void => { accessTokenStore.wipe(); });

  let timer: ReturnType<typeof setTimeout> | null = null;
  let fired = false;

  const onIdle = (): void => {
    if (fired) return;
    fired = true;
    wipe();
    clearToken();
    router.replace("/login?reason=auto_lock");
  };

  const reset = (): void => {
    if (fired) return;
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(onIdle, idleMs);
  };

  for (const e of AUTO_LOCK_EVENTS) {
    doc.addEventListener(e, reset, { passive: true });
  }
  reset(); // start the timer on mount

  return (): void => {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    for (const e of AUTO_LOCK_EVENTS) {
      doc.removeEventListener(e, reset);
    }
  };
}

/**
 * React hook — mount once at the (authed) tree root.
 */
export function useAutoLock(): void {
  const router = useRouter();
  useEffect(() => {
    return attachAutoLock(router);
  }, [router]);
}
