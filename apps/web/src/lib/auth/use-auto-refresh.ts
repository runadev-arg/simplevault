"use client";

import { useEffect, useRef } from "react";

import { AuthClientError, refresh as apiRefresh } from "../api/auth-client";

import { accessTokenStore } from "./access-token-store";
import { keyStore } from "./key-store";

/**
 * Auto-refresh hook.
 *
 * Schedules a `POST /auth/refresh` call ~60s before access-token expiry.
 * On success, replaces the in-memory access token and re-schedules.
 * On 401 / E1005 (refresh-token reuse OR family-revoked OR expired),
 * wipes EVERY in-memory secret + access token and hard-redirects to
 * /login. No retry loop — fail closed (per 02-08 SUMMARY).
 *
 * Also listens for `visibilitychange` so a tab that was backgrounded
 * past expiry refreshes immediately on return.
 *
 * USE ONLY ONCE per app — wire it up in the auth-context provider.
 */

const REFRESH_LEAD_MS = 60_000; // 60 s before exp

export function useAutoRefresh(opts: {
  /** Fired AFTER a successful refresh — context bumps its accessToken state. */
  onRefreshed: (newAccessToken: string) => void;
  /** Fired on hard failure (reuse-detect, expired, network). */
  onAuthLost: () => void;
}): void {
  const onRefreshedRef = useRef(opts.onRefreshed);
  const onAuthLostRef = useRef(opts.onAuthLost);
  onRefreshedRef.current = opts.onRefreshed;
  onAuthLostRef.current = opts.onAuthLost;

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const state: { cancelled: boolean; inFlight: boolean } = {
      cancelled: false,
      inFlight: false,
    };

    function clearTimer(): void {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    }

    async function doRefresh(): Promise<void> {
      if (state.cancelled || state.inFlight) return;
      state.inFlight = true;
      try {
        const res = await apiRefresh();
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- state.cancelled is mutated by the effect cleanup outside this async function.
        if (state.cancelled) return;
        accessTokenStore.set(res.accessToken, res.expiresIn);
        onRefreshedRef.current(res.accessToken);
        schedule();
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- mutated by effect cleanup
        if (state.cancelled) return;
        const isAuthFail =
          e instanceof AuthClientError &&
          (e.status === 401 ||
            e.code === "AUTH_REFRESH_REUSED" ||
            e.code === "AUTH_INVALID_CREDENTIALS" ||
            e.code === "E1005" ||
            e.code === "E1001");
        if (isAuthFail) {
          // Fail closed: wipe everything.
          accessTokenStore.wipe();
          keyStore.wipe();
          onAuthLostRef.current();
          return;
        }
        // Network blip — re-schedule a short retry (30 s) but no infinite loop.
        timer = setTimeout(() => { void doRefresh(); }, 30_000);
      } finally {
        state.inFlight = false;
      }
    }

    function schedule(): void {
      clearTimer();
      const expAt = accessTokenStore.expiresAt();
      if (expAt === 0) return; // no session to refresh
      const delay = Math.max(0, expAt - Date.now() - REFRESH_LEAD_MS);
      timer = setTimeout(() => { void doRefresh(); }, delay);
    }

    function onVisibility(): void {
      if (document.visibilityState !== "visible") return;
      // If we're already past lead-window, refresh immediately.
      const expAt = accessTokenStore.expiresAt();
      if (expAt === 0) return;
      if (expAt - Date.now() <= REFRESH_LEAD_MS) {
        void doRefresh();
      }
    }

    function onStoreChange(): void {
      // Token was set/cleared elsewhere (login completed, logout fired).
      const expAt = accessTokenStore.expiresAt();
      if (expAt === 0) {
        clearTimer();
      } else {
        schedule();
      }
    }

    // Initial schedule (covers post-login mounts) + subscribe.
    schedule();
    const unsub = accessTokenStore.subscribe(onStoreChange);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      state.cancelled = true;
      clearTimer();
      unsub();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);
}
