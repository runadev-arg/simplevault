"use client";

import { useRouter } from "next/navigation";
import type { JSX } from "react";
import { useCallback, useEffect, useState } from "react";

import { AuthClientError } from "../../../lib/api/auth-client";
import { accessTokenStore } from "../../../lib/auth/access-token-store";
import { keyStore } from "../../../lib/auth/key-store";
import {
  applyStepUpSession,
  completeWithPasskey,
  completeWithTotp,
  findTotpMatch,
  loadStepUpMaterial,
  type StepUpMaterialDerived,
  type StepUpResult,
} from "../../../lib/auth/step-up-flow";

/**
 * Phase 03 Plan 10 — `/login/2fa` step-up consumer (Truth 7 + 16).
 *
 * Reads the step-up token + 2FA-availability flags stashed by /login in
 * `sessionStorage` (key `"sv:step-up"`), then drives whichever ceremony
 * the user has enrolled:
 *
 *   - Passkey (PRIMARY when available — phishing-resistant per
 *     THREAT-MODEL §17): `completeWithPasskey` runs the WebAuthn
 *     assertion ceremony.
 *   - Authenticator app (SECONDARY): user types the 6-digit code; the
 *     client decrypts the wrapped TOTP secret with master_DEK derived
 *     from the password + secret_key kept in the keyStore across the
 *     soft `/login` → `/login/2fa` navigation.
 *
 * On success we run the same `unlockSecrets` path as 1FA-only login,
 * stash the access token + key material, hard-redirect to /me. On
 * permanent failure (missing handoff, expired step-up, etc.) we wipe
 * everything and bounce back to /login.
 */

interface StashedStepUp {
  token: string;
  twoFa: { webauthnAvailable: boolean; totpAvailable: boolean };
}

function readStash(): StashedStepUp | null {
  try {
    const raw = sessionStorage.getItem("sv:step-up");
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof (parsed as { token?: unknown }).token === "string" &&
      typeof (parsed as { twoFa?: { webauthnAvailable?: unknown; totpAvailable?: unknown } }).twoFa === "object"
    ) {
      const tw = (parsed as { twoFa: { webauthnAvailable?: unknown; totpAvailable?: unknown } }).twoFa;
      return {
        token: (parsed as { token: string }).token,
        twoFa: {
          webauthnAvailable: tw.webauthnAvailable === true,
          totpAvailable: tw.totpAvailable === true,
        },
      };
    }
  } catch {
    // ignore — treat as missing handoff
  }
  return null;
}

function clearStash(): void {
  try {
    sessionStorage.removeItem("sv:step-up");
  } catch {
    // ignore
  }
}

function wipeAndBounce(router: ReturnType<typeof useRouter>): void {
  clearStash();
  accessTokenStore.wipe();
  keyStore.wipe();
  router.replace("/login");
}

export default function TwoFaPage(): JSX.Element {
  const router = useRouter();
  const [stash, setStash] = useState<StashedStepUp | null>(null);
  const [bootstrapped, setBootstrapped] = useState(false);
  const [busy, setBusy] = useState(false);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [material, setMaterial] = useState<StepUpMaterialDerived | null>(null);

  useEffect(() => {
    const s = readStash();
    setStash(s);
    setBootstrapped(true);
    if (s === null) {
      // Direct navigation to /login/2fa without a prior /login → bounce.
      router.replace("/login");
    }
  }, [router]);

  // Lazy-fetch step-up material when TOTP is the only / fallback path.
  // For WebAuthn-only accounts we skip — the ceremony doesn't need it.
  useEffect(() => {
    if (stash === null || material !== null) return;
    if (!stash.twoFa.totpAvailable) return;
    void (async () => {
      try {
        const m = await loadStepUpMaterial(stash.token);
        setMaterial(m);
      } catch (e) {
        if (e instanceof AuthClientError && e.status === 401) {
          setErr("Step-up session expired. Please sign in again.");
          setTimeout(() => {
            wipeAndBounce(router);
          }, 1500);
        }
        // Other errors surface only when the user actually tries to verify.
      }
    })();
  }, [stash, material, router]);

  const finalize = useCallback(
    async (result: StepUpResult): Promise<void> => {
      const email = keyStore.getString("step_up_email");
      const password = keyStore.getString("step_up_password");
      const secretKey = keyStore.getBytes("step_up_secret_key");
      if (!email || !password || !secretKey) {
        // Lost the in-memory handoff (e.g. tab restored from history).
        // Best we can do is hand the user a fresh access token + bounce
        // them to /me, but they'll need to re-login to use the vault
        // (master_DEK is unrecoverable without the password).
        accessTokenStore.set(result.accessToken, result.expiresIn);
        clearStash();
        window.location.assign("/me");
        return;
      }
      accessTokenStore.set(result.accessToken, result.expiresIn);
      try {
        await applyStepUpSession(result, email, password, secretKey);
      } finally {
        // Drop the step-up bootstraps in keyStore — they're only useful
        // for the brief /login → /login/2fa window.
        keyStore.set("step_up_password", "");
        // Best-effort: zero the secret_key bytes referenced by the
        // step-up bootstrap entry. The "real" secret_key has been
        // re-set under "secret_key" by applyStepUpSession.
        const sk = keyStore.getBytes("step_up_secret_key");
        if (sk) sk.fill(0);
      }
      clearStash();
      window.location.assign("/me");
    },
    [],
  );

  async function onPasskey(): Promise<void> {
    if (stash === null || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const result = await completeWithPasskey(stash.token);
      await finalize(result);
    } catch (e) {
      if (e instanceof Error && e.name === "NotAllowedError") {
        setErr("Cancelled. Try again or use your authenticator app.");
      } else if (e instanceof AuthClientError) {
        setErr(e.message);
      } else if (e instanceof Error) {
        setErr(e.message);
      } else {
        setErr("Passkey ceremony failed.");
      }
      setBusy(false);
    }
  }

  async function onTotp(): Promise<void> {
    if (stash === null || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const m = material ?? (await loadStepUpMaterial(stash.token));
      if (material === null) setMaterial(m);
      const email = keyStore.getString("step_up_email");
      const password = keyStore.getString("step_up_password");
      const secretKey = keyStore.getBytes("step_up_secret_key");
      if (!email || !password || !secretKey) {
        setErr("Session expired — please sign in again.");
        setTimeout(() => {
          wipeAndBounce(router);
        }, 1500);
        return;
      }
      const match = await findTotpMatch(m, email, password, secretKey, code);
      const result = await completeWithTotp(
        stash.token,
        match.credentialId,
        match.candidateStep,
      );
      // Best-effort wipe of the step-up master_DEK derived inside findTotpMatch.
      match.masterDek.fill(0);
      await finalize(result);
    } catch (e) {
      if (e instanceof AuthClientError) {
        setErr(e.message);
      } else if (e instanceof Error) {
        setErr(e.message);
      } else {
        setErr("Verification failed.");
      }
      setBusy(false);
    }
  }

  if (!bootstrapped) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }
  if (stash === null) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Redirecting to sign-in…</p>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-10">
      <div className="w-full max-w-md space-y-6">
        <header className="space-y-2 text-center">
          <h1 className="text-3xl font-semibold tracking-tight">
            Two-factor authentication
          </h1>
          <p className="text-sm text-zinc-400">
            Choose how you'd like to confirm it's you. Your sign-in expires in
            about 2 minutes.
          </p>
        </header>

        {stash.twoFa.webauthnAvailable && (
          <section className="space-y-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 p-5">
            <h2 className="text-base font-semibold text-emerald-100">
              Use a passkey
            </h2>
            <p className="text-sm text-zinc-300">
              Your device will prompt for biometrics or a PIN. Recommended —
              phishing-resistant.
            </p>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                void onPasskey();
              }}
              className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
            >
              {busy ? "Verifying…" : "Use passkey"}
            </button>
          </section>
        )}

        {stash.twoFa.totpAvailable && (
          <section className="space-y-2 rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
            <h2 className="text-base font-semibold text-zinc-100">
              Enter code from authenticator app
            </h2>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => {
                setCode(e.target.value);
              }}
              maxLength={6}
              disabled={busy}
              placeholder="123456"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-mono tracking-widest text-zinc-100"
            />
            <button
              type="button"
              disabled={busy || code.trim().length !== 6}
              onClick={() => {
                void onTotp();
              }}
              className="rounded-md bg-zinc-700 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-600 disabled:opacity-40"
            >
              {busy ? "Verifying…" : "Verify code"}
            </button>
          </section>
        )}

        {err !== null && (
          <p
            role="alert"
            className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            {err}
          </p>
        )}

        <p className="text-center text-xs text-zinc-500">
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              wipeAndBounce(router);
            }}
            className="underline hover:text-zinc-300"
          >
            Cancel and start over
          </button>
        </p>
      </div>
    </main>
  );
}
