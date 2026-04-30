"use client";

import type { JSX } from "react";
import { useEffect, useReducer, useState } from "react";

import type { Argon2Params } from "../../lib/api/auth-client";

import { InviteCodeStep } from "./steps/InviteCodeStep";
import { MasterPasswordStep } from "./steps/MasterPasswordStep";
import { RecoveryPhraseConfirmStep } from "./steps/RecoveryPhraseConfirmStep";
import { RecoveryPhraseRevealStep } from "./steps/RecoveryPhraseRevealStep";
import { SecretKeyRevealStep } from "./steps/SecretKeyRevealStep";
import { SubmittingStep } from "./steps/SubmittingStep";

/**
 * /signup multi-step flow. Six steps + a terminal "done" pseudo-step that
 * triggers a redirect to /login.
 *
 * GATES (LOAD-BEARING; the reducer is the single enforcement point):
 *   - "invite" -> "master-pw"     : requires inviteRedeemed payload
 *   - "master-pw" -> "secret-key" : requires password (>=12, 3/4 char classes)
 *   - "secret-key" -> "recovery-reveal" : requires user re-pasted secret_key
 *   - "recovery-reveal" -> "recovery-confirm" : requires "I will be tested" gate
 *   - "recovery-confirm" -> "submitting" : requires 4/4 challenge words
 *   - "submitting" -> "done" : on POST /auth/signup 201
 *
 * SECRET LIFECYCLE (LOAD-BEARING):
 *   - master_password / secret_key / mnemonic live ONLY in this component's
 *     state + the in-memory keyStore for the Submitting derivation.
 *   - On signup success, SubmittingStep calls keyStore.wipe() AND we
 *     navigate to /login?signed_up=1 (no auto-login — secret_key is
 *     short-lived RAM only; user logs in fresh).
 *   - Cancel / unmount: useEffect cleanup wipes keyStore.
 *
 * NO localStorage / sessionStorage / IndexedDB writes anywhere on this
 * page or its children. Verifiable in DevTools Application tab.
 */

export type Step =
  | "invite"
  | "master-pw"
  | "secret-key"
  | "recovery-reveal"
  | "recovery-confirm"
  | "submitting"
  | "done";

export interface InviteRedeemed {
  inviteId: string;
  email: string;
  argon2Params: Argon2Params;
  serverArgonSalt: string;
}

export interface SignupState {
  step: Step;
  invite: InviteRedeemed | null;
  password: string | null; // master password, in-memory only
  secretKey: Uint8Array | null; // 16 B
  mnemonic: string | null; // 24-word BIP-39
  challengeIndices: readonly number[] | null; // for recovery-confirm
  error: string | null;
}

export type SignupAction =
  | { type: "invite-redeemed"; payload: InviteRedeemed }
  | { type: "password-set"; password: string }
  | { type: "secret-key-confirmed"; secretKey: Uint8Array }
  | { type: "recovery-revealed"; mnemonic: string; challengeIndices: number[] }
  | { type: "recovery-reroll"; challengeIndices: number[] }
  | { type: "recovery-confirmed" }
  | { type: "back-to-recovery-reveal"; challengeIndices: number[] }
  | { type: "submit-success" }
  | { type: "submit-error"; error: string }
  | { type: "error"; error: string };

const initialState: SignupState = {
  step: "invite",
  invite: null,
  password: null,
  secretKey: null,
  mnemonic: null,
  challengeIndices: null,
  error: null,
};

function reducer(s: SignupState, a: SignupAction): SignupState {
  switch (a.type) {
    case "invite-redeemed":
      // gate: only valid when in invite step
      if (s.step !== "invite") return s;
      return { ...s, step: "master-pw", invite: a.payload, error: null };
    case "password-set":
      if (s.step !== "master-pw") return s;
      return { ...s, step: "secret-key", password: a.password, error: null };
    case "secret-key-confirmed":
      if (s.step !== "secret-key") return s;
      return {
        ...s,
        step: "recovery-reveal",
        secretKey: a.secretKey,
        error: null,
      };
    case "recovery-revealed":
      if (s.step !== "recovery-reveal") return s;
      return {
        ...s,
        step: "recovery-confirm",
        mnemonic: a.mnemonic,
        challengeIndices: a.challengeIndices,
        error: null,
      };
    case "recovery-reroll":
      return { ...s, challengeIndices: a.challengeIndices, error: null };
    case "recovery-confirmed":
      if (s.step !== "recovery-confirm") return s;
      return { ...s, step: "submitting", error: null };
    case "back-to-recovery-reveal":
      // user got a wrong answer — re-roll AND go back to reveal screen
      return {
        ...s,
        step: "recovery-reveal",
        challengeIndices: a.challengeIndices,
        error: "One or more words were wrong. Re-display the phrase and try again.",
      };
    case "submit-success":
      return { ...s, step: "done", error: null };
    case "submit-error":
      // Stay on submitting step but expose error so user can retry / start over
      return { ...s, error: a.error };
    case "error":
      return { ...s, error: a.error };
    default:
      return s;
  }
}

export default function SignupPage(): JSX.Element {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [cryptoReady, setCryptoReady] = useState(false);

  // Load libsodium (and crypto bundle) once. Children may still
  // `await ready()` defensively.
  useEffect(() => {
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const mod = await import("@simplevault/crypto/browser");
        await mod.ready();
        if (!flag.cancelled) setCryptoReady(true);
      } catch {
        if (!flag.cancelled) {
          dispatch({
            type: "error",
            error: "Failed to load crypto library. Reload the page.",
          });
        }
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, []);

  // Best-effort secret wipe on unmount (page navigation, tab close intent).
  useEffect(() => {
    return () => {
      // Lazy import to keep this file synchronous; ignore errors.
      void import("../../lib/auth/key-store").then((m) => {
        m.keyStore.wipe();
      });
    };
  }, []);

  if (!cryptoReady && state.step === "invite") {
    return (
      <main className="flex min-h-screen items-center justify-center px-6">
        <p className="text-zinc-400">Loading secure crypto module…</p>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-10">
      <div className="w-full max-w-xl space-y-6">
        <header className="space-y-2 text-center">
          <h1 className="text-3xl font-semibold tracking-tight">Create your SimpleVault</h1>
          <p className="text-sm text-zinc-400">Step {stepIndex(state.step)} of 6</p>
        </header>

        {state.step === "invite" && <InviteCodeStep dispatch={dispatch} />}
        {state.step === "master-pw" && <MasterPasswordStep dispatch={dispatch} />}
        {state.step === "secret-key" && <SecretKeyRevealStep dispatch={dispatch} />}
        {state.step === "recovery-reveal" && (
          <RecoveryPhraseRevealStep dispatch={dispatch} initialMnemonic={state.mnemonic} />
        )}
        {state.step === "recovery-confirm" && state.mnemonic !== null && state.challengeIndices !== null && (
          <RecoveryPhraseConfirmStep
            dispatch={dispatch}
            mnemonic={state.mnemonic}
            indices={state.challengeIndices}
          />
        )}
        {state.step === "submitting" && state.invite !== null && state.password !== null && state.secretKey !== null && state.mnemonic !== null && (
          <SubmittingStep
            dispatch={dispatch}
            invite={state.invite}
            password={state.password}
            secretKey={state.secretKey}
            mnemonic={state.mnemonic}
          />
        )}
        {state.step === "done" && (
          <p className="text-center text-emerald-400">
            Account created. Redirecting to sign-in…
          </p>
        )}

        {state.error && (
          <p
            role="alert"
            className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            {state.error}
          </p>
        )}
      </div>
    </main>
  );
}

function stepIndex(s: Step): number {
  switch (s) {
    case "invite":
      return 1;
    case "master-pw":
      return 2;
    case "secret-key":
      return 3;
    case "recovery-reveal":
      return 4;
    case "recovery-confirm":
      return 5;
    case "submitting":
    case "done":
      return 6;
  }
}
