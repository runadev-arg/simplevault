"use client";

import { useEffect, useRef, useState, type Dispatch, type JSX } from "react";

import { AuthClientError, signup } from "../../../lib/api/auth-client";
import { keyStore } from "../../../lib/auth/key-store";
import { buildSignupEnvelope } from "../../../lib/crypto/signup-derivations";
import type { InviteRedeemed, SignupAction } from "../page";

/**
 * Submitting step.
 *
 * 1. Show "Deriving keys… please wait" — Argon2id blocks the main thread
 *    for ~750ms (params are operator-tuned via /invite/redeem). For v1
 *    we accept the main-thread block; a Web Worker rewrite is a Phase 04
 *    optimisation. UI stays responsive otherwise (just no spinner anim
 *    during the blocking call).
 *
 * 2. Build the signup envelope (10 fields, frozen by 02-07 SUMMARY).
 *
 * 3. POST /auth/signup. On 201 -> `keyStore.wipe()` + redirect to
 *    /login?signed_up=1. NO auto-login (per 02-07 §auto-login decision).
 *
 * 4. On 4xx -> render error + offer "Start over" (returns to /signup root,
 *    discarding state and wiping keyStore).
 */

export function SubmittingStep({
  dispatch,
  invite,
  password,
  secretKey,
  mnemonic,
}: {
  dispatch: Dispatch<SignupAction>;
  invite: InviteRedeemed;
  password: string;
  secretKey: Uint8Array;
  mnemonic: string;
}): JSX.Element {
  const [phase, setPhase] = useState<"deriving" | "submitting" | "ok" | "err">(
    "deriving",
  );
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;

    void (async (): Promise<void> => {
      let derived: Awaited<ReturnType<typeof buildSignupEnvelope>>["derived"] | null =
        null;
      try {
        // Stash secrets in the key-store so the unmount cleanup can wipe
        // them even if this effect throws mid-flight.
        keyStore.set("secret_key", secretKey);
        keyStore.set("master_password", password);
        keyStore.set("mnemonic", mnemonic);

        const built = await buildSignupEnvelope({
          inviteId: invite.inviteId,
          email: invite.email,
          password,
          secretKey,
          mnemonic,
          argon2Params: invite.argon2Params,
          serverArgonSaltB64: invite.serverArgonSalt,
        });
        derived = built.derived;
        keyStore.set("master_kek", derived.masterKek);
        keyStore.set("master_dek", derived.masterDek);
        keyStore.set("recovery_kek", derived.recoveryKek);
        keyStore.set("sign_sk", derived.signSk);
        keyStore.set("kx_sk", derived.kxSk);

        setPhase("submitting");

        await signup(built.envelope);

        // Success: wipe everything and redirect.
        keyStore.wipe();
        // Best-effort fill on locals (the keyStore .wipe() already zero'd
        // these buffers, but being explicit is cheap).
        secretKey.fill(0);
        derived.masterKek.fill(0);
        derived.masterDek.fill(0);
        derived.recoveryKek.fill(0);
        derived.signSk.fill(0);
        derived.kxSk.fill(0);

        dispatch({ type: "submit-success" });
        setPhase("ok");
        // Hard redirect — full page reload so no signup state lingers.
        window.location.assign("/login?signed_up=1");
      } catch (e) {
        // Wipe in-memory secrets on error too — no point in keeping them
        // around if signup failed.
        try {
          keyStore.wipe();
        } catch {
          // ignore
        }
        if (e instanceof AuthClientError) {
          if (e.code === "E1006") {
            setErrMsg(
              "Invalid invite. The code may have expired or been used. Please request a new invite.",
            );
          } else if (e.code === "E1007") {
            setErrMsg("Too many signup attempts. Please try again later.");
          } else if (e.code === "E4001") {
            setErrMsg("The signup payload was rejected. Please try again.");
          } else {
            setErrMsg(e.message);
          }
        } else {
          setErrMsg("Network or unexpected error. Please try again.");
        }
        setPhase("err");
        dispatch({ type: "submit-error", error: "Signup failed." });
      }
    })();
  }, [dispatch, invite, mnemonic, password, secretKey]);

  if (phase === "deriving") {
    return (
      <div className="space-y-3 text-center">
        <p className="text-zinc-200">Encrypting your vault…</p>
        <p className="text-xs text-zinc-500">
          Running Argon2id key derivation (this can take a moment).
        </p>
      </div>
    );
  }
  if (phase === "submitting") {
    return (
      <div className="space-y-3 text-center">
        <p className="text-zinc-200">Sending encrypted artifacts…</p>
      </div>
    );
  }
  if (phase === "ok") {
    return <p className="text-emerald-400">Account created. Redirecting…</p>;
  }
  // err
  return (
    <div className="space-y-3">
      <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
        {errMsg ?? "Signup failed."}
      </p>
      <button
        type="button"
        onClick={() => {
          window.location.assign("/signup");
        }}
        className="w-full rounded-md bg-zinc-700 px-4 py-2 font-medium hover:bg-zinc-600"
      >
        Start over
      </button>
    </div>
  );
}
