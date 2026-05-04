"use client";

import {
  ready,
  buildOtpauthUrl,
  verifyTotpCandidate,
  totpReady,
  type Argon2Params,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";
import QRCode from "qrcode";
import type { JSX } from "react";
import { useEffect, useState } from "react";

import { AuthClientError, me as apiMe } from "../../../../lib/api/auth-client";
import {
  beginTotpRegister,
  finishTotpRegister,
} from "../../../../lib/api/twofa-client";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";
import { wrapTotpSecret } from "../../../../lib/crypto/totp-wrap";

interface EnrollTotpFlowProps {
  onEnrolled: () => void | Promise<void>;
}

type Phase =
  | "init" // pre-flight: button to start
  | "show-qr" // QR + provisioning URL displayed; user scans
  | "verify" // user enters the 6-digit code
  | "submitting" // wrapping + posting finish-register
  | "done"; // success message

/**
 * Phase 03 Plan 10 T3 — TOTP enrolment flow (Truths 5, 6, 16).
 *
 *   1. POST /2fa/totp/begin-register → issuanceNonce (TTL 120s server-side)
 *   2. Client generates 20 random bytes via libsodium → otpauth URL → QR
 *   3. User scans into authenticator + enters 6-digit code
 *   4. Client runs `verifyTotpCandidate(secret, code, currentStep, drift=1)`
 *      locally — RFC 6238 SHA-1 / 30s. Server NEVER sees the secret OR
 *      the code (Plan 03 Key Link 3).
 *   5. On match: wrap secret under master_DEK + AAD `sv:user-totp:v1|`
 *      and POST /2fa/totp/finish-register.
 *   6. Always best-effort zero the in-memory secret on transition.
 *
 * The user must already be logged in (master_DEK is in the keyStore from
 * the 1FA login flow). If keyStore.master_dek is missing (e.g. hard
 * refresh post-login), surface a "please re-login to add TOTP" hint.
 */
export function EnrollTotpFlow({ onEnrolled }: EnrollTotpFlowProps): JSX.Element {
  const { accessToken } = useAuth();
  const [phase, setPhase] = useState<Phase>("init");
  const [secret, setSecret] = useState<Uint8Array | null>(null);
  const [issuanceNonce, setIssuanceNonce] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string>("");
  const [otpauthUrl, setOtpauthUrl] = useState<string>("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("Authenticator");
  const [email, setEmail] = useState<string | null>(null);
  const [argon2Params, setArgon2Params] = useState<Argon2Params | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Pre-fetch the user's email + argon2Params (needed to build the AAD).
  // The /me response already exposes both — re-use the existing endpoint
  // rather than duplicating profile state in another lib module.
  useEffect(() => {
    if (accessToken === null || email !== null) return;
    void (async () => {
      try {
        const r = await apiMe(accessToken);
        setEmail(r.email);
        setArgon2Params(r.argon2Params);
      } catch {
        // non-fatal — we surface a clear error when the user clicks "start"
      }
    })();
  }, [accessToken, email]);

  function wipeLocal(): void {
    if (secret) secret.fill(0);
    setSecret(null);
    setIssuanceNonce(null);
    setQrDataUrl("");
    setOtpauthUrl("");
    setCode("");
  }

  async function start(): Promise<void> {
    if (accessToken === null) return;
    setErr(null);
    if (email === null || argon2Params === null) {
      setErr("Couldn't load your profile. Please try again in a moment.");
      return;
    }
    try {
      // Server reserves the issuance nonce + binds it to user_id (TTL 120s).
      // If the user takes longer than 120s to enrol the secret, finish-register
      // returns 400 and we restart from this step.
      const { issuanceNonce: nonce } = await beginTotpRegister(accessToken);
      // libsodium wasm + crypto/totp wasm are both lazy-loaded.
      await ready();
      await totpReady();
      const sec = sodium.randombytes_buf(20);
      const url = buildOtpauthUrl({
        issuer: "SimpleVault",
        account: email,
        secret: sec,
      });
      const qr = await QRCode.toDataURL(url, { errorCorrectionLevel: "M" });
      setSecret(sec);
      setIssuanceNonce(nonce);
      setOtpauthUrl(url);
      setQrDataUrl(qr);
      setPhase("show-qr");
    } catch (e) {
      if (e instanceof AuthClientError) setErr(e.message);
      else if (e instanceof Error) setErr(e.message);
      else setErr("Failed to start TOTP setup.");
    }
  }

  async function verifyAndSubmit(): Promise<void> {
    if (accessToken === null || secret === null || issuanceNonce === null) return;
    if (email === null || argon2Params === null) {
      setErr("Profile information is missing. Please try again.");
      return;
    }
    setErr(null);
    const trimmedCode = code.trim();
    if (!/^\d{6}$/.test(trimmedCode)) {
      setErr("Enter the 6-digit code from your authenticator app.");
      return;
    }
    const masterDek = keyStore.getBytes("master_dek");
    if (!masterDek) {
      setErr(
        "Missing decryption key (please log out and back in, then retry).",
      );
      return;
    }

    setPhase("submitting");
    try {
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      // RFC 6238 ±1 step drift (90 seconds either side of the wall clock).
      const v = verifyTotpCandidate(secret, trimmedCode, currentStep, 1);
      if (!v.ok) {
        setErr("That code didn't match. Try again with the most recent one.");
        setPhase("verify");
        return;
      }
      const { wrappedSecret, encryptedSecretAad } = await wrapTotpSecret(
        secret,
        masterDek,
        email,
        argon2Params,
      );
      await finishTotpRegister(accessToken, {
        issuanceNonce,
        wrappedSecret,
        encryptedSecretAad,
        name: name.trim() || "Authenticator",
        candidateStep: v.step ?? currentStep,
      });
      wipeLocal();
      setPhase("done");
      await onEnrolled();
    } catch (e) {
      if (e instanceof AuthClientError) setErr(e.message);
      else if (e instanceof Error) setErr(e.message);
      else setErr("Failed to add authenticator app.");
      setPhase("verify");
    }
  }

  function cancel(): void {
    wipeLocal();
    setPhase("init");
    setErr(null);
  }

  if (phase === "init") {
    return (
      <div className="flex flex-col gap-2">
        <button
          type="button"
          disabled={accessToken === null}
          onClick={() => {
            void start();
          }}
          className="self-start rounded-md bg-zinc-700 px-3 py-2 text-sm hover:bg-zinc-600 disabled:opacity-40"
        >
          Set up authenticator app
        </button>
        {err !== null && (
          <p
            role="alert"
            className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200"
          >
            {err}
          </p>
        )}
      </div>
    );
  }

  if (phase === "done") {
    return (
      <p className="text-sm text-emerald-200" role="status">
        Authenticator app added.
      </p>
    );
  }

  // show-qr / verify / submitting share the QR + form layout.
  return (
    <div className="flex flex-col gap-4">
      <ol className="list-decimal space-y-2 pl-5 text-sm text-zinc-300">
        <li>
          Open your authenticator app (Google Authenticator, 1Password, Authy,
          …) and scan the QR code below.
        </li>
        <li>
          Enter the 6-digit code your app shows. You have ~120 seconds before
          the setup expires.
        </li>
      </ol>

      {qrDataUrl !== "" && (
        <img
          src={qrDataUrl}
          alt="TOTP setup QR code"
          className="h-48 w-48 rounded bg-white p-2"
        />
      )}

      {otpauthUrl !== "" && (
        <details className="text-xs text-zinc-400">
          <summary className="cursor-pointer">
            Can't scan? Show provisioning URL
          </summary>
          <code className="mt-2 block break-all rounded bg-zinc-900 p-2 font-mono">
            {otpauthUrl}
          </code>
        </details>
      )}

      <div className="flex flex-col gap-2">
        <label className="block text-sm font-medium text-zinc-200">
          Name
          <input
            type="text"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
            }}
            maxLength={64}
            disabled={phase === "submitting"}
            className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100"
          />
        </label>
        <label className="block text-sm font-medium text-zinc-200">
          6-digit code
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
            }}
            maxLength={6}
            disabled={phase === "submitting"}
            placeholder="123456"
            className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-mono tracking-widest text-zinc-100"
          />
        </label>
      </div>

      {err !== null && (
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200"
        >
          {err}
        </p>
      )}

      <div className="flex gap-2">
        <button
          type="button"
          disabled={phase === "submitting"}
          onClick={() => {
            void verifyAndSubmit();
          }}
          className="rounded-md bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
        >
          {phase === "submitting" ? "Adding…" : "Verify and add"}
        </button>
        <button
          type="button"
          disabled={phase === "submitting"}
          onClick={cancel}
          className="rounded-md bg-zinc-800 px-3 py-2 text-sm hover:bg-zinc-700 disabled:opacity-40"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
