"use client";

import { startRegistration } from "@simplewebauthn/browser";
import type { JSX } from "react";
import { useState } from "react";

import { AuthClientError } from "../../../../lib/api/auth-client";
import {
  beginWebauthnRegister,
  finishWebauthnRegister,
} from "../../../../lib/api/twofa-client";
import { useAuth } from "../../../../lib/auth/auth-context";

interface EnrollPasskeyButtonProps {
  onEnrolled: () => void | Promise<void>;
}

/**
 * Phase 03 Plan 10 T2 — passkey enrolment via @simplewebauthn/browser@^11.
 *
 * Flow (Truth 1, 2):
 *   1. POST /2fa/webauthn/begin-register → JSON options
 *   2. startRegistration({ optionsJSON }) — browser prompts for biometric/PIN
 *   3. POST /2fa/webauthn/finish-register with the attestation + chosen name
 *   4. On success: refresh the parent list.
 *
 * Cancellation (`NotAllowedError`) is surfaced as a graceful "Cancelled"
 * note, not an error. WebAuthn ceremonies that fail for other reasons
 * (RP-ID mismatch, invalid attestation) bubble up as red text with the
 * library's message.
 */
export function EnrollPasskeyButton({
  onEnrolled,
}: EnrollPasskeyButtonProps): JSX.Element {
  const { accessToken } = useAuth();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const trimmed = name.trim();
  const canSubmit = !busy && trimmed.length >= 1 && accessToken !== null;

  return (
    <div className="flex flex-col gap-2">
      <label className="block text-sm font-medium text-zinc-200">
        Name (e.g. "iCloud Keychain", "YubiKey 5C")
        <input
          type="text"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
          }}
          maxLength={64}
          disabled={busy}
          placeholder="iCloud Keychain"
          className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 disabled:opacity-40"
        />
      </label>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!canSubmit}
          onClick={() => {
            if (!canSubmit) return;
            // canSubmit already gates on accessToken !== null; TS narrows.
            const at = accessToken;
            setBusy(true);
            setErr(null);
            setInfo(null);
            void (async () => {
              try {
                // beginWebauthnRegister returns z.unknown(); the
                // @simplewebauthn/browser library narrows + validates the
                // shape itself (throws if malformed). We pass the raw JSON
                // through.
                const optionsJSON = (await beginWebauthnRegister(
                  at,
                )) as Parameters<typeof startRegistration>[0]["optionsJSON"];
                const att = await startRegistration({ optionsJSON });
                await finishWebauthnRegister(at, {
                  response: att,
                  name: trimmed,
                });
                setName("");
                setInfo("Passkey added.");
                await onEnrolled();
              } catch (e) {
                if (e instanceof Error && e.name === "NotAllowedError") {
                  setInfo("Cancelled.");
                } else if (e instanceof AuthClientError) {
                  setErr(e.message);
                } else if (e instanceof Error) {
                  setErr(e.message);
                } else {
                  setErr("Failed to add passkey.");
                }
              } finally {
                setBusy(false);
              }
            })();
          }}
          className="rounded-md bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
        >
          {busy ? "Adding…" : "Add passkey"}
        </button>
        {info !== null && (
          <p className="text-sm text-emerald-200" role="status">
            {info}
          </p>
        )}
      </div>
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
