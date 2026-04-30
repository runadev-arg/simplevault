"use client";

import type { Dispatch, JSX, SyntheticEvent } from "react";
import { useMemo, useState } from "react";

import type { SignupAction } from "../page";

/**
 * Master password step.
 *
 * Phase 02 strength check (no zxcvbn yet — Phase 04): require ≥12 chars
 * AND at least 3 of 4 character classes (lower, upper, digit, symbol).
 *
 * Stores the password in component state only; on advance, the parent
 * keeps it in `SignupState.password` until the Submitting step builds
 * master_KEK, after which keyStore.wipe() runs.
 */

interface CharClassResult {
  ok: boolean;
  reason?: string;
}

function checkPassword(pw: string): CharClassResult {
  if (pw.length < 12) return { ok: false, reason: "Must be at least 12 characters." };
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^A-Za-z0-9]/.test(pw)) classes++;
  if (classes < 3) {
    return {
      ok: false,
      reason:
        "Use at least 3 of: lowercase, uppercase, digits, symbols.",
    };
  }
  return { ok: true };
}

export function MasterPasswordStep({
  dispatch,
}: {
  dispatch: Dispatch<SignupAction>;
}): JSX.Element {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const check = useMemo(() => checkPassword(pw), [pw]);

  function onSubmit(e: SyntheticEvent<HTMLFormElement>): void {
    e.preventDefault();
    if (!check.ok) {
      setErr(check.reason ?? "Password too weak.");
      return;
    }
    if (pw !== confirm) {
      setErr("Passwords do not match.");
      return;
    }
    setErr(null);
    dispatch({ type: "password-set", password: pw });
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4" autoComplete="off">
      <div className="space-y-2">
        <label htmlFor="pw" className="block text-sm font-medium">
          Master password
        </label>
        <input
          id="pw"
          type="password"
          autoComplete="new-password"
          autoFocus
          value={pw}
          onChange={(ev) => {
            setPw(ev.target.value);
          }}
          className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
        />
        <p className={check.ok ? "text-xs text-emerald-400" : "text-xs text-zinc-500"}>
          {check.ok ? "Looks good." : check.reason}
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor="confirm" className="block text-sm font-medium">
          Confirm master password
        </label>
        <input
          id="confirm"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(ev) => {
            setConfirm(ev.target.value);
          }}
          className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
        />
      </div>

      <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">
        SimpleVault NEVER sends this password to the server. If you forget
        it, you can recover only with both your secret key and your 24-word
        recovery phrase.
      </p>

      {err && (
        <p role="alert" className="text-sm text-red-300">
          {err}
        </p>
      )}

      <button
        type="submit"
        disabled={!check.ok || !confirm}
        className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
      >
        Continue
      </button>
    </form>
  );
}
