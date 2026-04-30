"use client";

import type { Dispatch, JSX, SyntheticEvent } from "react";
import { useState } from "react";

import { AuthClientError, redeemInvite } from "../../../lib/api/auth-client";
import type { SignupAction } from "../page";

const INVITE_RE = /^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z-]{8,64}$/;

export function InviteCodeStep({
  dispatch,
}: {
  dispatch: Dispatch<SignupAction>;
}): JSX.Element {
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handleSubmit(e: SyntheticEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    if (!INVITE_RE.test(code)) {
      setErr("Invite code must be 8–64 chars (letters, digits, hyphens).");
      return;
    }
    setPending(true);
    setErr(null);
    try {
      const res = await redeemInvite(code);
      dispatch({ type: "invite-redeemed", payload: res });
    } catch (err2) {
      if (err2 instanceof AuthClientError) {
        setErr(err2.code === "E1006" ? "Invalid or expired invite." : err2.message);
      } else {
        setErr("Network error. Please try again.");
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <form
      onSubmit={(e) => {
        void handleSubmit(e);
      }}
      className="space-y-4"
    >
      <div className="space-y-2">
        <label htmlFor="invite" className="block text-sm font-medium">
          Invite code
        </label>
        <input
          id="invite"
          type="text"
          autoFocus
          autoComplete="off"
          spellCheck={false}
          value={code}
          onChange={(ev) => {
            setCode(ev.target.value.trim());
          }}
          className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm tracking-wider"
          placeholder="K3JM-9PXQ-7T4N-22HS-VR8E-A6YF"
        />
        <p className="text-xs text-zinc-500">
          Paste the invite code from your operator. Codes are single-use.
        </p>
      </div>

      {err && (
        <p role="alert" className="text-sm text-red-300">
          {err}
        </p>
      )}

      <button
        type="submit"
        disabled={pending || !code}
        className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
      >
        {pending ? "Verifying…" : "Continue"}
      </button>
    </form>
  );
}
