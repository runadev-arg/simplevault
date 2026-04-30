"use client";

import type { Dispatch, JSX, SyntheticEvent } from "react";
import { useEffect, useMemo, useState } from "react";

import type { SignupAction } from "../page";

/**
 * Secret-key reveal + transcription gate.
 *
 * On mount: lazy-import @simplevault/crypto + libsodium, generate 16 random
 * bytes via `sodium.randombytes_buf(16)`, render as Crockford-base32 with
 * 4-char hyphen groups (e.g. "K3JM-9PXQ-7T4N-22HS-VR8E-A6YF").
 *
 * Gate: user must (a) tick "I have stored this" AND (b) re-paste the
 * formatted string into a confirmation input. On match, dispatch
 * `secret-key-confirmed` with the raw 16-B Uint8Array.
 *
 * SECURITY:
 *   - Generated client-side. The server never sees this value.
 *   - Lives in component state until the Submitting step. After signup
 *     completes, keyStore.wipe() zeros the buffer.
 */

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // RFC 4648 + Crockford

export function bytesToCrockford(bytes: Uint8Array): string {
  // 16 B -> 128 bits -> ceil(128/5) = 26 chars
  // We use the standard "encode 5 bits at a time, MSB first" path.
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const ch = CROCKFORD[(value >>> bits) & 0x1f];
      out += ch ?? "";
    }
  }
  if (bits > 0) {
    const ch = CROCKFORD[(value << (5 - bits)) & 0x1f];
    out += ch ?? "";
  }
  // group in 4-char chunks
  return out.match(/.{1,4}/g)?.join("-") ?? out;
}

function normaliseInput(s: string): string {
  return s
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1")
    .replace(/[^0-9A-Z]/g, "");
}

export function SecretKeyRevealStep({
  dispatch,
}: {
  dispatch: Dispatch<SignupAction>;
}): JSX.Element {
  const [secret, setSecret] = useState<Uint8Array | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [confirmInput, setConfirmInput] = useState("");
  const [genErr, setGenErr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const sodium = (await import("libsodium-wrappers-sumo")).default;
        await sodium.ready;
        const sk = sodium.randombytes_buf(16);
        if (!flag.cancelled) setSecret(sk);
      } catch {
        if (!flag.cancelled) setGenErr("Failed to generate secret key.");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, []);

  const formatted = useMemo(() => (secret ? bytesToCrockford(secret) : ""), [secret]);

  async function copyToClipboard(): Promise<void> {
    try {
      await navigator.clipboard.writeText(formatted);
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch {
      // ignore — user can manually transcribe
    }
  }

  function onSubmit(e: SyntheticEvent<HTMLFormElement>): void {
    e.preventDefault();
    if (!secret) return;
    if (!acknowledged) {
      setErr("You must confirm you have stored the secret key.");
      return;
    }
    const normCanonical = formatted.replace(/-/g, "");
    const normInput = normaliseInput(confirmInput);
    if (normInput !== normCanonical) {
      setErr("The secret key you entered does not match. Please try again.");
      return;
    }
    setErr(null);
    dispatch({ type: "secret-key-confirmed", secretKey: secret });
  }

  if (genErr) {
    return <p className="text-red-300">{genErr}</p>;
  }
  if (!secret) {
    return <p className="text-zinc-400">Generating secret key…</p>;
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4" autoComplete="off">
      <div className="space-y-2">
        <label className="block text-sm font-medium">Your secret key</label>
        <div className="rounded-md border border-amber-500/40 bg-zinc-900 p-4 text-center font-mono text-lg tracking-widest">
          {formatted}
        </div>
        <button
          type="button"
          onClick={() => {
            void copyToClipboard();
          }}
          className="text-xs text-emerald-400 hover:underline"
        >
          {copied ? "Copied!" : "Copy to clipboard"}
        </button>
        <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">
          Shown ONCE. Store it offline (printed paper, password manager). Without
          this AND your master password, your vault cannot be unlocked. The
          server never sees this value.
        </p>
      </div>

      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(ev) => {
            setAcknowledged(ev.target.checked);
          }}
          className="mt-1"
        />
        <span>I have securely stored my secret key.</span>
      </label>

      <div className="space-y-2">
        <label htmlFor="confirm-sk" className="block text-sm font-medium">
          Re-enter your secret key (paste or type)
        </label>
        <input
          id="confirm-sk"
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={confirmInput}
          onChange={(ev) => {
            setConfirmInput(ev.target.value);
          }}
          className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono"
        />
      </div>

      {err && (
        <p role="alert" className="text-sm text-red-300">
          {err}
        </p>
      )}

      <button
        type="submit"
        disabled={!acknowledged || !confirmInput}
        className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
      >
        Continue
      </button>
    </form>
  );
}
