"use client";

import { useEffect, useState, type Dispatch, type JSX } from "react";

import type { SignupAction } from "../page";

/**
 * Recovery-phrase reveal step.
 *
 * Generates a 24-word BIP-39 mnemonic (NFKD-normalised by the bip39
 * library). Displays as a 6×4 numbered grid.
 *
 * Gate: user MUST tick "I will be tested on it next" before advance.
 * Advancing also rolls 4 challenge indices via libsodium randombytes_uniform
 * (without replacement) so the next step's challenge is unbiased.
 */

function pickIndices(count: number, max: number, randUniform: (u: number) => number): number[] {
  const set = new Set<number>();
  while (set.size < count) {
    set.add(randUniform(max));
  }
  return Array.from(set).sort((a, b) => a - b);
}

export function RecoveryPhraseRevealStep({
  dispatch,
  initialMnemonic,
}: {
  dispatch: Dispatch<SignupAction>;
  initialMnemonic: string | null;
}): JSX.Element {
  const [mnemonic, setMnemonic] = useState<string | null>(initialMnemonic);
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (mnemonic !== null) return;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const mod = await import("@simplevault/crypto/browser");
        await mod.ready();
        const m = mod.generateMnemonic();
        if (!flag.cancelled) setMnemonic(m);
      } catch {
        if (!flag.cancelled) setErr("Failed to generate recovery phrase.");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [mnemonic]);

  async function copy(): Promise<void> {
    if (mnemonic === null) return;
    try {
      await navigator.clipboard.writeText(mnemonic);
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch {
      // ignore
    }
  }

  async function onContinue(): Promise<void> {
    if (mnemonic === null) return;
    if (!acknowledged) {
      setErr("You must confirm you have transcribed the phrase.");
      return;
    }
    try {
      const sodium = (await import("libsodium-wrappers-sumo")).default;
      await sodium.ready;
      const idx = pickIndices(4, 24, (u) => sodium.randombytes_uniform(u));
      dispatch({ type: "recovery-revealed", mnemonic, challengeIndices: idx });
    } catch {
      setErr("Failed to prepare confirmation challenge.");
    }
  }

  if (err !== null && mnemonic === null) {
    return <p className="text-red-300">{err}</p>;
  }
  if (mnemonic === null) {
    return <p className="text-zinc-400">Generating recovery phrase…</p>;
  }

  const words = mnemonic.split(" ");

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <label className="block text-sm font-medium">Your 24-word recovery phrase</label>
        <ol className="grid grid-cols-2 gap-2 rounded-md border border-amber-500/40 bg-zinc-900 p-4 sm:grid-cols-4">
          {words.map((w, i) => (
            <li key={i} className="font-mono text-sm">
              <span className="mr-2 inline-block w-6 text-right text-zinc-500">{i + 1}.</span>
              {w}
            </li>
          ))}
        </ol>
        <button
          type="button"
          onClick={() => {
            void copy();
          }}
          className="text-xs text-emerald-400 hover:underline"
        >
          {copied ? "Copied!" : "Copy to clipboard"}
        </button>
        <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">
          Shown ONCE. Reveal only on a private screen. With this phrase, anyone
          who also knows your secret key + email can recover your vault. Store
          it offline (paper, metal backup). The server never sees this phrase.
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
        <span>I have transcribed this phrase. I understand I will be tested on it next.</span>
      </label>

      {err && (
        <p role="alert" className="text-sm text-red-300">
          {err}
        </p>
      )}

      <button
        type="button"
        onClick={() => {
          void onContinue();
        }}
        disabled={!acknowledged}
        className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
      >
        Continue
      </button>
    </div>
  );
}

export const __test = { pickIndices };
