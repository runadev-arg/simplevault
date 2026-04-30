"use client";

import type { Dispatch, JSX, SyntheticEvent } from "react";
import { useState } from "react";

import type { SignupAction } from "../page";

/**
 * Recovery-phrase confirm step.
 *
 * Renders 4 inputs labelled with the challenge positions (passed in from
 * the parent's state, picked at the previous step's advance). User must
 * type the correct word at each. Validation is in-memory (compare to the
 * still-in-state mnemonic split by " ").
 *
 * On all 4 correct -> dispatch `recovery-confirmed` -> advance to submit.
 * On any wrong -> re-roll challenge indices AND go back to the reveal
 * step (so the user has to re-display the phrase + pick a new challenge —
 * no infinite retries against a fixed challenge).
 */

export function RecoveryPhraseConfirmStep({
  dispatch,
  mnemonic,
  indices,
}: {
  dispatch: Dispatch<SignupAction>;
  mnemonic: string;
  indices: readonly number[];
}): JSX.Element {
  const words = mnemonic.split(" ");
  const [answers, setAnswers] = useState<Record<number, string>>({});

  async function reroll(): Promise<number[]> {
    const sodium = (await import("libsodium-wrappers-sumo")).default;
    await sodium.ready;
    const set = new Set<number>();
    while (set.size < 4) {
      set.add(sodium.randombytes_uniform(24));
    }
    return Array.from(set).sort((a, b) => a - b);
  }

  async function handleSubmit(e: SyntheticEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    let allCorrect = true;
    for (const i of indices) {
      const expected = words[i];
      const got = (answers[i] ?? "").trim().toLowerCase();
      if (expected === undefined || got !== expected) {
        allCorrect = false;
        break;
      }
    }
    if (!allCorrect) {
      const newIdx = await reroll();
      dispatch({ type: "back-to-recovery-reveal", challengeIndices: newIdx });
      return;
    }
    dispatch({ type: "recovery-confirmed" });
  }

  return (
    <form
      onSubmit={(e) => {
        void handleSubmit(e);
      }}
      className="space-y-4"
      autoComplete="off"
    >
      <p className="text-sm text-zinc-400">
        Type the words at the following positions to confirm you transcribed
        the phrase correctly.
      </p>

      <div className="grid grid-cols-2 gap-3">
        {indices.map((i) => (
          <div key={i} className="space-y-1">
            <label htmlFor={`w${String(i)}`} className="block text-xs font-medium text-zinc-400">
              Word #{i + 1}
            </label>
            <input
              id={`w${String(i)}`}
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={answers[i] ?? ""}
              onChange={(ev) => {
                const v = ev.target.value;
                setAnswers((s) => ({ ...s, [i]: v }));
              }}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono"
            />
          </div>
        ))}
      </div>

      <button
        type="submit"
        disabled={indices.some((i) => !(answers[i] ?? "").trim())}
        className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
      >
        Verify and continue
      </button>
    </form>
  );
}
