"use client";

/**
 * Phase 04 / Plan 04-10 (T1) — Password + passphrase generator dialog.
 *
 * This component is intentionally heavy: it transitively imports
 * `@/lib/passwords/generator` which pulls in the EFF-large wordlist
 * (7776 entries, ~60 KiB minified). Pages that mount the editor
 * dynamic-import THIS module via `next/dynamic` with `ssr: false` so
 * the wordlist chunk is split out of the editor's First Load JS.
 *
 * Two tabs:
 *   - password — length slider 8..128, four class checkboxes
 *     (defaults: length=20, all on)
 *   - passphrase — wordCount slider 3..10, separator input
 *     (defaults: 5, "-")
 *
 * Live preview. "Use this" → onAccept(output) + close.
 *
 * No shadcn / Radix — the project does not depend on them. Native
 * <dialog> + role-driven Tailwind styling, with a focus trap fallback
 * via `autoFocus` on the primary action and ESC-to-close handled by
 * the user agent's <dialog> contract.
 */

import type { JSX } from "react";
import { useEffect, useRef, useState } from "react";

import {
  generatePassphrase,
  generatePassword,
} from "../lib/passwords/generator";

type Tab = "password" | "passphrase";

interface Classes {
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface GeneratorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAccept: (value: string) => void;
}

export function GeneratorDialog({
  open,
  onOpenChange,
  onAccept,
}: GeneratorDialogProps): JSX.Element | null {
  const [tab, setTab] = useState<Tab>("password");
  const [length, setLength] = useState(20);
  const [classes, setClasses] = useState<Classes>({
    lower: true,
    upper: true,
    digits: true,
    symbols: true,
  });
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState("-");
  const [output, setOutput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);

  const regen = (): void => {
    setError(null);
    try {
      const v =
        tab === "password"
          ? generatePassword({ length, ...classes })
          : generatePassphrase({ wordCount, separator });
      setOutput(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Generation failed");
      setOutput("");
    }
  };

  // Auto-(re)generate on every relevant input change while open.
  useEffect(() => {
    if (!open) return;
    setError(null);
    try {
      const v =
        tab === "password"
          ? generatePassword({ length, ...classes })
          : generatePassphrase({ wordCount, separator });
      setOutput(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Generation failed");
      setOutput("");
    }
  }, [open, tab, length, classes, wordCount, separator]);

  // ESC closes.
  useEffect(() => {
    if (!open) return;
    const onKey = (ev: KeyboardEvent): void => {
      if (ev.key === "Escape") onOpenChange(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onOpenChange]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Password generator"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onOpenChange(false);
      }}
      ref={dialogRef}
    >
      <div className="w-full max-w-lg rounded-md border border-zinc-800 bg-zinc-900 p-5 text-zinc-100 shadow-xl">
        <header className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Generate</h2>
          <button
            type="button"
            onClick={() => {
              onOpenChange(false);
            }}
            className="text-zinc-400 hover:text-zinc-100"
            aria-label="Close generator"
          >
            ×
          </button>
        </header>

        <div role="tablist" className="mb-4 flex gap-2 border-b border-zinc-800">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "password"}
            onClick={() => {
              setTab("password");
            }}
            className={`px-3 py-2 text-sm ${
              tab === "password"
                ? "border-b-2 border-zinc-100 text-zinc-100"
                : "text-zinc-400"
            }`}
          >
            Password
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "passphrase"}
            onClick={() => {
              setTab("passphrase");
            }}
            className={`px-3 py-2 text-sm ${
              tab === "passphrase"
                ? "border-b-2 border-zinc-100 text-zinc-100"
                : "text-zinc-400"
            }`}
          >
            Passphrase
          </button>
        </div>

        {tab === "password" && (
          <div role="tabpanel" className="space-y-3">
            <label className="block text-sm">
              Length: <span className="font-mono">{length}</span>
              <input
                type="range"
                min={8}
                max={128}
                value={length}
                onChange={(e) => {
                  setLength(Number(e.target.value));
                }}
                className="mt-1 w-full"
                aria-label="Password length"
              />
            </label>
            <fieldset className="grid grid-cols-2 gap-2 text-sm">
              <legend className="sr-only">Character classes</legend>
              {(["lower", "upper", "digits", "symbols"] as const).map((k) => (
                <label key={k} className="inline-flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={classes[k]}
                    onChange={(e) => {
                      setClasses({ ...classes, [k]: e.target.checked });
                    }}
                  />
                  <span className="capitalize">{k}</span>
                </label>
              ))}
            </fieldset>
          </div>
        )}

        {tab === "passphrase" && (
          <div role="tabpanel" className="space-y-3">
            <label className="block text-sm">
              Words: <span className="font-mono">{wordCount}</span>
              <input
                type="range"
                min={3}
                max={10}
                value={wordCount}
                onChange={(e) => {
                  setWordCount(Number(e.target.value));
                }}
                className="mt-1 w-full"
                aria-label="Word count"
              />
            </label>
            <label className="block text-sm">
              Separator
              <input
                type="text"
                value={separator}
                onChange={(e) => {
                  setSeparator(e.target.value);
                }}
                maxLength={4}
                className="mt-1 w-full rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 font-mono"
              />
            </label>
          </div>
        )}

        <div className="mt-4 rounded-md border border-zinc-700 bg-zinc-950 p-3 font-mono text-sm break-all">
          {output || (error ?? "")}
        </div>
        {error && (
          <p role="alert" className="mt-2 text-xs text-red-400">
            {error}
          </p>
        )}

        <footer className="mt-4 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={regen}
            className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800"
          >
            Regenerate
          </button>
          <button
            type="button"
            onClick={() => {
              if (output) {
                onAccept(output);
                onOpenChange(false);
              }
            }}
            disabled={!output}
            className="rounded-md bg-emerald-600 px-3 py-2 text-sm text-white hover:bg-emerald-500 disabled:opacity-40"
            autoFocus
          >
            Use this
          </button>
        </footer>
      </div>
    </div>
  );
}
