"use client";

/**
 * Phase 04 / Plan 04-10 — Shared credential editor (used by both
 * /credential/new and /credential/[id]).
 *
 * Renders REQ-VAULT-002 fields:
 *   - name (required)
 *   - urls[] (multi-add chips)
 *   - username
 *   - password (input + reveal + StrengthMeter + Generate + Copy)
 *   - notes (textarea)
 *   - custom_fields[{name,value,hidden}] (repeatable)
 *   - is_favorite (checkbox)
 *
 * The editor delegates encrypt + POST/PATCH to the page via `onSave`.
 * The reuse-count is supplied by the parent (it owns the vault-wide
 * reuse map; the editor is dumb).
 *
 * GeneratorDialog is dynamic-imported with ssr:false so the EFF wordlist
 * stays out of this route's First Load JS until the dialog opens.
 */

import dynamic from "next/dynamic";
import type { JSX } from "react";
import { useState } from "react";

import {
  copyPasswordWithClear,
  CLIPBOARD_CLEAR_MS,
} from "../lib/vault/clipboard-stub";
import {
  emptyCredential,
  type CustomField,
  type DecryptedCredential,
} from "../lib/vault/credential-shape";

import { ReuseBadge } from "./credentials/reuse-badge";
import { StrengthMeter } from "./strength-meter";

const GeneratorDialog = dynamic(
  () => import("./generator-dialog").then((m) => m.GeneratorDialog),
  { ssr: false },
);

export type EditorMode = "new" | "edit";

export interface CredentialEditorProps {
  mode: EditorMode;
  initial?: DecryptedCredential;
  /** Reuse count EXCLUDING self (0 = unique). Parent computes via reuse-set. */
  reuseCount?: number;
  onSave: (next: DecryptedCredential) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel?: () => void;
  /** Surface from parent: 409 conflict/save errors. */
  error?: string | null;
  busy?: boolean;
}

export function CredentialEditor({
  mode,
  initial,
  reuseCount = 0,
  onSave,
  onDelete,
  onCancel,
  error,
  busy = false,
}: CredentialEditorProps): JSX.Element {
  const [draft, setDraft] = useState<DecryptedCredential>(
    () => initial ?? emptyCredential(),
  );
  const [showPassword, setShowPassword] = useState(false);
  const [genOpen, setGenOpen] = useState(false);
  const [urlInput, setUrlInput] = useState("");
  const [urlError, setUrlError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const updateField = <K extends keyof DecryptedCredential>(
    k: K,
    v: DecryptedCredential[K],
  ): void => {
    setDraft((d) => ({ ...d, [k]: v }));
  };

  const addUrl = (): void => {
    const trimmed = urlInput.trim();
    if (trimmed === "") return;
    try {
      // Validate via URL constructor; Zod-level url() runs again at
      // submit but we surface the error inline immediately.
      new URL(trimmed);
    } catch {
      setUrlError("Not a valid URL (include https:// prefix)");
      return;
    }
    if (draft.urls.length >= 10) {
      setUrlError("Up to 10 URLs");
      return;
    }
    setUrlError(null);
    setDraft((d) => ({ ...d, urls: [...d.urls, trimmed] }));
    setUrlInput("");
  };

  const removeUrl = (i: number): void => {
    setDraft((d) => ({ ...d, urls: d.urls.filter((_, idx) => idx !== i) }));
  };

  const addCustomField = (): void => {
    if (draft.custom_fields.length >= 20) return;
    setDraft((d) => ({
      ...d,
      custom_fields: [
        ...d.custom_fields,
        { name: "", value: "", hidden: false },
      ],
    }));
  };

  const updateCustomField = (i: number, patch: Partial<CustomField>): void => {
    setDraft((d) => ({
      ...d,
      custom_fields: d.custom_fields.map((cf, idx) =>
        idx === i ? { ...cf, ...patch } : cf,
      ),
    }));
  };

  const removeCustomField = (i: number): void => {
    setDraft((d) => ({
      ...d,
      custom_fields: d.custom_fields.filter((_, idx) => idx !== i),
    }));
  };

  const onCopyPassword = async (): Promise<void> => {
    if (!draft.password) return;
    try {
      await copyPasswordWithClear(draft.password);
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 2_000);
    } catch (e) {
      setLocalError(e instanceof Error ? e.message : "Copy failed");
    }
  };

  const onSubmit = async (e: React.SyntheticEvent): Promise<void> => {
    e.preventDefault();
    setLocalError(null);
    if (draft.name.trim() === "") {
      setLocalError("Name is required");
      return;
    }
    setSaving(true);
    try {
      await onSave(draft);
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const disabled = busy || saving;

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col gap-6 px-6 py-10">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">
          {mode === "new" ? "New credential" : "Edit credential"}
        </h1>
      </header>

      {(error ?? localError) && (
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error ?? localError}
        </p>
      )}

      <form
        onSubmit={(e) => {
          void onSubmit(e);
        }}
        className="flex flex-col gap-5"
      >
        {/* name */}
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Name</span>
          <input
            type="text"
            value={draft.name}
            required
            maxLength={200}
            onChange={(e) => {
              updateField("name", e.target.value);
            }}
            className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
          />
        </label>

        {/* urls */}
        <div className="block text-sm">
          <span className="mb-1 block font-medium">URLs</span>
          <div className="mb-2 flex flex-wrap gap-2">
            {draft.urls.map((u, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs"
              >
                <span className="max-w-[220px] truncate">{u}</span>
                <button
                  type="button"
                  onClick={() => {
                    removeUrl(i);
                  }}
                  className="text-zinc-400 hover:text-red-400"
                  aria-label={`Remove ${u}`}
                >
                  ×
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              type="url"
              value={urlInput}
              placeholder="https://example.com"
              onChange={(e) => {
                setUrlInput(e.target.value);
                setUrlError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addUrl();
                }
              }}
              className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
            />
            <button
              type="button"
              onClick={addUrl}
              className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800"
            >
              Add
            </button>
          </div>
          {urlError && (
            <p role="alert" className="mt-1 text-xs text-red-400">
              {urlError}
            </p>
          )}
        </div>

        {/* username */}
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Username</span>
          <input
            type="text"
            value={draft.username}
            maxLength={200}
            onChange={(e) => {
              updateField("username", e.target.value);
            }}
            className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
          />
        </label>

        {/* password row */}
        <div className="block text-sm">
          <span className="mb-1 flex items-center gap-2 font-medium">
            Password
            {reuseCount > 0 && <ReuseBadge count={reuseCount} />}
          </span>
          <div className="flex gap-2">
            <input
              type={showPassword ? "text" : "password"}
              value={draft.password}
              maxLength={1024}
              onChange={(e) => {
                updateField("password", e.target.value);
              }}
              className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono"
              data-testid="password-input"
            />
            <button
              type="button"
              onClick={() => {
                setShowPassword((s) => !s);
              }}
              className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800"
              aria-pressed={showPassword}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
            <button
              type="button"
              onClick={() => {
                setGenOpen(true);
              }}
              className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800"
            >
              Generate
            </button>
            <button
              type="button"
              onClick={() => {
                void onCopyPassword();
              }}
              disabled={!draft.password}
              className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800 disabled:opacity-40"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <div className="mt-2">
            <StrengthMeter password={draft.password} />
          </div>
          <p className="mt-1 text-xs text-zinc-500">
            Copied passwords are best-effort cleared after{" "}
            {Math.round(CLIPBOARD_CLEAR_MS / 1000)}s. Browsers cannot truly
            clear the OS clipboard if you paste elsewhere.
          </p>
        </div>

        {/* notes */}
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Notes</span>
          <textarea
            value={draft.notes}
            maxLength={10_000}
            rows={4}
            onChange={(e) => {
              updateField("notes", e.target.value);
            }}
            className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
          />
        </label>

        {/* custom fields */}
        <div className="block text-sm">
          <div className="mb-2 flex items-center justify-between">
            <span className="font-medium">Custom fields</span>
            <button
              type="button"
              onClick={addCustomField}
              disabled={draft.custom_fields.length >= 20}
              className="rounded-md border border-zinc-700 px-2 py-1 text-xs hover:bg-zinc-800 disabled:opacity-40"
            >
              + Add field
            </button>
          </div>
          {draft.custom_fields.map((cf, i) => (
            <div key={i} className="mb-2 flex gap-2">
              <input
                type="text"
                placeholder="Name"
                value={cf.name}
                maxLength={100}
                onChange={(e) => {
                  updateCustomField(i, { name: e.target.value });
                }}
                className="w-1/3 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1"
              />
              <input
                type={cf.hidden ? "password" : "text"}
                placeholder="Value"
                value={cf.value}
                maxLength={2000}
                onChange={(e) => {
                  updateCustomField(i, { value: e.target.value });
                }}
                className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1"
              />
              <label className="inline-flex items-center gap-1 text-xs text-zinc-400">
                <input
                  type="checkbox"
                  checked={cf.hidden}
                  onChange={(e) => {
                    updateCustomField(i, { hidden: e.target.checked });
                  }}
                />
                Hidden
              </label>
              <button
                type="button"
                onClick={() => {
                  removeCustomField(i);
                }}
                className="rounded-md border border-zinc-700 px-2 py-1 text-xs hover:bg-red-500/20"
                aria-label="Remove field"
              >
                ×
              </button>
            </div>
          ))}
        </div>

        {/* favorite */}
        <label className="inline-flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.is_favorite}
            onChange={(e) => {
              updateField("is_favorite", e.target.checked);
            }}
          />
          Favorite
        </label>

        {/* actions */}
        <footer className="flex items-center justify-between gap-2 border-t border-zinc-800 pt-4">
          <div className="flex gap-2">
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                disabled={disabled}
                className="rounded-md border border-zinc-700 px-3 py-2 text-sm hover:bg-zinc-800 disabled:opacity-40"
              >
                Cancel
              </button>
            )}
            {mode === "edit" && onDelete && (
              <button
                type="button"
                onClick={() => {
                  void onDelete();
                }}
                disabled={disabled}
                className="rounded-md border border-red-500/40 px-3 py-2 text-sm text-red-300 hover:bg-red-500/10 disabled:opacity-40"
              >
                Delete
              </button>
            )}
          </div>
          <button
            type="submit"
            disabled={disabled}
            className="rounded-md bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500 disabled:opacity-40"
          >
            {saving ? "Saving…" : mode === "new" ? "Create" : "Save"}
          </button>
        </footer>
      </form>

      <GeneratorDialog
        open={genOpen}
        onOpenChange={setGenOpen}
        onAccept={(v) => {
          updateField("password", v);
        }}
      />
    </main>
  );
}
