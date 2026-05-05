"use client";

/**
 * Phase 05 / Plan 05-05 — `/page/new`.
 *
 * Create flow:
 *   1. fetch /vault/personal → vaultId; fetch /me → email (sha256(email)
 *      bound into AAD).
 *   2. user enters a title + body (TipTap JSON).
 *   3. client generates a UUIDv4 LOCALLY (crypto.randomUUID) — closes the
 *      AAD-self-consistency gap on POST (sibling parity with credentials).
 *   4. encryptPage({tiptapJson, isFavorite: false, meta: {title}}, masterDek,
 *      {vaultId, pageId, version: 1, email}) → {ciphertext, nonce,
 *      aadParamsJson, titleSearchToken}.
 *   5. createPage(envelope) → router.replace(`/page/[id]`).
 */

import { ready } from "@simplevault/crypto/browser";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { JSX } from "react";

import { PageEditor } from "../../../../components/tiptap-editor";
import { me as apiMe } from "../../../../lib/api/auth-client";
import { listVaultPersonal } from "../../../../lib/api/credentials-client";
import { createPage } from "../../../../lib/api/pages-client";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";
import { encryptPage } from "../../../../lib/crypto/page-cipher";

type TipTapDoc = { type: "doc"; content?: unknown[] };

const EMPTY_DOC: TipTapDoc = { type: "doc", content: [{ type: "paragraph" }] };

export default function NewPagePage(): JSX.Element {
  const router = useRouter();
  const { accessToken } = useAuth();
  const [bootError, setBootError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [ctx, setCtx] = useState<{ vaultId: string; email: string } | null>(
    null,
  );
  const [title, setTitle] = useState("");
  const [doc, setDoc] = useState<TipTapDoc>(EMPTY_DOC);

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    void (async (): Promise<void> => {
      try {
        await ready();
        const [vault, who] = await Promise.all([
          listVaultPersonal(accessToken),
          apiMe(accessToken),
        ]);
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (cancelled) return;
        setCtx({ vaultId: vault.vaultId, email: who.email });
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (cancelled) return;
        setBootError(
          e instanceof Error ? e.message : "Failed to load vault context",
        );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken]);

  const onSave = async (): Promise<void> => {
    if (accessToken === null || ctx === null) {
      setSaveError("Not ready");
      return;
    }
    setSaveError(null);
    const masterDek = keyStore.getBytes("master_dek");
    if (masterDek === undefined) {
      setSaveError("Vault is locked. Sign in again.");
      return;
    }
    const trimmed = title.trim();
    if (trimmed === "") {
      setSaveError("Title is required.");
      return;
    }
    setSaving(true);
    try {
      const pageId = crypto.randomUUID();
      const envelope = await encryptPage(
        {
          tiptapJson: doc,
          isFavorite: false,
          meta: { title: trimmed, createdAt: new Date().toISOString() },
        },
        masterDek,
        {
          vaultId: ctx.vaultId,
          pageId,
          version: 1,
          email: ctx.email,
        },
      );
      await createPage(accessToken, {
        vaultId: ctx.vaultId,
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        aadParamsJson: envelope.aadParamsJson,
        titleSearchToken: envelope.titleSearchToken,
      });
      router.replace(`/page/${encodeURIComponent(pageId)}`);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  if (bootError !== null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {bootError}
        </p>
      </main>
    );
  }
  if (ctx === null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col gap-6 px-6 py-10">
      <header className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold tracking-tight">New page</h1>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => {
              router.replace("/pages");
            }}
            className="rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              void onSave();
            }}
            disabled={saving}
            className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </header>

      <input
        type="text"
        value={title}
        onChange={(e) => {
          setTitle(e.target.value);
        }}
        placeholder="Title"
        aria-label="Page title"
        className="w-full rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-lg text-zinc-100 placeholder:text-zinc-500"
      />

      <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-3">
        <PageEditor
          value={doc}
          onChange={(next: unknown) => {
            setDoc(next as TipTapDoc);
          }}
        />
      </div>

      {saveError !== null ? (
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {saveError}
        </p>
      ) : null}
    </main>
  );
}
