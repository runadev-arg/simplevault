"use client";

/**
 * Phase 05 / Plan 05-05 — `/page/[id]`.
 *
 * Edit flow:
 *   1. fetch /vault/personal → vaultId; fetch /me → email; fetch
 *      /pages/:id → blob.
 *   2. decrypt → {tiptapJson, isFavorite, meta}.
 *   3. user edits title + body.
 *   4. on save: re-encrypt with version: current+1, PATCH with witness
 *      version: current. On 409 PageVersionConflictError, surface a typed
 *      retry-or-cancel modal (NEVER silent — INDEX Truth + REQ).
 *   5. version-history side panel: GET /pages/:id/history; click a row to
 *      LAZILY decrypt that single version and render via
 *      <RenderedTipTapHtml>. NEVER decrypt the whole history eagerly.
 *   6. delete button → confirm → deletePage → /pages.
 *   7. favorite toggle → re-encrypt with meta.isFavorite flipped (PATCH).
 */

import { ready } from "@simplevault/crypto/browser";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { JSX } from "react";

import {
  PageEditor,
  RenderedTipTapHtml,
} from "../../../../components/tiptap-editor";
import { me as apiMe } from "../../../../lib/api/auth-client";
import { listVaultPersonal } from "../../../../lib/api/credentials-client";
import {
  deletePage,
  getPage,
  getPageHistory,
  patchPage,
  PageVersionConflictError,
  type PageHistoryItem,
} from "../../../../lib/api/pages-client";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";
import {
  decryptPage,
  encryptPage,
  type DecryptedPagePlaintext,
} from "../../../../lib/crypto/page-cipher";

interface Baseline {
  vaultId: string;
  email: string;
  version: number;
  decrypted: DecryptedPagePlaintext;
}

interface HistoryPreview {
  version: number;
  html: string;
}

type TipTapDoc = { type: "doc"; content?: unknown[] };

export default function EditPagePage(): JSX.Element {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { accessToken } = useAuth();
  const [baseline, setBaseline] = useState<Baseline | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [title, setTitle] = useState("");
  const [doc, setDoc] = useState<TipTapDoc | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [history, setHistory] = useState<PageHistoryItem[] | null>(null);
  const [preview, setPreview] = useState<HistoryPreview | null>(null);
  const [conflict, setConflict] = useState<null | { fresh: Baseline }>(null);

  useEffect(() => {
    if (accessToken === null || !id) return;
    let cancelled = false;
    void (async (): Promise<void> => {
      try {
        await ready();
        const masterDek = keyStore.getBytes("master_dek");
        if (masterDek === undefined) {
          throw new Error("Vault is locked. Sign in again.");
        }
        const [vault, who, blob] = await Promise.all([
          listVaultPersonal(accessToken),
          apiMe(accessToken),
          getPage(accessToken, id),
        ]);
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (cancelled) return;
        const plain = await decryptPage(
          {
            ciphertext: blob.ciphertext,
            nonce: blob.nonce,
            aadParamsJson: blob.aadParamsJson,
          },
          masterDek,
          { email: who.email },
        );
        setBaseline({
          vaultId: vault.vaultId,
          email: who.email,
          version: blob.version,
          decrypted: plain,
        });
        setTitle(plain.meta?.title ?? "");
        setDoc((plain.tiptapJson as TipTapDoc | null) ?? { type: "doc" });
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (cancelled) return;
        setBootError(e instanceof Error ? e.message : "Failed to load page");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken, id]);

  const persist = async (
    base: Baseline,
    nextDoc: TipTapDoc,
    nextTitle: string,
    nextFavorite: boolean,
  ): Promise<void> => {
    if (accessToken === null) return;
    const masterDek = keyStore.getBytes("master_dek");
    if (masterDek === undefined) {
      setSaveError("Vault is locked. Sign in again.");
      return;
    }
    const newVersion = base.version + 1;
    const envelope = await encryptPage(
      {
        tiptapJson: nextDoc,
        isFavorite: nextFavorite,
        meta: { ...base.decrypted.meta, title: nextTitle.trim() },
      },
      masterDek,
      {
        vaultId: base.vaultId,
        pageId: id,
        version: newVersion,
        email: base.email,
      },
    );
    try {
      await patchPage(accessToken, id, {
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        aadParamsJson: envelope.aadParamsJson,
        titleSearchToken: envelope.titleSearchToken,
        version: base.version, // CAS witness — caller's known-current.
      });
      setBaseline({
        ...base,
        version: newVersion,
        decrypted: {
          tiptapJson: nextDoc,
          isFavorite: nextFavorite,
          meta: { ...base.decrypted.meta, title: nextTitle.trim() },
        },
      });
    } catch (err) {
      if (err instanceof PageVersionConflictError) {
        // Re-fetch the FRESH server state and surface a typed
        // retry-or-cancel UX (NEVER silent).
        const fresh = await getPage(accessToken, id);
        const freshPlain = await decryptPage(
          {
            ciphertext: fresh.ciphertext,
            nonce: fresh.nonce,
            aadParamsJson: fresh.aadParamsJson,
          },
          masterDek,
          { email: base.email },
        );
        setConflict({
          fresh: {
            vaultId: base.vaultId,
            email: base.email,
            version: fresh.version,
            decrypted: freshPlain,
          },
        });
        return;
      }
      throw err;
    }
  };

  const onSave = async (): Promise<void> => {
    if (baseline === null || doc === null) return;
    setSaveError(null);
    setSaving(true);
    try {
      await persist(baseline, doc, title, baseline.decrypted.isFavorite);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const onToggleFavorite = async (): Promise<void> => {
    if (baseline === null || doc === null) return;
    setSaveError(null);
    setSaving(true);
    try {
      await persist(baseline, doc, title, !baseline.decrypted.isFavorite);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const onDelete = async (): Promise<void> => {
    if (accessToken === null) return;
    const ok = window.confirm("Delete this page? This cannot be undone.");
    if (!ok) return;
    await deletePage(accessToken, id);
    router.replace("/pages");
  };

  // History panel: lazy-load the history list when opened; per-version
  // decrypt only happens on click.
  useEffect(() => {
    if (!historyOpen || accessToken === null) return;
    if (history !== null) return;
    void (async (): Promise<void> => {
      try {
        const items = await getPageHistory(accessToken, id);
        setHistory(items);
      } catch (e) {
        setSaveError(e instanceof Error ? e.message : "Failed to load history");
      }
    })();
  }, [historyOpen, accessToken, id, history]);

  const onPreviewVersion = async (item: PageHistoryItem): Promise<void> => {
    if (accessToken === null || baseline === null) return;
    const masterDek = keyStore.getBytes("master_dek");
    if (masterDek === undefined) return;
    try {
      const plain = await decryptPage(
        {
          ciphertext: item.ciphertext,
          nonce: item.nonce,
          aadParamsJson: item.aadParamsJson,
        },
        masterDek,
        { email: baseline.email },
      );
      // Convert tiptapJson to HTML for the read-only preview. We rely on
      // `<RenderedTipTapHtml>` to defensively sanitize before render.
      // If the editor pkg ships a JSON→HTML helper we'd call it; for now
      // we pass through a JSON.stringify shim — sibling 05-04 owns the
      // exact contract.
      const html =
        typeof plain.tiptapJson === "string"
          ? (plain.tiptapJson as string)
          : JSON.stringify(plain.tiptapJson);
      setPreview({ version: item.version, html });
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Decrypt failed");
    }
  };

  const onRestoreVersion = async (item: PageHistoryItem): Promise<void> => {
    if (baseline === null) return;
    const masterDek = keyStore.getBytes("master_dek");
    if (masterDek === undefined) return;
    const ok = window.confirm(
      `Restore version ${item.version.toString()} as a new edit?`,
    );
    if (!ok) return;
    try {
      const plain = await decryptPage(
        {
          ciphertext: item.ciphertext,
          nonce: item.nonce,
          aadParamsJson: item.aadParamsJson,
        },
        masterDek,
        { email: baseline.email },
      );
      setSaving(true);
      await persist(
        baseline,
        plain.tiptapJson as TipTapDoc,
        plain.meta?.title ?? title,
        baseline.decrypted.isFavorite,
      );
      setDoc(plain.tiptapJson as TipTapDoc);
      setTitle(plain.meta?.title ?? title);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Restore failed");
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
  if (baseline === null || doc === null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-6 py-10 md:flex-row">
      <section className="flex flex-1 flex-col gap-4">
        <header className="flex items-center justify-between gap-4">
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">
            Edit page <span className="text-zinc-500">v{baseline.version}</span>
          </h1>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => {
                void onToggleFavorite();
              }}
              className="rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900"
              aria-label="Toggle favorite"
            >
              {baseline.decrypted.isFavorite ? "★" : "☆"}
            </button>
            <button
              type="button"
              onClick={() => {
                setHistoryOpen((v) => !v);
              }}
              className="rounded-md border border-zinc-800 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-900"
            >
              {historyOpen ? "Hide history" : "History"}
            </button>
            <button
              type="button"
              onClick={() => {
                void onDelete();
              }}
              className="rounded-md border border-red-500/40 px-3 py-2 text-sm text-red-200 hover:bg-red-500/10"
            >
              Delete
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

        {conflict !== null ? (
          <div
            role="alertdialog"
            aria-modal="true"
            className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-100"
          >
            <p className="font-medium">
              This page changed in another tab.
            </p>
            <p className="mt-1 text-amber-200/90">
              The server is now at v{conflict.fresh.version.toString()}. Reload
              to see the latest, or cancel to keep your in-progress edits and
              try again.
            </p>
            <div className="mt-3 flex gap-2">
              <button
                type="button"
                onClick={() => {
                  setBaseline(conflict.fresh);
                  setDoc(conflict.fresh.decrypted.tiptapJson as TipTapDoc);
                  setTitle(conflict.fresh.decrypted.meta?.title ?? "");
                  setConflict(null);
                }}
                className="rounded-md bg-amber-100 px-3 py-2 text-sm font-medium text-amber-900 hover:bg-amber-50"
              >
                Reload latest
              </button>
              <button
                type="button"
                onClick={() => {
                  setConflict(null);
                }}
                className="rounded-md border border-amber-500/40 px-3 py-2 text-sm text-amber-100 hover:bg-amber-500/10"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {historyOpen ? (
        <aside className="w-full shrink-0 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 md:w-80">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-400">
            Version history
          </h2>
          {history === null ? (
            <p className="mt-2 text-sm text-zinc-500">Loading…</p>
          ) : history.length === 0 ? (
            <p className="mt-2 text-sm text-zinc-500">No prior versions yet.</p>
          ) : (
            <ul className="mt-3 flex flex-col gap-2">
              {history.map((h) => (
                <li
                  key={h.version}
                  className="rounded-md border border-zinc-800 bg-zinc-950/50 p-2 text-sm"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-zinc-200">
                      v{h.version}
                    </span>
                    <span className="text-xs text-zinc-500">
                      {new Date(h.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="mt-2 flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        void onPreviewVersion(h);
                      }}
                      className="rounded-md border border-zinc-800 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-900"
                    >
                      Preview
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        void onRestoreVersion(h);
                      }}
                      className="rounded-md border border-zinc-800 px-2 py-1 text-xs text-zinc-200 hover:bg-zinc-900"
                    >
                      Restore
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {preview !== null ? (
            <div className="mt-4 rounded-md border border-zinc-800 bg-zinc-950/50 p-3">
              <p className="mb-2 text-xs uppercase tracking-wide text-zinc-500">
                Preview v{preview.version}
              </p>
              <RenderedTipTapHtml html={preview.html} />
            </div>
          ) : null}
        </aside>
      ) : null}
    </main>
  );
}
