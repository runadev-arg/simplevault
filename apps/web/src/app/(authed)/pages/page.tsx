"use client";

/**
 * Phase 05 / Plan 05-05 — `/pages` list view.
 *
 * RESPONSIBILITIES:
 *   1. Fetch metadata listing via `listPages()` (Plan 05-02).
 *   2. Derive the per-vault `titleSearchKey` from `master_DEK` once on
 *      mount (HKDF-Expand info `"sv:title-search:v1"`); kept in component
 *      state, never persisted.
 *   3. For each page metadata, GET the full envelope and decrypt to
 *      extract title + favorite flag (eager-all per ≤50-user scale; INDEX
 *      Truth 7 says body-search is client-side over the loaded set).
 *   4. Title search bar (debounced 200ms): on input, compute the 8-byte
 *      `computeTitleSearchToken(titleSearchKey, query.toLowerCase())`,
 *      hex-encode, refetch via `searchPagesByTitlePrefix(hex)`. Empty
 *      query → unfiltered listing.
 *   5. Body-search toggle: client-side filter over decrypted titles +
 *      body text (REQ-VAULT-010). Does NOT hit the server.
 *   6. Favourites pinned first; secondary sort by `updatedAt` desc.
 *   7. Empty state CTA → `/page/new`.
 */

import {
  computeTitleSearchToken,
  deriveTitleSearchKey,
  ready,
} from "@simplevault/crypto/browser";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { JSX } from "react";

import { Card, CardDescription, CardGrid, CardHoverItem, CardTitle } from "../../../components/aceternity/cards/card-grid";
import { me as apiMe } from "../../../lib/api/auth-client";
import {
  getPage,
  listPages,
  searchPagesByTitlePrefix,
  type PageSummary,
} from "../../../lib/api/pages-client";
import { useAuth } from "../../../lib/auth/auth-context";
import { keyStore } from "../../../lib/auth/key-store";
import { decryptPage, extractTitle } from "../../../lib/crypto/page-cipher";

interface DecryptedSummary {
  id: string;
  title: string;
  bodyText: string;
  isFavorite: boolean;
  updatedAt: string;
  version: number;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/** Pull plain-text body content from a TipTap JSON document for body-search. */
function extractBodyText(tiptapJson: unknown): string {
  const out: string[] = [];
  const walk = (node: unknown): void => {
    if (typeof node !== "object" || node === null) return;
    const n = node as { text?: unknown; content?: unknown };
    if (typeof n.text === "string") out.push(n.text);
    if (Array.isArray(n.content)) {
      for (const c of n.content) walk(c);
    }
  };
  walk(tiptapJson);
  return out.join(" ");
}

export default function PagesListPage(): JSX.Element {
  const { accessToken } = useAuth();
  const [list, setList] = useState<PageSummary[] | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [titleKey, setTitleKey] = useState<Uint8Array | null>(null);
  const [decrypted, setDecrypted] = useState<Record<string, DecryptedSummary>>(
    {},
  );
  const [query, setQuery] = useState("");
  const [bodySearch, setBodySearch] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Bootstrap: fetch /me + derive titleSearchKey + initial unfiltered list.
  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        await ready();
        const masterDek = keyStore.getBytes("master_dek");
        if (masterDek === undefined) {
          throw new Error("Vault is locked. Sign in again.");
        }
        const [meRes, listRes, key] = await Promise.all([
          apiMe(accessToken),
          listPages(accessToken),
          deriveTitleSearchKey(masterDek),
        ]);
        if (flag.cancelled) return;
        setEmail(meRes.email);
        setList(listRes);
        setTitleKey(key);
      } catch (e) {
        if (flag.cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load pages");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [accessToken]);

  // Eager decrypt of every page in the list (title + favorite + body for
  // client-side body-search). For ≤50-user scale, eager-all is fine; INDEX
  // Truth 7 + REQ-VAULT-010 say body search MUST be client-side. We drop
  // any plaintext-bytes references after extracting the few text fields.
  useEffect(() => {
    if (list === null || email === null || accessToken === null) return undefined;
    if (list.length === 0) return undefined;
    let cancelled = false;
    void (async (): Promise<void> => {
      try {
        const masterDek = keyStore.getBytes("master_dek");
        if (masterDek === undefined) return;
        const blobs = await Promise.all(list.map((p) => getPage(accessToken, p.id)));
        if (cancelled) return;
        const decryptedAll = await Promise.all(
          blobs.map(async (blob) => {
            const plain = await decryptPage(
              {
                ciphertext: blob.ciphertext,
                nonce: blob.nonce,
                aadParamsJson: blob.aadParamsJson,
              },
              masterDek,
              { email },
            );
            const title = extractTitle(plain.tiptapJson);
            const bodyText = extractBodyText(plain.tiptapJson);
            const isFavorite = plain.meta?.isFavorite === true;
            return {
              id: blob.id,
              title,
              bodyText,
              isFavorite,
              updatedAt: blob.updatedAt,
              version: blob.version,
            } satisfies DecryptedSummary;
          }),
        );
        if (cancelled) return;
        const map: Record<string, DecryptedSummary> = {};
        for (const d of decryptedAll) map[d.id] = d;
        setDecrypted(map);
      } catch {
        // Silent: decryption failures stay as un-decrypted skeleton cards.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [list, email, accessToken]);

  // Debounced title-prefix search — refetches the server list with the
  // 8-byte HMAC token's hex prefix when the query is non-empty.
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onQueryChange = useCallback(
    (q: string) => {
      setQuery(q);
      if (titleKey === null || accessToken === null) return;
      if (debounceTimer.current !== null) clearTimeout(debounceTimer.current);
      debounceTimer.current = setTimeout(() => {
        void (async (): Promise<void> => {
          try {
            const trimmed = q.trim();
            if (trimmed === "" || bodySearch) {
              // Body-search mode does its own client-side filter — server
              // listing stays unfiltered so the local set is whole.
              const all = await listPages(accessToken);
              setList(all);
              return;
            }
            const token = await computeTitleSearchToken(
              titleKey,
              trimmed.toLowerCase(),
            );
            const hex = bytesToHex(token);
            const res = await searchPagesByTitlePrefix(accessToken, hex);
            setList(res);
          } catch (e) {
            setError(e instanceof Error ? e.message : "Search failed");
          }
        })();
      }, 200);
    },
    [titleKey, accessToken, bodySearch],
  );

  // Final ordering: favorites first, then updatedAt desc; body-search (if
  // enabled) further filters over decrypted title+body.
  const orderedIds = useMemo<string[]>(() => {
    if (list === null) return [];
    const q = query.trim().toLowerCase();
    return [...list]
      .map((p) => ({ id: p.id, summary: decrypted[p.id] ?? null, updatedAt: p.updatedAt }))
      .filter(({ summary }) => {
        if (!bodySearch || q === "") return true;
        if (summary === null) return false;
        return (
          summary.title.toLowerCase().includes(q) ||
          summary.bodyText.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => {
        const af = a.summary?.isFavorite === true ? 1 : 0;
        const bf = b.summary?.isFavorite === true ? 1 : 0;
        if (af !== bf) return bf - af;
        const au = a.summary?.updatedAt ?? a.updatedAt;
        const bu = b.summary?.updatedAt ?? b.updatedAt;
        return bu.localeCompare(au);
      })
      .map(({ id }) => id);
  }, [list, decrypted, query, bodySearch]);

  if (accessToken === null) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  if (error !== null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error}
        </p>
      </main>
    );
  }

  if (list === null) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <p className="text-zinc-400">Loading pages…</p>
      </main>
    );
  }

  if (list.length === 0) {
    return (
      <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center justify-center gap-4 px-6 py-10 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">No pages yet</h1>
        <p className="text-zinc-400">
          Create your first page to start writing.
        </p>
        <a
          href="/page/new"
          className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
        >
          New page
        </a>
      </main>
    );
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Pages</h1>
        <div className="flex flex-col items-stretch gap-3 md:flex-row md:items-center">
          <input
            type="search"
            value={query}
            onChange={(e) => {
              onQueryChange(e.target.value);
            }}
            placeholder={bodySearch ? "Search title + body" : "Search by title"}
            aria-label="Search pages"
            className="w-full rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 md:w-72"
          />
          <label className="flex items-center gap-2 text-xs text-zinc-400">
            <input
              type="checkbox"
              checked={bodySearch}
              onChange={(e) => {
                setBodySearch(e.target.checked);
              }}
              aria-label="Toggle body search"
            />
            Body search
          </label>
          <a
            href="/page/new"
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            New
          </a>
        </div>
      </header>

      <CardGrid>
        {orderedIds.map((id) => {
          const summary = decrypted[id];
          return (
            <CardHoverItem key={id}>
              <a href={`/page/${encodeURIComponent(id)}`}>
                <Card>
                  <CardTitle>
                    {summary?.isFavorite === true ? "★ " : ""}
                    {summary?.title ?? "Decrypting…"}
                  </CardTitle>
                  <CardDescription>
                    {summary === undefined
                      ? ""
                      : (summary.bodyText.slice(0, 120) || "Empty page")}
                  </CardDescription>
                </Card>
              </a>
            </CardHoverItem>
          );
        })}
      </CardGrid>
    </main>
  );
}
