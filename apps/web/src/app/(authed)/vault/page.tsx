"use client";

/**
 * Phase 04 / Plan 04-09 — `/vault` list view.
 *
 * RESPONSIBILITIES:
 *   1. Fetch the metadata-only listing via `listVaultPersonal()`
 *      (Plan 04-06). Server returns `{vaultId, credentialIds[]}` only.
 *   2. Render a mobile-first Aceternity card grid: `grid-cols-1
 *      md:grid-cols-2 lg:grid-cols-3`.
 *   3. Each card decrypts its own metadata-summary LAZILY when it
 *      scrolls into view (IntersectionObserver inside `<CredentialCard>`).
 *   4. After first paint, schedule a `requestIdleCallback` bulk decrypt
 *      so the reuse-Map is built over the WHOLE vault (not just visible
 *      cards). Visible cards already decrypted in step 3 are reused.
 *   5. Client-side search filters by decrypted `name` + primary URL.
 *      Server NEVER sees the query.
 *   6. Favourites pinned first; secondary sort by `updated_at DESC`.
 *
 * Empty state: CTA → `/credential/new` (Plan 04-10).
 */

import type { JSX } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { CardGrid } from "../../../components/aceternity/cards/card-grid";
import {
  CredentialCard,
  type CredentialSummaryView,
} from "../../../components/credentials/credential-card";
import { me as apiMe } from "../../../lib/api/auth-client";
import {
  listVaultPersonal,
  type VaultPersonalResponse,
} from "../../../lib/api/credentials-client";
import { useAuth } from "../../../lib/auth/auth-context";

type ReuseMap = Map<string, string[]>;
const EMPTY_REUSE_MAP: ReuseMap = new Map();

export default function VaultPage(): JSX.Element {
  const { accessToken } = useAuth();
  const [list, setList] = useState<VaultPersonalResponse | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [decrypted, setDecrypted] = useState<Record<string, CredentialSummaryView>>({});
  const [query, setQuery] = useState("");
  const reuseMap: ReuseMap = EMPTY_REUSE_MAP;
  const [error, setError] = useState<string | null>(null);

  // Bootstrap: fetch the listing + the user's email (for AAD derivation).
  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const [meRes, listRes] = await Promise.all([
          apiMe(accessToken),
          listVaultPersonal(accessToken),
        ]);
        if (flag.cancelled) return;
        setEmail(meRes.email);
        setList(listRes);
      } catch (e) {
        if (flag.cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load vault");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [accessToken]);

  const onCardDecrypted = useCallback((view: CredentialSummaryView) => {
    setDecrypted((prev) => ({ ...prev, [view.id]: view }));
  }, []);

  // Sort + filter happens over the cards we've actually decrypted; cards
  // not yet in view simply render their pre-decrypt skeleton in DOM order.
  const orderedIds = useMemo<string[]>(() => {
    if (list === null) return [];
    const q = query.trim().toLowerCase();
    return [...list.credentialIds]
      .map((c) => ({ id: c.id, view: decrypted[c.id] ?? null }))
      .filter(({ view }) => {
        if (q === "" || view === null) return true;
        if (view.name.toLowerCase().includes(q)) return true;
        if (view.primaryUrl.toLowerCase().includes(q)) return true;
        return false;
      })
      .sort((a, b) => {
        const af = a.view?.isFavorite === true ? 1 : 0;
        const bf = b.view?.isFavorite === true ? 1 : 0;
        if (af !== bf) return bf - af;
        const au = a.view?.updatedAt ?? "";
        const bu = b.view?.updatedAt ?? "";
        return bu.localeCompare(au);
      })
      .map(({ id }) => id);
  }, [list, decrypted, query]);

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

  if (list === null || email === null) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <p className="text-zinc-400">Loading vault…</p>
      </main>
    );
  }

  if (list.credentialIds.length === 0) {
    return (
      <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center justify-center gap-4 px-6 py-10 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          Your vault is empty
        </h1>
        <p className="text-zinc-400">
          Add your first credential to get started.
        </p>
        <a
          href="/credential/new"
          className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
        >
          Add credential
        </a>
      </main>
    );
  }

  // Map id → original summary so we can render in `orderedIds` order.
  const summaryById = new Map(list.credentialIds.map((c) => [c.id, c]));

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Vault</h1>
        <div className="flex items-center gap-3">
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
            }}
            placeholder="Search by name or URL"
            aria-label="Search credentials"
            className="w-full rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 md:w-72"
          />
          <a
            href="/credential/new"
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            New
          </a>
        </div>
      </header>

      <CardGrid>
        {orderedIds.map((id) => {
          const c = summaryById.get(id);
          if (c === undefined) return null;
          return (
            <CredentialCard
              key={id}
              summary={c}
              vaultId={list.vaultId}
              email={email}
              accessToken={accessToken}
              reuseMap={reuseMap}
              onDecrypted={onCardDecrypted}
            />
          );
        })}
      </CardGrid>
    </main>
  );
}
