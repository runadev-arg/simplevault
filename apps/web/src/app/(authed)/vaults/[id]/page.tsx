"use client";

/**
 * Phase 07 / Plan 07-04 — `/vaults/[id]` shared vault credential list.
 *
 * Near-identical to the personal vault page (`/vault`) but:
 *   - Loads vaultId from route params.
 *   - Loads the vault DEK from keyStore under "vault_dek:<vaultId>".
 *   - Fetches credential IDs from GET /vault/:id (shared vault listing).
 *   - Passes the vault DEK to <CredentialCard> via the optional `dek` prop.
 *   - Header includes Invite + Members buttons.
 */

import { z } from "zod";
import { ready } from "@simplevault/crypto/browser";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { JSX } from "react";
import { useParams } from "next/navigation";

import { CardGrid } from "../../../../components/aceternity/cards/card-grid";
import {
  CredentialCard,
  type CredentialSummaryView,
} from "../../../../components/credentials/credential-card";
import { me as apiMe } from "../../../../lib/api/auth-client";
import { request } from "../../../../lib/api/auth-client";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";

// Inline API wrapper for the shared vault credential listing.
// GET /vault/:id — mirrors the shape of listVaultPersonal.
async function listVaultCredentials(accessToken: string, vaultId: string) {
  return request(`/vault/${encodeURIComponent(vaultId)}`, {
    method: "GET",
    schema: z.object({
      vaultId: z.string().uuid(),
      credentialIds: z.array(
        z.object({
          id: z.string().uuid(),
          version: z.number(),
          updatedAt: z.string(),
        }),
      ),
    }),
    accessToken,
  });
}

type VaultCredentialsResponse = {
  vaultId: string;
  credentialIds: { id: string; version: number; updatedAt: string }[];
};

type ReuseMap = Map<string, string[]>;
const EMPTY_REUSE_MAP: ReuseMap = new Map();

export default function SharedVaultPage(): JSX.Element {
  const { accessToken } = useAuth();
  const params = useParams<{ id: string }>();
  const vaultId = params.id;

  const [list, setList] = useState<VaultCredentialsResponse | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [decrypted, setDecrypted] = useState<Record<string, CredentialSummaryView>>({});
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Load vault DEK from keyStore. If missing, the user needs to accept their
  // invite or sign in again.
  const vaultDek = keyStore.getBytes(`vault_dek:${vaultId}`);

  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        await ready();
        const [meRes, listRes] = await Promise.all([
          apiMe(accessToken),
          listVaultCredentials(accessToken, vaultId),
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
  }, [accessToken, vaultId]);

  const onCardDecrypted = useCallback((view: CredentialSummaryView) => {
    setDecrypted((prev) => ({ ...prev, [view.id]: view }));
  }, []);

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

  if (vaultDek === undefined) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
        >
          Vault DEK not loaded. Please accept your invite again or sign in.
        </p>
        <div className="mt-4 flex gap-3">
          <a
            href="/invites"
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            Go to Invites
          </a>
          <a
            href="/vaults"
            className="rounded-md border border-zinc-700 px-3 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
          >
            Back to Vaults
          </a>
        </div>
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
          Vault is empty
        </h1>
        <p className="text-zinc-400">Add the first credential to this vault.</p>
        <div className="flex gap-3">
          <a
            href={`/credential/new?vaultId=${encodeURIComponent(vaultId)}`}
            className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            Add credential
          </a>
          <a
            href={`/vaults/${encodeURIComponent(vaultId)}/invite`}
            className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
          >
            Invite
          </a>
        </div>
      </main>
    );
  }

  const summaryById = new Map(list.credentialIds.map((c) => [c.id, c]));

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-6 px-6 py-10">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">
          Shared Vault
        </h1>
        <div className="flex items-center gap-2 flex-wrap">
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
            }}
            placeholder="Search by name or URL"
            aria-label="Search credentials"
            className="w-full rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 md:w-64"
          />
          <a
            href={`/credential/new?vaultId=${encodeURIComponent(vaultId)}`}
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            New
          </a>
          <a
            href={`/vaults/${encodeURIComponent(vaultId)}/invite`}
            className="rounded-md border border-zinc-700 px-3 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
          >
            Invite
          </a>
          <a
            href={`/vaults/${encodeURIComponent(vaultId)}/members`}
            className="rounded-md border border-zinc-700 px-3 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800"
          >
            Members
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
              reuseMap={EMPTY_REUSE_MAP}
              onDecrypted={onCardDecrypted}
              dek={vaultDek}
            />
          );
        })}
      </CardGrid>
    </main>
  );
}
