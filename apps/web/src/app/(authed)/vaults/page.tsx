"use client";

/**
 * Phase 07 / Plan 07-04 — `/vaults` overview page.
 *
 * Lists all vaults the authenticated user has access to:
 *   - One personal vault (kind="personal") rendered as a standalone card.
 *   - Zero or more shared vaults (kind="shared") rendered in a CardGrid.
 *
 * Does NOT fetch pending invites — just shows a static link to /invites.
 */

import { useEffect, useState } from "react";
import type { JSX } from "react";

import {
  Card,
  CardDescription,
  CardGrid,
  CardHoverItem,
  CardTitle,
} from "../../../components/aceternity/cards/card-grid";
import { useAuth } from "../../../lib/auth/auth-context";
import {
  listAllVaults,
  type VaultListItem,
} from "../../../lib/api/vault-sharing-client";

export default function VaultsPage(): JSX.Element {
  const { accessToken } = useAuth();
  const [vaults, setVaults] = useState<VaultListItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const list = await listAllVaults(accessToken);
        if (flag.cancelled) return;
        setVaults(list);
      } catch (e) {
        if (flag.cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load vaults");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [accessToken]);

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

  if (vaults === null) {
    return (
      <main className="mx-auto max-w-6xl px-6 py-10">
        <p className="text-zinc-400">Loading vaults…</p>
      </main>
    );
  }

  const personalVault = vaults.find((v) => v.kind === "personal") ?? null;
  const sharedVaults = vaults.filter((v) => v.kind === "shared");

  return (
    <main className="mx-auto flex min-h-screen max-w-6xl flex-col gap-10 px-6 py-10">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Vaults</h1>
        <div className="flex items-center gap-3">
          <a
            href="/invites"
            className="text-sm text-zinc-400 hover:text-zinc-100"
          >
            Pending invites
          </a>
          <a
            href="/vaults/new"
            className="rounded-md bg-zinc-100 px-3 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            New vault
          </a>
        </div>
      </header>

      {/* Personal vault */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium uppercase tracking-wider text-zinc-500">
          Personal
        </h2>
        {personalVault !== null ? (
          <a href="/vault" className="block max-w-xs">
            <CardHoverItem>
              <Card>
                <CardTitle>Personal Vault</CardTitle>
                <CardDescription>Your private credential store</CardDescription>
                <p className="mt-2 text-xs text-zinc-500">Owner</p>
              </Card>
            </CardHoverItem>
          </a>
        ) : (
          <p className="text-sm text-zinc-500">No personal vault found.</p>
        )}
      </section>

      {/* Shared vaults */}
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium uppercase tracking-wider text-zinc-500">
          Shared
        </h2>
        {sharedVaults.length === 0 ? (
          <div className="flex flex-col items-start gap-3">
            <p className="text-sm text-zinc-400">No shared vaults yet.</p>
            <a
              href="/vaults/new"
              className="rounded-md bg-zinc-800 px-3 py-2 text-sm font-medium text-zinc-100 hover:bg-zinc-700"
            >
              Create a shared vault
            </a>
          </div>
        ) : (
          <CardGrid>
            {sharedVaults.map((vault) => (
              <a key={vault.id} href={`/vaults/${vault.id}`} className="block h-full">
                <CardHoverItem>
                  <Card>
                    <div className="flex items-start justify-between gap-2">
                      <CardTitle>{vault.name ?? "Unnamed vault"}</CardTitle>
                      <span
                        className={`mt-2 shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${
                          vault.role === "owner"
                            ? "bg-violet-500/20 text-violet-300"
                            : "bg-zinc-700 text-zinc-300"
                        }`}
                      >
                        {vault.role}
                      </span>
                    </div>
                    <CardDescription>
                      {vault.memberCount}{" "}
                      {vault.memberCount === 1 ? "member" : "members"}
                    </CardDescription>
                  </Card>
                </CardHoverItem>
              </a>
            ))}
          </CardGrid>
        )}
      </section>
    </main>
  );
}
