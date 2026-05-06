"use client";

/**
 * Phase 07 / Plan 07-05 — `/invites`
 *
 * Shows pending invites for the current user. Each invite can be accepted
 * (unwraps the vault DEK and stores it in keyStore before redirecting to the
 * vault) or declined (removed from the local list).
 */

import { type JSX, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import sodium from "libsodium-wrappers-sumo";

import { ready } from "@simplevault/crypto/browser";
import { useAuth } from "../../../lib/auth/auth-context";
import { keyStore } from "../../../lib/auth/key-store";
import { unwrapVaultKey } from "../../../lib/crypto/vault-key";
import {
  type PendingInvite,
  acceptInvite,
  declineInvite,
  getPendingInvites,
} from "../../../lib/api/vault-sharing-client";

export default function InvitesPage(): JSX.Element {
  const { accessToken } = useAuth();
  const router = useRouter();

  const [list, setList] = useState<PendingInvite[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [processing, setProcessing] = useState<string | null>(null); // invite id being acted on

  useEffect(() => {
    if (accessToken === null) return undefined;
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        await ready();
        const invites = await getPendingInvites(accessToken);
        if (flag.cancelled) return;
        setList(invites);
      } catch (e) {
        if (flag.cancelled) return;
        setError(e instanceof Error ? e.message : "Failed to load invites");
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, [accessToken]);

  async function handleAccept(invite: PendingInvite): Promise<void> {
    if (accessToken === null) return;
    setError(null);
    setProcessing(invite.id);
    try {
      // kx_pk is never stored — always derived on demand from kx_sk.
      const kxSk = keyStore.getBytes("kx_sk");

      if (kxSk === undefined) {
        setError("kx_sk_missing");
        setProcessing(null);
        return;
      }

      const kxPk = sodium.crypto_scalarmult_base(kxSk);

      const vaultDek = await unwrapVaultKey(invite.wrappedVaultKey, kxPk, kxSk);
      // Confirm server-side first; only store DEK in memory on success.
      await acceptInvite(accessToken, invite.id);
      keyStore.set("vault_dek:" + invite.vaultId, vaultDek);
      router.push("/vaults/" + invite.vaultId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to accept invite.");
      setProcessing(null);
    }
  }

  async function handleDecline(invite: PendingInvite): Promise<void> {
    if (accessToken === null) return;
    setError(null);
    setProcessing(invite.id);
    try {
      await declineInvite(accessToken, invite.id);
      setList((prev) => (prev === null ? null : prev.filter((i) => i.id !== invite.id)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to decline invite.");
    } finally {
      setProcessing(null);
    }
  }

  if (accessToken === null) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  if (error !== null) {
    const isLocked = error === "kx_sk_missing";
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {isLocked
            ? "Your vault key is not loaded. Please sign in again to accept invites."
            : error}
        </p>
        {isLocked && (
          <Link
            href="/login"
            className="mt-3 inline-block rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white"
          >
            Sign in again
          </Link>
        )}
      </main>
    );
  }

  if (list === null) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-10">
        <p className="text-zinc-400">Loading invites…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-10">
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">Pending Invites</h1>

      {list.length === 0 ? (
        <p className="text-zinc-400">No pending invites.</p>
      ) : (
        <ul className="flex flex-col gap-4">
          {list.map((invite) => (
            <li
              key={invite.id}
              className="flex flex-col gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 px-5 py-4 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="flex flex-col gap-1">
                <p className="font-medium text-zinc-100">
                  {invite.vaultName ?? "Unnamed vault"}
                </p>
                <p className="text-sm text-zinc-400">
                  Invited by: {invite.invitedByEmail}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={processing === invite.id}
                  onClick={() => void handleAccept(invite)}
                  className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-50"
                >
                  {processing === invite.id ? "Processing…" : "Accept"}
                </button>
                <button
                  type="button"
                  disabled={processing === invite.id}
                  onClick={() => void handleDecline(invite)}
                  className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
                >
                  Decline
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
