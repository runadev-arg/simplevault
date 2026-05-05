"use client";

/**
 * Phase 07 / Plan 07-05 — `/vaults/[id]/invite`
 *
 * Owner invites another user by email. Looks up the invitee's X25519 public
 * key, wraps the vault DEK under it (sealed box), then sends the invite.
 */

import { type JSX, useState } from "react";
import { useParams } from "next/navigation";

import { useAuth } from "../../../../../lib/auth/auth-context";
import { keyStore } from "../../../../../lib/auth/key-store";
import { wrapVaultKey } from "../../../../../lib/crypto/vault-key";
import {
  createInvite,
  lookupUser,
  VaultAlreadyMemberError,
  VaultUserNotFoundError,
} from "../../../../../lib/api/vault-sharing-client";

export default function InvitePage(): JSX.Element {
  const { accessToken } = useAuth();
  const params = useParams<{ id: string }>();
  const vaultId = params.id;

  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "loading" | "success">("idle");
  const [error, setError] = useState<string | null>(null);

  const vaultDek = keyStore.getBytes("vault_dek:" + vaultId);

  if (vaultDek === undefined) {
    return (
      <main className="mx-auto max-w-lg px-6 py-10">
        <p
          role="alert"
          className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
        >
          Vault DEK not loaded — go back to the vault.
        </p>
        <div className="mt-4">
          <a
            href={`/vaults/${encodeURIComponent(vaultId)}`}
            className="text-sm text-zinc-300 underline hover:text-white"
          >
            Back to vault
          </a>
        </div>
      </main>
    );
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    if (accessToken === null) return;
    setError(null);
    setStatus("loading");
    try {
      const { id: inviteeId, kxPublicKey } = await lookupUser(
        accessToken,
        email.trim(),
      );
      const wrapped = await wrapVaultKey(vaultDek!, kxPublicKey);
      await createInvite(accessToken, vaultId, inviteeId, wrapped);
      setStatus("success");
      setEmail("");
    } catch (err) {
      setStatus("idle");
      if (err instanceof VaultUserNotFoundError) {
        setError("No SimpleVault account found for that email.");
      } else if (err instanceof VaultAlreadyMemberError) {
        setError("This user is already a member or has a pending invite.");
      } else {
        setError(err instanceof Error ? err.message : "An unexpected error occurred.");
      }
    }
  }

  return (
    <main className="mx-auto max-w-lg px-6 py-10">
      <h1 className="mb-6 text-2xl font-semibold tracking-tight">Invite to Vault</h1>

      <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor="invite-email" className="text-sm font-medium text-zinc-300">
            Email address
          </label>
          <input
            id="invite-email"
            type="email"
            required
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
            }}
            placeholder="user@example.com"
            disabled={status === "loading"}
            className="rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 disabled:opacity-50"
          />
        </div>

        {error !== null && (
          <p
            role="alert"
            className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            {error}
          </p>
        )}

        {status === "success" && (
          <p
            role="status"
            className="rounded-md border border-green-500/40 bg-green-500/10 px-4 py-3 text-sm text-green-200"
          >
            Invite sent!
          </p>
        )}

        <button
          type="submit"
          disabled={status === "loading"}
          className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-50"
        >
          {status === "loading" ? "Sending…" : "Invite"}
        </button>
      </form>

      <div className="mt-6">
        <a
          href={`/vaults/${encodeURIComponent(vaultId)}`}
          className="text-sm text-zinc-400 hover:text-zinc-200"
        >
          ← Back to vault
        </a>
      </div>
    </main>
  );
}
