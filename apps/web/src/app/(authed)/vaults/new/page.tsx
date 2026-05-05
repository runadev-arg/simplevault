"use client";

/**
 * Phase 07 / Plan 07-04 — `/vaults/new` create shared vault page.
 *
 * Flow:
 *   1. User enters a vault name (required, max 100 chars).
 *   2. On submit:
 *      a. await ready() — ensure libsodium is initialised.
 *      b. Generate a fresh 32-byte vault DEK.
 *      c. Derive the caller's X25519 public key from their stored kx_sk.
 *         (kx_pk is not stored separately; derive it via crypto_scalarmult_base.)
 *      d. Wrap the vault DEK under the caller's own X25519 public key
 *         (sealed box) so the owner can decrypt their own vault.
 *      e. POST /vaults/group → receive {id}.
 *      f. Store the unwrapped DEK in keyStore under "vault_dek:<id>".
 *      g. Navigate to /vaults/<id>.
 */

import { ready } from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";
import { useRouter } from "next/navigation";
import type { JSX, SyntheticEvent } from "react";
import { useState } from "react";

import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";
import {
  generateVaultDek,
  wrapVaultKey,
} from "../../../../lib/crypto/vault-key";
import { createGroupVault } from "../../../../lib/api/vault-sharing-client";

export default function NewVaultPage(): JSX.Element {
  const { accessToken } = useAuth();
  const router = useRouter();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  async function handleSubmit(e: SyntheticEvent): Promise<void> {
    e.preventDefault();
    if (accessToken === null || busy) return;
    const trimmedName = name.trim();
    if (trimmedName === "") return;

    setBusy(true);
    setSaveError(null);

    try {
      await ready();

      // Generate a fresh vault DEK.
      const dek = await generateVaultDek();

      // Derive the caller's X25519 public key from the stored kx_sk.
      // kx_pk is not stored separately in keyStore — derive it inline.
      const kxSk = keyStore.getBytes("kx_sk");
      if (kxSk === undefined) {
        setSaveError("Key material not available. Sign in again.");
        setBusy(false);
        return;
      }
      const myKxPk = sodium.crypto_scalarmult_base(kxSk);

      // Wrap the vault DEK under the caller's own public key so the owner
      // can unwrap and use the vault immediately after creation.
      const wrapped = await wrapVaultKey(dek, myKxPk);

      // Create the shared vault on the server.
      const { id } = await createGroupVault(accessToken, trimmedName, wrapped);

      // Stash the unwrapped DEK in the in-memory keyStore for immediate use.
      keyStore.set(`vault_dek:${id}`, dek);

      router.replace(`/vaults/${id}`);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to create vault");
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col justify-center gap-6 px-6 py-10">
      <h1 className="text-2xl font-semibold tracking-tight">
        New shared vault
      </h1>

      <form
        onSubmit={(e) => {
          void handleSubmit(e);
        }}
        className="flex flex-col gap-4"
      >
        <div className="flex flex-col gap-1">
          <label
            htmlFor="vault-name"
            className="text-sm font-medium text-zinc-300"
          >
            Vault name
          </label>
          <input
            id="vault-name"
            type="text"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
            }}
            maxLength={100}
            required
            disabled={busy}
            placeholder="e.g. Team credentials"
            className="rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 disabled:opacity-50"
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

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={busy || name.trim() === ""}
            className="rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-white disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create vault"}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              router.replace("/vaults");
            }}
            className="rounded-md border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"
          >
            Cancel
          </button>
        </div>
      </form>
    </main>
  );
}
