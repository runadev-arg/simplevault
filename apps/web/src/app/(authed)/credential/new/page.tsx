"use client";

/**
 * Phase 04 / Plan 04-10 (T2) — /credential/new.
 *
 * Create flow:
 *   1. fetch /vault/personal → vaultId
 *   2. fetch /me → email (sha256(email) is bound into AAD)
 *   3. client generates a UUIDv4 LOCALLY (crypto.randomUUID) — see
 *      Plan 04-10 SUMMARY: "client-chosen UUID closes the AAD-self-
 *      consistency gap on POST". Plan 04-02 already accepts an optional
 *      `credentialId` on the create DTO.
 *   4. encrypt(JSON, master_DEK, AAD = label || sha256(email) ||
 *      canonicalJson({credentialId, vaultId, version: 1}))
 *   5. POST → server stores ciphertext + nonce + the canonical aadParamsJson
 *   6. router.replace("/vault")
 *
 * Master DEK + email + access token come from the in-memory stores
 * (keyStore + accessTokenStore). The /vault list page (Plan 04-09 sibling)
 * is the natural post-create destination.
 */

import {
  canonicalCredentialAadJson,
  ready,
} from "@simplevault/crypto/browser";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { JSX } from "react";

import { CredentialEditor } from "../../../../components/credential-editor";
import { me as apiMe } from "../../../../lib/api/auth-client";
import {
  createCredential,
  listVaultPersonal,
} from "../../../../lib/api/credentials-client";
import { useAuth } from "../../../../lib/auth/auth-context";
import { keyStore } from "../../../../lib/auth/key-store";
import {
  buildVaultCredentialAad,
  encryptCredential,
} from "../../../../lib/crypto/credential-cipher";
import {
  DecryptedCredentialSchema,
  type DecryptedCredential,
} from "../../../../lib/vault/credential-shape";

export default function NewCredentialPage(): JSX.Element {
  const router = useRouter();
  const { accessToken } = useAuth();
  const [bootError, setBootError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [ctx, setCtx] = useState<{ vaultId: string; email: string } | null>(
    null,
  );

  useEffect(() => {
    if (accessToken === null) return;
    let cancelled = false;
    void (async () => {
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

  const onSave = async (raw: DecryptedCredential): Promise<void> => {
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
    // Validate + apply Zod defaults before encrypting.
    const decrypted = DecryptedCredentialSchema.parse(raw);
    // Client-chosen UUID — keeps AAD self-consistent in a single roundtrip.
    const credentialId = crypto.randomUUID();
    const version = 1;
    const aad = buildVaultCredentialAad({
      vaultId: ctx.vaultId,
      credentialId,
      version,
      email: ctx.email,
    });
    const aadParamsJson = canonicalCredentialAadJson({
      vaultId: ctx.vaultId,
      credentialId,
      version,
    });
    const blob = await encryptCredential(
      JSON.stringify(decrypted),
      masterDek,
      aad,
    );
    await createCredential(accessToken, {
      vaultId: ctx.vaultId,
      credentialId,
      ciphertext: blob.ciphertext,
      nonce: blob.nonce,
      aadParamsJson,
    });
    router.replace("/vault");
  };

  if (bootError) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-10">
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
      <main className="mx-auto max-w-2xl px-6 py-10">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  return (
    <CredentialEditor
      mode="new"
      onSave={onSave}
      onCancel={() => {
        router.replace("/vault");
      }}
      error={saveError}
    />
  );
}
