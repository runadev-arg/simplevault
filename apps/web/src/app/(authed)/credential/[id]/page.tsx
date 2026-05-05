"use client";

/**
 * Phase 04 / Plan 04-10 (T3) — /credential/[id].
 *
 * Edit flow:
 *   1. fetch /vault/personal → vaultId (or use ?vaultId= query param for shared vaults);
 *      fetch /credentials/:id → blob+version
 *   2. fetch /me → email (sha256(email) bound into AAD)
 *   3. decrypt with AAD = label || sha256(email) || canonicalJson(
 *      {credentialId,vaultId,version: blob.version})
 *   4. on save: bump version (blob.version + 1), rotate password-history
 *      (last 10) IN-BLOB if password changed, encrypt, PATCH (CAS witness
 *      = baseline.version)
 *   5. on 409 VersionConflictError → re-fetch + re-decrypt + prompt
 *      "Apply your edits on top of the latest version?" — recursive retry
 *      uses the FRESH baseline (server-current.version + 1)
 *
 * History rotation (REQ-VAULT-006 / INDEX truth 12):
 *   if next.password !== baseline.password:
 *     next.history = [{password: baseline.password, changedAt: now()},
 *                     ...baseline.history].slice(0, 10)
 *   else:
 *     next.history = baseline.history (preserved verbatim)
 *
 * Old plaintext NEVER exits the encrypted blob — the server only ever sees
 * ciphertext. Cap = 10; oldest evicted.
 *
 * Phase 07 — supports shared vaults via ?vaultId= query param.
 * resolveVaultDek() picks the shared vault DEK when available, falls back
 * to master_dek for personal vaults.
 */

import {
  buildVaultCredentialAad as buildAadImpl,
  canonicalCredentialAadJson,
  ready,
} from "@simplevault/crypto/browser";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import type { JSX } from "react";

import { CredentialEditor } from "../../../../components/credential-editor";
import { me as apiMe } from "../../../../lib/api/auth-client";
import {
  deleteCredential,
  getCredential,
  listVaultPersonal,
  updateCredential,
} from "../../../../lib/api/credentials-client";
import { VersionConflictError } from "../../../../lib/api/errors";
import { useAuth } from "../../../../lib/auth/auth-context";
import { AAD_LABEL_VAULT_CREDENTIAL } from "../../../../lib/crypto/aad-labels";
import {
  decryptCredential,
  encryptCredential,
} from "../../../../lib/crypto/credential-cipher";
import {
  DecryptedCredentialSchema,
  type DecryptedCredential,
} from "../../../../lib/vault/credential-shape";
import { resolveVaultDek } from "../../../../lib/vault/resolve-vault-dek";

interface Baseline {
  vaultId: string;
  email: string;
  version: number;
  decrypted: DecryptedCredential;
}

function buildAad(
  vaultId: string,
  credentialId: string,
  version: number,
  email: string,
): Uint8Array {
  return buildAadImpl(
    { vaultId, credentialId, version, email },
    AAD_LABEL_VAULT_CREDENTIAL,
  );
}

function EditCredentialPageInner(): JSX.Element {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const id = params.id;
  const searchParams = useSearchParams();
  const vaultIdParam = searchParams.get("vaultId") ?? undefined;
  const { accessToken } = useAuth();
  const [baseline, setBaseline] = useState<Baseline | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  useEffect(() => {
    if (accessToken === null || !id) return;
    let cancelled = false;
    void (async (): Promise<void> => {
      try {
        await ready();
        const masterDek = resolveVaultDek(vaultIdParam);
        if (masterDek === undefined) {
          throw new Error("Vault is locked. Sign in again.");
        }
        if (vaultIdParam !== undefined) {
          // Shared vault — skip listVaultPersonal, use the provided vaultId
          const [who, blob] = await Promise.all([
            apiMe(accessToken),
            getCredential(accessToken, id),
          ]);
          // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
          if (cancelled) return;
          const aad = buildAad(vaultIdParam, id, blob.version, who.email);
          const json = await decryptCredential(
            { ciphertext: blob.ciphertext, nonce: blob.nonce },
            masterDek,
            aad,
          );
          const decrypted = DecryptedCredentialSchema.parse(JSON.parse(json));
          setBaseline({
            vaultId: vaultIdParam,
            email: who.email,
            version: blob.version,
            decrypted,
          });
        } else {
          const [vault, who, blob] = await Promise.all([
            listVaultPersonal(accessToken),
            apiMe(accessToken),
            getCredential(accessToken, id),
          ]);
          // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
          if (cancelled) return;
          const aad = buildAad(vault.vaultId, id, blob.version, who.email);
          const json = await decryptCredential(
            { ciphertext: blob.ciphertext, nonce: blob.nonce },
            masterDek,
            aad,
          );
          const decrypted = DecryptedCredentialSchema.parse(JSON.parse(json));
          setBaseline({
            vaultId: vault.vaultId,
            email: who.email,
            version: blob.version,
            decrypted,
          });
        }
      } catch (e) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (cancelled) return;
        if (e instanceof Error && e.message.includes("history")) {
          setBootError(
            "Credential history corrupted; contact admin.",
          );
        } else {
          setBootError(
            e instanceof Error ? e.message : "Failed to load credential",
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken, id, vaultIdParam]);

  const saveWithBaseline = async (
    base: Baseline,
    next: DecryptedCredential,
  ): Promise<void> => {
    if (accessToken === null) return;
    const masterDek = resolveVaultDek(vaultIdParam);
    if (masterDek === undefined) {
      setSaveError("Vault is locked. Sign in again.");
      return;
    }
    // History rotation — IN-BLOB; old plaintext never leaves the envelope.
    let nextHistory = base.decrypted.history;
    if (next.password !== base.decrypted.password) {
      nextHistory = [
        {
          password: base.decrypted.password,
          changedAt: new Date().toISOString(),
        },
        ...base.decrypted.history,
      ].slice(0, 10);
    }
    const merged: DecryptedCredential = { ...next, history: nextHistory };
    // Re-validate (also caps history at 10 via the schema).
    const validated = DecryptedCredentialSchema.parse(merged);

    const newVersion = base.version + 1;
    const aad = buildAad(base.vaultId, id, newVersion, base.email);
    const aadParamsJson = canonicalCredentialAadJson({
      vaultId: base.vaultId,
      credentialId: id,
      version: newVersion,
    });
    const blob = await encryptCredential(
      JSON.stringify(validated),
      masterDek,
      aad,
    );
    try {
      await updateCredential(accessToken, id, {
        ciphertext: blob.ciphertext,
        nonce: blob.nonce,
        aadParamsJson,
        version: base.version, // CAS witness — caller's known-current.
      });
      // Optimistic local baseline bump (in case the user keeps editing).
      setBaseline({
        ...base,
        version: newVersion,
        decrypted: validated,
      });
      if (vaultIdParam !== undefined) {
        router.replace("/vaults/" + vaultIdParam);
      } else {
        router.replace("/vault");
      }
    } catch (err) {
      if (err instanceof VersionConflictError) {
        // Re-fetch + decrypt the FRESH server state.
        const fresh = await getCredential(accessToken, id);
        const freshAad = buildAad(base.vaultId, id, fresh.version, base.email);
        const freshJson = await decryptCredential(
          { ciphertext: fresh.ciphertext, nonce: fresh.nonce },
          masterDek,
          freshAad,
        );
        const freshDecrypted = DecryptedCredentialSchema.parse(
          JSON.parse(freshJson),
        );
        const freshBaseline: Baseline = {
          ...base,
          version: fresh.version,
          decrypted: freshDecrypted,
        };
        setBaseline(freshBaseline);
        // Surface a typed retry-or-cancel UX (NOT a silent failure).
        const proceed = window.confirm(
          "This credential was updated elsewhere. Apply your edits on top of the latest version?",
        );
        if (!proceed) {
          setSaveError(
            "Save cancelled — you are now editing the latest version. Re-apply your changes and save again.",
          );
          return;
        }
        // Recursive retry uses the fresh baseline (fresh.version + 1).
        await saveWithBaseline(freshBaseline, next);
        return;
      }
      throw err;
    }
  };

  const onSave = async (next: DecryptedCredential): Promise<void> => {
    if (baseline === null) return;
    setSaveError(null);
    await saveWithBaseline(baseline, next);
  };

  const onDelete = async (): Promise<void> => {
    if (accessToken === null) return;
    const ok = window.confirm(
      "Delete this credential? This cannot be undone.",
    );
    if (!ok) return;
    await deleteCredential(accessToken, id);
    if (vaultIdParam !== undefined) {
      router.replace("/vaults/" + vaultIdParam);
    } else {
      router.replace("/vault");
    }
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
  if (baseline === null) {
    return (
      <main className="mx-auto max-w-2xl px-6 py-10">
        <p className="text-zinc-400">Loading…</p>
      </main>
    );
  }

  return (
    <CredentialEditor
      mode="edit"
      initial={baseline.decrypted}
      onSave={onSave}
      onDelete={onDelete}
      onCancel={() => {
        if (vaultIdParam !== undefined) {
          router.replace("/vaults/" + vaultIdParam);
        } else {
          router.replace("/vault");
        }
      }}
      error={saveError}
    />
  );
}

export default function EditCredentialPage(): JSX.Element {
  // Suspense boundary required by Next.js App Router for `useSearchParams`.
  return (
    <Suspense fallback={<main className="mx-auto max-w-2xl px-6 py-10"><p className="text-zinc-400">Loading…</p></main>}>
      <EditCredentialPageInner />
    </Suspense>
  );
}
