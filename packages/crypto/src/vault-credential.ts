/**
 * Phase 04 Plan 04 — browser-only vault-credential AAD builder.
 *
 * The plaintext credential blob is wrapped under master_DEK with AAD =
 *   utf8(label) || sha256(lower(email)) || canonicalJson({credentialId, vaultId, version})
 *
 * The label is INJECTED (not hard-coded here) because the canonical
 * source of truth lives in `apps/web/src/lib/crypto/aad-labels.ts` and
 * `@simplevault/crypto` cannot import from `apps/web`. The web caller
 * passes `AAD_LABEL_VAULT_CREDENTIAL`. The aad-parity test (apps/web)
 * enforces that the literal is imported, never re-declared.
 *
 * Browser-only: NOT re-exported from `node.ts`. The server has no
 * business deriving credential AAD — it stores the canonical-JSON
 * portion verbatim and ships it back at decrypt time.
 */

export interface VaultCredentialAadInput {
  vaultId: string;
  credentialId: string;
  version: number;
  email: string;
}

export function canonicalCredentialAadJson(_v: {
  vaultId: string;
  credentialId: string;
  version: number;
}): string {
  throw new Error("not impl");
}

export function buildVaultCredentialAad(
  _input: VaultCredentialAadInput,
  _label: string,
): Uint8Array {
  throw new Error("not impl");
}
