import sodium from "libsodium-wrappers-sumo";

/**
 * Phase 04 Plan 04 — browser-only vault-credential AAD builder.
 *
 * The plaintext credential blob is wrapped under master_DEK with AAD =
 *   utf8(label) || sha256(lower(email)) || canonicalJson({credentialId, vaultId, version})
 *
 * Canonical JSON: keys sorted lexicographically (credentialId < vaultId
 * < version), no whitespace, UTF-8. Hand-rolled string template — does
 * NOT depend on `Object.keys` order semantics. If a fourth key is ever
 * added the v-suffix in the label MUST be bumped (data-migration event).
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
 *
 * `await ready()` (libsodium init) is the caller's responsibility for
 * top-level await ergonomics. `sodium.crypto_hash_sha256` requires it.
 */

export interface VaultCredentialAadInput {
  vaultId: string;
  credentialId: string;
  version: number;
  email: string;
}

export function canonicalCredentialAadJson(v: {
  vaultId: string;
  credentialId: string;
  version: number;
}): string {
  // Alphabetical key order: credentialId < vaultId < version. No whitespace.
  return (
    `{"credentialId":${JSON.stringify(v.credentialId)},` +
    `"vaultId":${JSON.stringify(v.vaultId)},` +
    `"version":${v.version}}`
  );
}

export function buildVaultCredentialAad(
  input: VaultCredentialAadInput,
  label: string,
): Uint8Array {
  // Defensive — libsodium must be ready for crypto_hash_sha256.
  // Callers that always `await ready()` first hit a no-op fast path.
  if (!sodium.crypto_hash_sha256) {
    throw new Error(
      "buildVaultCredentialAad: libsodium not ready — await ready() first",
    );
  }
  const labelBytes = sodium.from_string(label);
  const emailLower = input.email.trim().toLowerCase();
  const emailHash = sodium.crypto_hash_sha256(sodium.from_string(emailLower));
  const json = canonicalCredentialAadJson({
    vaultId: input.vaultId,
    credentialId: input.credentialId,
    version: input.version,
  });
  const jsonBytes = sodium.from_string(json);
  const out = new Uint8Array(
    labelBytes.length + emailHash.length + jsonBytes.length,
  );
  out.set(labelBytes, 0);
  out.set(emailHash, labelBytes.length);
  out.set(jsonBytes, labelBytes.length + emailHash.length);
  return out;
}

