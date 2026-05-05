import {
  buildVaultCredentialAad as buildVaultCredentialAadImpl,
  type VaultCredentialAadInput,
} from "@simplevault/crypto/browser";

import { AAD_LABEL_VAULT_CREDENTIAL } from "./aad-labels";

/**
 * Phase 04 Plan 04 — browser-only encrypt/decrypt wrappers around
 * `aead.encrypt` / `aead.decrypt` for vault credential blobs.
 *
 * The AAD is built by `buildVaultCredentialAad` from `@simplevault/crypto`
 * with the label INJECTED from `aad-labels.ts` (single source of truth;
 * FINDING-0026 closure relies on this). The nonce is 24 random bytes per
 * encrypt (REQ-CRYPTO no-reuse — XChaCha20-Poly1305 IETF).
 */

export type CredentialBlob = {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
};

/**
 * Convenience: build the per-credential AAD using the FROZEN label
 * imported from `aad-labels.ts`. Callers that already have the AAD bytes
 * (e.g. Plan 04-09 round-tripping `aadParamsJson` from the server) should
 * call `buildVaultCredentialAad` directly with the same label.
 */
export function buildVaultCredentialAad(
  input: VaultCredentialAadInput,
): Uint8Array {
  return buildVaultCredentialAadImpl(input, AAD_LABEL_VAULT_CREDENTIAL);
}

export function encryptCredential(
  _plaintextJson: string,
  _masterDek: Uint8Array,
  _aad: Uint8Array,
): Promise<CredentialBlob> {
  throw new Error("not impl");
}

export function decryptCredential(
  _blob: CredentialBlob,
  _masterDek: Uint8Array,
  _aad: Uint8Array,
): Promise<string> {
  throw new Error("not impl");
}
