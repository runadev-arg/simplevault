import {
  buildVaultCredentialAad as buildVaultCredentialAadImpl,
  encrypt as aeadEncrypt,
  decrypt as aeadDecrypt,
  ready,
  type VaultCredentialAadInput,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

import { AAD_LABEL_VAULT_CREDENTIAL } from "./aad-labels";

/**
 * Phase 04 Plan 04 — browser-only encrypt/decrypt wrappers around
 * `aead.encrypt` / `aead.decrypt` for vault credential blobs.
 *
 * The AAD is built by `buildVaultCredentialAad` from `@simplevault/crypto`
 * with the label INJECTED from `aad-labels.ts` (single source of truth;
 * FINDING-0026 closure relies on this). The nonce is 24 random bytes per
 * encrypt (REQ-CRYPTO no-reuse — XChaCha20-Poly1305 IETF, generated
 * inside `aead.encrypt`).
 */

export interface CredentialBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

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

/**
 * Encrypt a credential plaintext (canonical JSON) under master_DEK with
 * the supplied AAD. The 24-byte nonce is generated inside `aead.encrypt`
 * (libsodium randombytes_buf), guaranteeing no reuse.
 */
export async function encryptCredential(
  plaintextJson: string,
  masterDek: Uint8Array,
  aad: Uint8Array,
): Promise<CredentialBlob> {
  await ready();
  const pt = sodium.from_string(plaintextJson);
  const blob = await aeadEncrypt(pt, masterDek, aad);
  return { ciphertext: blob.ciphertext, nonce: blob.nonce };
}

/**
 * Decrypt a credential blob. Throws on tag mismatch (mutated ciphertext,
 * wrong AAD, wrong key, mutated nonce). Returns the original UTF-8 JSON.
 */
export async function decryptCredential(
  blob: CredentialBlob,
  masterDek: Uint8Array,
  aad: Uint8Array,
): Promise<string> {
  await ready();
  const pt = await aeadDecrypt(
    { ciphertext: blob.ciphertext, nonce: blob.nonce },
    masterDek,
    aad,
  );
  return sodium.to_string(pt);
}
