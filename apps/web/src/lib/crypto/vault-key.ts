import {
  ready,
  sealedBoxOpen,
  sealedBoxSeal,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

/**
 * Phase 07 — browser-only vault DEK wrap/unwrap helpers.
 *
 * Wraps a vault DEK (32 bytes) using X25519 sealed-box for a target
 * recipient. The underlying primitives (`sealedBoxSeal`, `sealedBoxOpen`)
 * live in `@simplevault/crypto/browser` (Phase 02). The sealed box is
 * 48 bytes: 32-byte ephemeral X25519 public key + 16-byte Poly1305 MAC.
 *
 * Callers store vault DEKs in keyStore under the key `"vault_dek:${vaultId}"`.
 * The personal vault uses `"master_dek"` directly (no change to Phase 04).
 */

/** Generate a fresh 32-byte vault DEK using libsodium's CSPRNG. */
export async function generateVaultDek(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(32);
}

/**
 * Seal vault_DEK under a recipient's X25519 public key.
 * Result is a 48-byte sealed box stored in `vault_memberships.wrapped_vault_key`.
 */
export async function wrapVaultKey(
  vaultDek: Uint8Array,
  recipientKxPk: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  return sealedBoxSeal(vaultDek, recipientKxPk);
}

/**
 * Open a sealed vault DEK using the recipient's X25519 keypair.
 * Throws `SealedBoxKeyLengthError` (or a libsodium error) if the box is
 * invalid — wrong key, tampered ciphertext, or wrong recipient.
 */
export async function unwrapVaultKey(
  sealed: Uint8Array,
  myKxPk: Uint8Array,
  myKxSk: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  return sealedBoxOpen(sealed, myKxPk, myKxSk);
}
