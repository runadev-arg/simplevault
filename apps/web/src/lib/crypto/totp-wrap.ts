import {
  encrypt,
  decrypt,
  encodeAad,
  type Argon2Params,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

import { AAD_LABEL_TOTP } from "./aad-labels";

/**
 * Phase 03 Plan 10 — TOTP-secret wrap/unwrap helpers.
 *
 * The TOTP secret (RFC 6238, 20 bytes) is wrapped under `master_DEK` with
 * AAD `encodeAad(argon2Params, "sv:user-totp:v1|" || SHA256(lower(email)))`.
 * The on-the-wire shape matches the existing `wrappedMasterDek` etc.
 * pattern — `nonce || ciphertext` packed as a single base64 string. The
 * AAD bytes themselves are also base64-encoded and round-tripped through
 * the server (defence in depth: any AAD substitution surfaces as a tag
 * mismatch on decrypt).
 *
 * SECURITY (Plan 03 Key Link 3): the server NEVER sees the plaintext
 * secret. This module runs ONLY in the browser. A `grep` for it in
 * `apps/api/src/` MUST return zero hits.
 */

const enc = new TextEncoder();

function emailHash(email: string): Uint8Array {
  return sodium.crypto_hash_sha256(enc.encode(email.toLowerCase()));
}

/**
 * Compute the AAD bytes used when wrapping/unwrapping a TOTP secret.
 * Pure function of the user's email + the system-wide argon2Params;
 * the client recomputes this at decrypt time. The server also stores
 * the bytes (round-trip), so AAD substitution by an active attacker
 * surfaces as a tag mismatch.
 */
export function computeTotpAad(
  email: string,
  argon2Params: Argon2Params,
): Uint8Array {
  const label = enc.encode(AAD_LABEL_TOTP);
  const h = emailHash(email);
  const ctx = new Uint8Array(label.length + h.length);
  ctx.set(label, 0);
  ctx.set(h, label.length);
  return encodeAad(argon2Params, ctx);
}

/**
 * Wrap a 20-byte TOTP secret under master_DEK. Returns the on-the-wire
 * `wrappedSecret` (base64 of `nonce || ciphertext`) AND the AAD bytes
 * used (base64) for round-tripping through the server.
 */
export async function wrapTotpSecret(
  secret: Uint8Array,
  masterDek: Uint8Array,
  email: string,
  argon2Params: Argon2Params,
): Promise<{ wrappedSecret: string; encryptedSecretAad: string }> {
  const aad = computeTotpAad(email, argon2Params);
  const blob = await encrypt(secret, masterDek, aad);
  const packed = new Uint8Array(blob.nonce.length + blob.ciphertext.length);
  packed.set(blob.nonce, 0);
  packed.set(blob.ciphertext, blob.nonce.length);
  return {
    wrappedSecret: sodium.to_base64(packed, sodium.base64_variants.ORIGINAL),
    encryptedSecretAad: sodium.to_base64(aad, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * Inverse of `wrapTotpSecret`. Throws on tag mismatch (wrong key, wrong
 * AAD, mutated blob) — caller treats that as "wrong credentials" and
 * surfaces a uniform error.
 */
export async function unwrapTotpSecret(
  wrappedSecretB64: string,
  encryptedSecretAadB64: string,
  masterDek: Uint8Array,
): Promise<Uint8Array> {
  const packed = sodium.from_base64(wrappedSecretB64, sodium.base64_variants.ORIGINAL);
  if (packed.length < 24 + 16) {
    throw new Error("totp-wrap: wrapped blob too short");
  }
  const nonce = packed.slice(0, 24);
  const ciphertext = packed.slice(24);
  const aad = sodium.from_base64(encryptedSecretAadB64, sodium.base64_variants.ORIGINAL);
  return decrypt({ nonce, ciphertext }, masterDek, aad);
}
