import sodium from "libsodium-wrappers-sumo";
import { ready } from "./argon2id.js";

/**
 * Output of `encrypt`. Stored alongside the AAD on the server side.
 *
 * Note: AAD is NOT carried in the blob — callers MUST re-supply matching
 * AAD on decrypt. See REQ-CRYPTO §pitfalls: AAD must bind context (vault_id,
 * item_id, version, kdf params bytes) so cross-context substitution and
 * KDF-param downgrade both fail with a tag mismatch.
 */
export type AeadCiphertext = {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
};

const KEY_BYTES = 32;
const NONCE_BYTES = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

export class AeadKeyLengthError extends Error {
  constructor(actual: number) {
    super(`aead: key must be exactly ${KEY_BYTES} bytes (got ${actual})`);
    this.name = "AeadKeyLengthError";
  }
}

function assertKeyLen(key: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new AeadKeyLengthError(key.length);
  }
}

/**
 * Encrypt with XChaCha20-Poly1305 IETF.
 * - 24-byte random nonce per call (collision-safe out to ~2^96).
 * - AAD is mandatory in the type. Pass `new Uint8Array(0)` for "no AAD" — explicit.
 */
export async function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array,
): Promise<AeadCiphertext> {
  await ready();
  assertKeyLen(key);
  const nonce = sodium.randombytes_buf(NONCE_BYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key,
  );
  return { ciphertext, nonce };
}

/**
 * Decrypt with XChaCha20-Poly1305 IETF. Throws on tag mismatch (any of:
 * mutated ciphertext, mutated AAD, wrong key, mutated nonce).
 */
export async function decrypt(
  blob: AeadCiphertext,
  key: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  assertKeyLen(key);
  // libsodium throws on tag-mismatch; we let it propagate.
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    blob.ciphertext,
    aad,
    blob.nonce,
    key,
  );
}
