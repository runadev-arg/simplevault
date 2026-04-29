import sodium from "libsodium-wrappers-sumo";
import { ready } from "./argon2id.js";

/**
 * X25519 sealed-box (libsodium `crypto_box_seal` / `crypto_box_seal_open`).
 *
 * Sealed boxes are the SimpleVault primitive for "anonymous wrap to a known
 * recipient public key" — the per-member wrapping used in shared vaults
 * (Phase 07): each member's vault_DEK copy is sealed to their `users.user_pub_key`.
 *
 * SECURITY NOTES (LOAD-BEARING — read before changing):
 *
 *   1. Sealed-boxes do NOT authenticate the sender. Anyone holding the
 *      recipient public key can produce a valid sealed-box; the recipient
 *      can decrypt it but cannot tell who sent it. This is the desired
 *      property for invite/share flows — sender anonymity is acceptable
 *      because the wrapped object (e.g. a vault_DEK) is itself created
 *      by an authenticated server-side request whose audit trail names
 *      the inviter.
 *
 *   2. If a future feature ever needs sender-authenticated wraps (e.g.
 *      "this DEK was sealed by Alice, signed under her key"), DO NOT add
 *      a sender field to this module. Instead introduce a sibling module
 *      that uses `crypto_box_easy` (sender keypair + recipient pubkey,
 *      authenticated) — keep the two primitives type-distinct so callers
 *      pick deliberately.
 *
 *   3. Naming: libsodium calls the secret half `privateKey`; we expose it
 *      as `secretKey` everywhere for consistency with libsodium's CLI/docs
 *      ("sk") and our own `users.wrapped_user_kx_sk` column name.
 *
 * Wire shape (libsodium's): ciphertext bytes = ephemeral_pubkey(32B)
 *   || box_easy(plaintext, nonce=blake2b(epk||rpk), epk_sk, rpk).
 * We treat it as opaque bytes; on-disk storage is just the raw output.
 */

const PUBLICKEYBYTES = 32;
const SECRETKEYBYTES = 32;

// libsodium's standard `crypto_box_seal` / `crypto_box_seal_open` /
// `crypto_box_keypair` are present at runtime in libsodium-sumo but
// missing from @types/libsodium-wrappers-sumo@0.7.8 (which only ships
// the curve25519xchacha20poly1305 variants). We cast through a typed
// view to keep call-sites strict without disabling type-checking globally.
type SodiumBoxSurface = {
  crypto_box_keypair: () => { publicKey: Uint8Array; privateKey: Uint8Array };
  crypto_box_seal: (message: Uint8Array, publicKey: Uint8Array) => Uint8Array;
  crypto_box_seal_open: (
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ) => Uint8Array;
};

function box(): SodiumBoxSurface {
  return sodium as unknown as SodiumBoxSurface;
}

export type KxKeyPair = {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
};

export class SealedBoxKeyLengthError extends Error {
  constructor(field: "publicKey" | "secretKey", expected: number, actual: number) {
    super(`sealed-box: ${field} must be ${expected} bytes (got ${actual})`);
    this.name = "SealedBoxKeyLengthError";
  }
}

function assertPub(pk: Uint8Array): void {
  if (pk.length !== PUBLICKEYBYTES) {
    throw new SealedBoxKeyLengthError("publicKey", PUBLICKEYBYTES, pk.length);
  }
}
function assertSk(sk: Uint8Array): void {
  if (sk.length !== SECRETKEYBYTES) {
    throw new SealedBoxKeyLengthError("secretKey", SECRETKEYBYTES, sk.length);
  }
}

/**
 * Generate a fresh X25519 key-exchange keypair (32B public, 32B secret).
 *
 * Used at signup to populate `users.user_pub_key` (publicKey, sent to
 * server in the clear) and `users.wrapped_user_kx_sk` (secretKey, wrapped
 * under master_KEK before transit).
 */
export async function generateKxKeyPair(): Promise<KxKeyPair> {
  await ready();
  const kp = box().crypto_box_keypair();
  // libsodium names the secret half `privateKey`; expose it as `secretKey`
  // for naming consistency across the SimpleVault codebase.
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

/**
 * Anonymous-sender seal: produce a ciphertext only `recipientPub`'s holder
 * of the matching secretKey can open. Output length is
 * `plaintext.length + crypto_box_SEALBYTES` (= plaintext.length + 48).
 */
export async function sealedBoxSeal(
  plaintext: Uint8Array,
  recipientPub: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  assertPub(recipientPub);
  return box().crypto_box_seal(plaintext, recipientPub);
}

/**
 * Open a sealed-box. Throws on any tampering, wrong key, or truncation.
 * Caller must supply BOTH the recipient's public AND secret key (libsodium
 * recovers the ephemeral pubkey from the ciphertext but needs the recipient
 * pubkey to recompute the BLAKE2b nonce).
 */
export async function sealedBoxOpen(
  ciphertext: Uint8Array,
  recipientPub: Uint8Array,
  recipientSk: Uint8Array,
): Promise<Uint8Array> {
  await ready();
  assertPub(recipientPub);
  assertSk(recipientSk);
  return box().crypto_box_seal_open(ciphertext, recipientPub, recipientSk);
}
