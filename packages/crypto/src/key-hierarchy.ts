import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import {
  ARGON2_DEFAULT_PARAMS,
  type Argon2Params,
  deriveKey,
  ready,
} from "./argon2id.js";
import { decrypt, encrypt, type AeadCiphertext } from "./aead.js";
import { mnemonicToSeed } from "./bip39.js";

/**
 * SimpleVault key hierarchy (CRYPTO-STACK.md §3 + §8).
 *
 *   secret_key (128b shown once in Emergency Kit)
 *   master_password (user knowledge factor)
 *   email (deterministic per-account label)
 *   user_argon_salt (16B random, server-stored, per-user)
 *
 *      ┌─ HKDF-SHA256(ikm=secret_key, salt=lower(email),
 *      │              info="simplevault.v1.master_seed") ──→ master_seed (32B)
 *      │
 *      ├─ Argon2id(password, salt = master_seed XOR user_argon_salt, params)
 *      │   ──→ master_KEK (32B)  [never leaves device]
 *      │
 *      └─ XChaCha20-Poly1305(key=master_KEK, msg=master_DEK, AAD=encodeAad(params, user_id))
 *          ──→ wrapped_master_DEK  [server-stored]
 *
 *   BIP-39 mnemonic (24 words, shown once)
 *      ├─ HKDF-SHA256(ikm=mnemonicToSeed(m), salt=user_id,
 *      │              info="simplevault.v1.recovery_kek") ──→ recovery_KEK (32B)
 *      │
 *      └─ XChaCha20-Poly1305(key=recovery_KEK, msg=master_DEK, AAD=encodeAad(params, user_id))
 *          ──→ wrapped_master_DEK_recovery
 *
 * AAD wire format (LOAD-BEARING — Plan 07/08 server code MUST replicate
 * this byte-for-byte to verify wrapped blobs at signup time):
 *
 *   aad = version_byte                        (1 byte, currently 0x01)
 *      || memoryKiB_be32                      (4 bytes, big-endian uint32)
 *      || iterations_be32                     (4 bytes, big-endian uint32)
 *      || parallelism_be32                    (4 bytes, big-endian uint32)
 *      || context_id_bytes                    (variable; UUID-as-text or other)
 *
 * Total prefix = 13 bytes. Argon2 params are baked into AAD so a downgrade
 * (e.g. attacker rewrites users.argon_memory_kib in the DB to a weaker
 * value) breaks the AEAD tag on every unwrap attempt.
 *
 * HKDF info-strings (frozen for v1):
 *   "simplevault.v1.master_seed"
 *   "simplevault.v1.recovery_kek"
 *
 * Bumping AAD_VERSION or info-strings is a hard wire-format break — invent
 * new strings instead and migrate at next major.
 */

const HKDF_INFO_MASTER_SEED = "simplevault.v1.master_seed";
const HKDF_INFO_RECOVERY_KEK = "simplevault.v1.recovery_kek";

export const AAD_VERSION = 0x01;

const enc = new TextEncoder();

/**
 * Canonical AAD encoder. Emits 13 bytes of fixed prefix + `contextId` bytes.
 *
 * `contextId` is the binding identifier — typically the user_id UUID encoded
 * as UTF-8 text bytes for users.wrapped_master_dek, or a vault_id|item_id|v
 * concatenation for item-level encryptions.
 */
export function encodeAad(
  params: Argon2Params,
  contextId: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(1 + 12 + contextId.length);
  out[0] = AAD_VERSION;
  const view = new DataView(out.buffer, out.byteOffset + 1, 12);
  view.setUint32(0, params.memoryKiB, false);
  view.setUint32(4, params.iterations, false);
  view.setUint32(8, params.parallelism, false);
  out.set(contextId, 13);
  return out;
}

// --- master KEK -----------------------------------------------------------

export interface DeriveMasterKekInput {
  /** Plaintext master password (UTF-8). Browser-only — never sent to server. */
  readonly password: string;
  /** 16- or 32-byte secret_key (Emergency Kit). */
  readonly secretKey: Uint8Array;
  /** User's email (case-insensitivised here; serves as HKDF salt domain separator). */
  readonly email: string;
  /** 16-byte random per-user salt, stored in users.user_argon_salt. */
  readonly userArgonSalt: Uint8Array;
  /** Argon2id params (defaulted but recommended explicit, baked into AAD). */
  readonly argon2Params?: Argon2Params;
}

/**
 * Derive `master_KEK` per CRYPTO-STACK.md §3.
 *   1. master_seed = HKDF-SHA256(ikm=secret_key, salt=lower(email),
 *                                info="simplevault.v1.master_seed", L=32)
 *   2. argon_salt  = master_seed XOR user_argon_salt[16]   (16-byte salt)
 *   3. master_KEK  = Argon2id(password_utf8, argon_salt, params, 32)
 *
 * The XOR step ties the salt to BOTH the secret_key (via master_seed) and
 * the server-stored user_argon_salt — neither alone is enough to derive
 * the right Argon2 salt, defending against half-stolen secrets.
 */
export async function deriveMasterKek(
  input: DeriveMasterKekInput,
): Promise<Uint8Array> {
  await ready();
  const params = input.argon2Params ?? ARGON2_DEFAULT_PARAMS;

  if (input.userArgonSalt.length !== 16) {
    throw new Error(
      `deriveMasterKek: userArgonSalt must be 16 bytes (got ${input.userArgonSalt.length})`,
    );
  }

  const masterSeed = hkdf(
    sha256,
    input.secretKey,
    enc.encode(input.email.toLowerCase()),
    HKDF_INFO_MASTER_SEED,
    32,
  );

  // XOR the first 16 bytes of master_seed with user_argon_salt to form
  // the 16-byte Argon2id salt. (Argon2id's libsodium binding requires
  // salt >= 16 bytes; we use exactly 16.)
  const argonSalt = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    argonSalt[i] = (masterSeed[i] ?? 0) ^ (input.userArgonSalt[i] ?? 0);
  }

  return deriveKey(enc.encode(input.password), argonSalt, params, 32);
}

// --- recovery KEK ---------------------------------------------------------

export interface DeriveRecoveryKekInput {
  /** BIP-39 24-word mnemonic. Browser-only — never sent to server. */
  readonly mnemonic: string;
  /** Stable per-account identifier (UUID-as-text bytes is fine). */
  readonly userId: Uint8Array;
}

/**
 * Derive `recovery_KEK` per CRYPTO-STACK.md §8.
 *
 *   recovery_seed = mnemonicToSeed(mnemonic)         (64 bytes, BIP-39)
 *   recovery_KEK  = HKDF-SHA256(ikm=recovery_seed,
 *                               salt=userId,
 *                               info="simplevault.v1.recovery_kek",
 *                               L=32)
 *
 * No Argon2 stretching: the BIP-39 seed already carries 256 bits of entropy,
 * so HKDF (deterministic, fast) is sufficient and lets recovery succeed in
 * <100ms vs the 750ms Argon2 path.
 */
export async function deriveRecoveryKek(
  input: DeriveRecoveryKekInput,
): Promise<Uint8Array> {
  const seed = await mnemonicToSeed(input.mnemonic);
  return hkdf(sha256, seed, input.userId, HKDF_INFO_RECOVERY_KEK, 32);
}

// --- wrap / unwrap --------------------------------------------------------

/**
 * Serialised wrapped key — `nonce || ciphertext` is the on-the-wire shape
 * that the API/DB layer should pack into bytea columns. The struct form
 * here makes the components explicit for callers that want them separately.
 */
export type WrappedKeyBlob = AeadCiphertext;

/**
 * Wrap a 32-byte key under a 32-byte wrapping key (XChaCha20-Poly1305 with
 * mandatory AAD). Use `encodeAad(params, contextId)` to produce the AAD.
 */
export async function wrapKey(
  plaintextKey: Uint8Array,
  wrappingKey: Uint8Array,
  aad: Uint8Array,
): Promise<WrappedKeyBlob> {
  return encrypt(plaintextKey, wrappingKey, aad);
}

/**
 * Inverse of `wrapKey`. Throws on tag mismatch (mutated AAD, mutated
 * ciphertext, wrong key, or any context downgrade).
 */
export async function unwrapKey(
  wrapped: WrappedKeyBlob,
  wrappingKey: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return decrypt(wrapped, wrappingKey, aad);
}
