import sodium from "libsodium-wrappers-sumo";
import { ready } from "./argon2id.js";

/**
 * Ed25519 signing keypair generation for SimpleVault user signing keys.
 *
 * At signup the browser generates an Ed25519 keypair; the secret half is
 * wrapped under master_KEK (AAD = encodeAad(params, "sv:user-sign-sk:v1|"
 * + user_id_bytes)) and stored in `users.wrapped_user_signing_sk`. The
 * public half is currently NOT persisted (Phase 02 doesn't expose a
 * signed-record path); Phase 10 hash-chain audit-events will start using
 * it for per-user signed records.
 *
 * Naming: libsodium calls the secret half `privateKey`; we expose it as
 * `secretKey` for naming consistency with the rest of the SimpleVault
 * codebase (matches `users.wrapped_user_signing_sk` column name).
 *
 * Sizes per libsodium: pub = 32 B, sk = 64 B (Ed25519 packs the seed
 * AND the public key into the secret-key blob — this is fine for our
 * wrap-and-store use case; we wrap the full 64 B and unwrap intact).
 */

type SodiumSignSurface = {
  crypto_sign_keypair: () => { publicKey: Uint8Array; privateKey: Uint8Array };
};

function signSurface(): SodiumSignSurface {
  return sodium as unknown as SodiumSignSurface;
}

export type SigningKeyPair = {
  readonly publicKey: Uint8Array; // 32 B
  readonly secretKey: Uint8Array; // 64 B (libsodium Ed25519 layout)
};

/**
 * Generate a fresh Ed25519 signing keypair. Caller must `await ready()`
 * implicitly via this function. Used at signup to populate
 * `users.wrapped_user_signing_sk` (after wrapping the secretKey under
 * master_KEK).
 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  await ready();
  const kp = signSurface().crypto_sign_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}
