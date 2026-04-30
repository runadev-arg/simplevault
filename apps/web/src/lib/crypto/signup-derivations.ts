import {
  ready,
  deriveKey,
  deriveMasterKek,
  deriveRecoveryKek,
  wrapKey,
  encodeAad,
  generateKxKeyPair,
  generateSigningKeyPair,
  computeRecoveryLookupHash,
  type Argon2Params,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

import type { SignupEnvelope } from "../api/auth-client";

/**
 * Build the POST /auth/signup request envelope (the "frozen" 10-field
 * shape from 02-07 SUMMARY).
 *
 * AAD CONTEXT-ID DESIGN (LOAD-BEARING — read before changing):
 *
 *   At signup time the client does NOT know the user_id (the server
 *   assigns it inside the atomic transaction). But every wrapped key in
 *   `users.wrapped_master_dek` / `users.wrapped_master_dek_recovery` /
 *   `users.wrapped_user_signing_sk` / `users.wrapped_user_kx_sk` MUST
 *   bind a stable per-user identifier into AAD so cross-user blob
 *   substitution attacks fail with a tag mismatch on unwrap.
 *
 *   We bind to `SHA256(email_lowercased)` (32 B):
 *     - email is canonicalised by the server (lower-cased on insert
 *       both at invite-create and signup) so the same input is reachable
 *       at every login — the client just SHA-256s the email it has.
 *     - 32 fixed bytes keeps AAD compact + leaks no plaintext email into
 *       AAD (AAD is authenticated but NOT encrypted, so a plain-email
 *       binder would expose the email in the wrapped blob's AAD bytes
 *       to anyone observing the storage layer).
 *     - email rebind/rotate (Phase 03+) will require a key-rewrap event
 *       — same contract as a rotated user_id would imply. Documented for
 *       Phase 04+ to honour.
 *
 *   Per-blob AAD label prefixes (from CRYPTO-STACK.md / 02-04 hand-off):
 *     - master_dek           : "sv:user-master:v1|"     + emailHash
 *     - master_dek_recovery  : "sv:user-recovery:v1|"   + emailHash
 *     - user_signing_sk      : "sv:user-sign-sk:v1|"    + emailHash
 *     - user_kx_sk           : "sv:user-kx-sk:v1|"      + emailHash
 *
 *   recovery_KEK derivation also takes `userId` as HKDF salt; we re-use
 *   the same emailHash for that role (consistent per-user binder across
 *   the hierarchy).
 *
 * SECRET LIFECYCLE:
 *   master_KEK / master_DEK / recovery_KEK / sign_sk / kx_sk are all
 *   created inside this function and returned in the envelope wrapped.
 *   The caller (SubmittingStep) zeros the unwrapped halves immediately
 *   after envelope construction via keyStore.wipe().
 */

const enc = new TextEncoder();

function emailHash(email: string): Uint8Array {
  // SHA256(lower(email)). Pure libsodium (no @noble import here).
  return sodium.crypto_hash_sha256(enc.encode(email.toLowerCase()));
}

function aadFor(label: string, params: Argon2Params, h: Uint8Array): Uint8Array {
  const prefix = enc.encode(label);
  const ctx = new Uint8Array(prefix.length + h.length);
  ctx.set(prefix, 0);
  ctx.set(h, prefix.length);
  return encodeAad(params, ctx);
}

function b64(b: Uint8Array): string {
  return sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
}

/**
 * Pack `nonce || ciphertext` into a single bytea-shaped blob and base64.
 * The server's signup DTO accepts a single base64-decoded byte string per
 * wrapped field; the on-disk shape (per 02-05 schema) is `nonce || ct`.
 */
function packWrapped(blob: { nonce: Uint8Array; ciphertext: Uint8Array }): string {
  const out = new Uint8Array(blob.nonce.length + blob.ciphertext.length);
  out.set(blob.nonce, 0);
  out.set(blob.ciphertext, blob.nonce.length);
  return b64(out);
}

export interface BuildEnvelopeInput {
  inviteId: string;
  email: string;
  password: string;
  secretKey: Uint8Array; // 16 B
  mnemonic: string;
  argon2Params: Argon2Params;
  /** base64-encoded 16-byte server-side argon salt (returned at /invite/redeem). */
  serverArgonSaltB64: string;
}

export interface DerivedSecrets {
  masterKek: Uint8Array;
  masterDek: Uint8Array;
  recoveryKek: Uint8Array;
  signSk: Uint8Array;
  kxSk: Uint8Array;
}

export interface BuildEnvelopeResult {
  envelope: SignupEnvelope;
  /** unwrapped key material — caller MUST zero these via keyStore.wipe() ASAP. */
  derived: DerivedSecrets;
}

export async function buildSignupEnvelope(
  input: BuildEnvelopeInput,
): Promise<BuildEnvelopeResult> {
  await ready();

  const h = emailHash(input.email);

  // 1. user_argon_salt: 16B random
  const userArgonSalt = sodium.randombytes_buf(16);

  // 2. master_KEK
  const masterKek = await deriveMasterKek({
    password: input.password,
    secretKey: input.secretKey,
    email: input.email,
    userArgonSalt,
    argon2Params: input.argon2Params,
  });

  // 3. master_DEK (fresh 32 B)
  const masterDek = sodium.randombytes_buf(32);

  // 4. Keypairs
  const sign = await generateSigningKeyPair(); // Ed25519 (32 + 64)
  const kx = await generateKxKeyPair(); // X25519 (32 + 32)

  // 5. recovery_KEK — uses emailHash as the per-user binder for HKDF salt.
  const recoveryKek = await deriveRecoveryKek({
    mnemonic: input.mnemonic,
    userId: h,
  });

  // 6. wrap everything (XChaCha20-Poly1305 with AAD bound to a per-blob
  //    label + emailHash + argon2 params).
  const wrappedMasterDek = await wrapKey(
    masterDek,
    masterKek,
    aadFor("sv:user-master:v1|", input.argon2Params, h),
  );
  const wrappedMasterDekRecovery = await wrapKey(
    masterDek,
    recoveryKek,
    aadFor("sv:user-recovery:v1|", input.argon2Params, h),
  );
  const wrappedUserSigningSk = await wrapKey(
    sign.secretKey,
    masterKek,
    aadFor("sv:user-sign-sk:v1|", input.argon2Params, h),
  );
  const wrappedUserKxSk = await wrapKey(
    kx.secretKey,
    masterKek,
    aadFor("sv:user-kx-sk:v1|", input.argon2Params, h),
  );

  // 7. argon2_secret_key_hash = Argon2id(secret_key, server_argon_salt, params)
  const serverArgonSalt = sodium.from_base64(
    input.serverArgonSaltB64,
    sodium.base64_variants.ORIGINAL,
  );
  const argon2SecretKeyHash = await deriveKey(
    input.secretKey,
    serverArgonSalt,
    input.argon2Params,
    32,
  );

  // 8. recoveryInnerHash = sha256(NFKD-canonical mnemonic) — server applies HMAC.
  const recoveryInnerHash = computeRecoveryLookupHash(input.mnemonic);

  const envelope: SignupEnvelope = {
    inviteId: input.inviteId,
    argon2SecretKeyHash: b64(argon2SecretKeyHash),
    argon2Params: input.argon2Params,
    userArgonSalt: b64(userArgonSalt),
    wrappedMasterDek: packWrapped(wrappedMasterDek),
    wrappedMasterDekRecovery: packWrapped(wrappedMasterDekRecovery),
    recoveryInnerHash: b64(recoveryInnerHash),
    userPubKey: b64(kx.publicKey),
    wrappedUserSigningSk: packWrapped(wrappedUserSigningSk),
    wrappedUserKxSk: packWrapped(wrappedUserKxSk),
  };

  return {
    envelope,
    derived: {
      masterKek,
      masterDek,
      recoveryKek,
      signSk: sign.secretKey,
      kxSk: kx.secretKey,
    },
  };
}
