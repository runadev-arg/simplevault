import {
  ready,
  deriveKey,
  deriveMasterKek,
  unwrapKey,
  encodeAad,
  type Argon2Params,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

import {
  AAD_LABEL_KX_SK,
  AAD_LABEL_MASTER,
  AAD_LABEL_SIGN_SK,
  type AadLabel,
} from "./aad-labels";

/**
 * Login-side mirror of `signup-derivations.ts`.
 *
 * Two derivations live here:
 *
 *   1. `buildLoginEnvelope`: compute `argon2_secret_key_hash` —
 *      the verifier the server compares constant-time against
 *      `users.argon2_secret_key_hash`. Same Argon2id derivation as
 *      signup (Argon2id(secret_key, server_argon_salt, params, 32B))
 *      with a GLOBAL `serverArgonSalt` that the client received in the
 *      /auth/login response (see "salt round-trip" in 02-11 SUMMARY).
 *
 *   2. `unlockMasterDek`: re-derive `master_KEK` from
 *      (password, secret_key, email, user_argon_salt, argon2_params)
 *      and unwrap the three wrapped keys returned by /auth/login,
 *      using the BYTE-IDENTICAL AAD (label || sha256(lower(email)))
 *      that signup used.
 */

const enc = new TextEncoder();

function emailHash(email: string): Uint8Array {
  return sodium.crypto_hash_sha256(enc.encode(email.toLowerCase()));
}

function aadFor(label: AadLabel, params: Argon2Params, h: Uint8Array): Uint8Array {
  const prefix = enc.encode(label);
  const ctx = new Uint8Array(prefix.length + h.length);
  ctx.set(prefix, 0);
  ctx.set(h, prefix.length);
  return encodeAad(params, ctx);
}

function fromB64(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

/**
 * Unpack the on-the-wire `nonce || ciphertext` blob (24-byte
 * XChaCha20-Poly1305 nonce + Poly1305 ciphertext+tag).
 */
function unpackWrapped(
  blobB64: string,
): { nonce: Uint8Array; ciphertext: Uint8Array } {
  const raw = fromB64(blobB64);
  if (raw.length < 24 + 16) {
    throw new Error("login-derivations: wrapped blob too short");
  }
  const nonce = raw.slice(0, 24);
  const ciphertext = raw.slice(24);
  return { nonce, ciphertext };
}

// --- 1. argon2_secret_key_hash builder ------------------------------------

export interface BuildLoginEnvelopeInput {
  email: string;
  secretKey: Uint8Array; // 16 B
  argon2Params: Argon2Params;
  /** base64-encoded global server-argon-salt (16 B). */
  serverArgonSaltB64: string;
}

export interface LoginEnvelope {
  email: string;
  argon2SecretKeyHash: string; // base64, 32 B
}

export async function buildLoginEnvelope(
  input: BuildLoginEnvelopeInput,
): Promise<LoginEnvelope> {
  await ready();
  const serverArgonSalt = fromB64(input.serverArgonSaltB64);
  const hash = await deriveKey(
    input.secretKey,
    serverArgonSalt,
    input.argon2Params,
    32,
  );
  return {
    email: input.email,
    argon2SecretKeyHash: sodium.to_base64(hash, sodium.base64_variants.ORIGINAL),
  };
}

// --- 2. unwrap master_DEK + signing/kx secret keys ------------------------

export interface UnlockSecretsInput {
  email: string;
  password: string;
  secretKey: Uint8Array;
  argon2Params: Argon2Params;
  /** base64, 16 B — returned by /auth/login. */
  userArgonSaltB64: string;
  /** base64 nonce||ct from /auth/login. */
  wrappedMasterDekB64: string;
  wrappedUserSigningSkB64: string;
  wrappedUserKxSkB64: string;
}

export interface UnlockedSecrets {
  masterKek: Uint8Array;
  masterDek: Uint8Array;
  signingSk: Uint8Array;
  kxSk: Uint8Array;
}

export async function unlockSecrets(
  input: UnlockSecretsInput,
): Promise<UnlockedSecrets> {
  await ready();
  const userArgonSalt = fromB64(input.userArgonSaltB64);

  const masterKek = await deriveMasterKek({
    password: input.password,
    secretKey: input.secretKey,
    email: input.email,
    userArgonSalt,
    argon2Params: input.argon2Params,
  });

  const h = emailHash(input.email);

  const masterDek = await unwrapKey(
    unpackWrapped(input.wrappedMasterDekB64),
    masterKek,
    aadFor(AAD_LABEL_MASTER, input.argon2Params, h),
  );
  const signingSk = await unwrapKey(
    unpackWrapped(input.wrappedUserSigningSkB64),
    masterKek,
    aadFor(AAD_LABEL_SIGN_SK, input.argon2Params, h),
  );
  const kxSk = await unwrapKey(
    unpackWrapped(input.wrappedUserKxSkB64),
    masterKek,
    aadFor(AAD_LABEL_KX_SK, input.argon2Params, h),
  );

  return { masterKek, masterDek, signingSk, kxSk };
}
