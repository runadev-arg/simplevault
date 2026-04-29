import type {
  EncryptedRecord,
  KdfParams,
  Plaintext,
  RecoveryPhrase,
  Salt,
  SymmetricKey,
  WrappedKey,
} from "./types.js";

export type * from "./types.js";

// Interface ONLY — both browser.ts and node.ts implement this.
// Phase 02 fills in the implementations.
export interface CryptoApi {
  randomBytes(n: number): Uint8Array;
  deriveMasterKEK(
    masterPassword: string,
    secretKey: Uint8Array,
    salt: Salt,
    params: KdfParams,
  ): Promise<SymmetricKey>;
  wrapKey(plaintextKey: SymmetricKey, kek: SymmetricKey): Promise<WrappedKey>;
  unwrapKey(wrapped: WrappedKey, kek: SymmetricKey): Promise<SymmetricKey>;
  encrypt(plaintext: Plaintext, key: SymmetricKey, aad: Uint8Array): Promise<EncryptedRecord>;
  decrypt(record: EncryptedRecord, key: SymmetricKey): Promise<Plaintext>;
  bip39Generate(): RecoveryPhrase;
  bip39ToSeed(phrase: RecoveryPhrase): Uint8Array;
  chainHashCompute(
    prevChainHash: Uint8Array | null,
    entryCanonicalJson: Uint8Array,
    hmacKey: Uint8Array,
  ): Promise<Uint8Array>;
  chainHashVerify(
    entry: { prev: Uint8Array | null; canonical: Uint8Array; chainHash: Uint8Array },
    hmacKey: Uint8Array,
  ): Promise<boolean>;
}

// The default export is resolved via conditional exports map.
// Don't export an implementation here — keep this file type-only.

// --- Public TYPE surface ---------------------------------------------------
// Re-export every value-bearing module's TYPE-LEVEL exports so consumers
// of `@simplevault/crypto/types` (or `import type { ... } from
// "@simplevault/crypto"`) get a single import site for type names without
// pulling either runtime barrel into their build graph.
//
// This is types-only (`export type`); the runtime implementations are
// resolved via the conditional exports map in package.json.
export type { Argon2Params } from "./argon2id.js";
export type { AeadCiphertext } from "./aead.js";
export type { CalibrationResult } from "./calibrate.js";
export type {
  DeriveMasterKekInput,
  DeriveRecoveryKekInput,
  WrappedKeyBlob,
} from "./key-hierarchy.js";
export type { KxKeyPair } from "./sealed-box.js";
