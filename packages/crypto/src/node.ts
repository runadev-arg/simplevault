import type { CryptoApi } from "./index.js";

/**
 * Server-side (Node) entry of the conditional exports map.
 *
 * INVARIANT (LOAD-BEARING): this barrel MUST NOT re-export any function
 * whose input is `master_password`, `secret_key`, or `mnemonic`. The
 * server never sees those values — exposing such symbols on the Node
 * barrel would invite an accidental import-and-call from API code.
 *
 * Concretely we drop:
 *   - `deriveMasterKek`               (takes password + secret_key)
 *   - `deriveRecoveryKek`             (takes mnemonic)
 *   - `generateMnemonic` / `generateMnemonicAsync`
 *   - `validateMnemonic`
 *   - `mnemonicToSeed`
 *   - `computeRecoveryLookupHash`     (takes mnemonic; the server-side
 *                                      outer-HMAC step lives in the API
 *                                      layer, not in @simplevault/crypto)
 *
 * The symbol-parity test (`test/parity.test.ts`) treats this divergence
 * as deliberate and snapshots the omitted set so future drift is caught.
 *
 * Server-safe surface (kept):
 *   - argon2id constants + `paramsToOpsMem`, `ready`, `verify` (the server
 *     uses these for KDF calibration / lookup-hash verification, but
 *     `deriveKey` is also kept because audit/HMAC paths in later phases
 *     may need it; password-input contexts are caller-policed)
 *   - aead `encrypt` / `decrypt` (general-purpose AEAD, server uses for
 *     audit-log canonical-record HMAC and any future server-side blobs)
 *   - calibrate (server-side CLI)
 *   - key-hierarchy `encodeAad`, `wrapKey`, `unwrapKey`, `AAD_VERSION`
 *     (server may need to re-verify AAD bindings during signup
 *      validation — see Plan 02-07)
 *   - sealed-box (server can construct sealed-boxes for invites if a
 *     trusted-server-side-signing path is later added; harmless server-
 *     side because no secret-key input)
 */

export {
  // argon2id
  ARGON2_DEFAULT_PARAMS,
  ARGON2_FLOOR_PARAMS,
  Argon2SaltTooShortError,
  deriveKey,
  paramsToOpsMem,
  ready,
  verify,
} from "./argon2id.js";
export type { Argon2Params } from "./argon2id.js";

export {
  AeadKeyLengthError,
  decrypt,
  encrypt,
} from "./aead.js";
export type { AeadCiphertext } from "./aead.js";

export { ARGON2_MEMORY_CAP_KIB, calibrate } from "./calibrate.js";
export type { CalibrationResult } from "./calibrate.js";

export {
  AAD_VERSION,
  encodeAad,
  unwrapKey,
  wrapKey,
} from "./key-hierarchy.js";
export type {
  DeriveMasterKekInput,
  DeriveRecoveryKekInput,
  WrappedKeyBlob,
} from "./key-hierarchy.js";

export {
  generateKxKeyPair,
  SealedBoxKeyLengthError,
  sealedBoxOpen,
  sealedBoxSeal,
} from "./sealed-box.js";
export type { KxKeyPair } from "./sealed-box.js";

const notImplemented = (name: string): never => {
  throw new Error(`@simplevault/crypto node.${name}() not yet implemented (Phase 02)`);
};

export const cryptoApi: CryptoApi = {
  randomBytes: () => notImplemented("randomBytes"),
  deriveMasterKEK: () => Promise.resolve(notImplemented("deriveMasterKEK")),
  wrapKey: () => Promise.resolve(notImplemented("wrapKey")),
  unwrapKey: () => Promise.resolve(notImplemented("unwrapKey")),
  encrypt: () => Promise.resolve(notImplemented("encrypt")),
  decrypt: () => Promise.resolve(notImplemented("decrypt")),
  bip39Generate: () => notImplemented("bip39Generate"),
  bip39ToSeed: () => notImplemented("bip39ToSeed"),
  chainHashCompute: () => Promise.resolve(notImplemented("chainHashCompute")),
  chainHashVerify: () => Promise.resolve(notImplemented("chainHashVerify")),
};

export default cryptoApi;
