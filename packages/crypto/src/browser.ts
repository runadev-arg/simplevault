import type { CryptoApi } from "./index.js";

// Re-export Phase-02 primitives via the browser entry of the conditional
// exports map. Keep this file free of any built-in Node-runtime module
// import. The dist/browser.js grep step in the plan SUMMARY enforces
// this (see 02-04-SUMMARY.md for the exact regex).
export * from "./argon2id.js";
export * from "./aead.js";
export * from "./calibrate.js";
export * from "./bip39.js";
export * from "./key-hierarchy.js";
export * from "./sealed-box.js";

const notImplemented = (name: string): never => {
  throw new Error(`@simplevault/crypto browser.${name}() not yet implemented (Phase 02)`);
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
