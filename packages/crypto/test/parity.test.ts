import { describe, expect, it } from "vitest";

/**
 * Cross-runtime export-parity contract for `@simplevault/crypto`.
 *
 * Goal: catch silent drift where a contributor adds a new export to one
 * barrel and forgets the other. The shared set is asserted by name; the
 * deliberate browser-only divergence is asserted by snapshot so any
 * future change to that set must be a conscious edit to this test.
 *
 * Why divergence exists at all (see node.ts header):
 *   The Node barrel intentionally drops every function that takes a
 *   master_password, secret_key, or mnemonic as input. The server must
 *   never see those values, and dropping them from the Node entry-point
 *   gives that invariant a type-system enforcement (server code that
 *   accidentally imports `deriveMasterKek` will fail to compile, not at
 *   runtime).
 *
 * If you legitimately need to change either set, update both the
 * `BROWSER_ONLY_EXPECTED` snapshot below AND the prose in node.ts.
 */

// Symbols that MUST appear in both barrels (the "shared" surface).
// Sorted for stable diffs.
const SHARED_EXPECTED = [
  "AAD_VERSION",
  "ARGON2_DEFAULT_PARAMS",
  "ARGON2_FLOOR_PARAMS",
  "ARGON2_MEMORY_CAP_KIB",
  "AeadKeyLengthError",
  "Argon2SaltTooShortError",
  "SealedBoxKeyLengthError",
  "calibrate",
  "cryptoApi",
  "decrypt",
  "default",
  "deriveKey",
  "encodeAad",
  "encrypt",
  "generateKxKeyPair",
  "generateSigningKeyPair",
  "paramsToOpsMem",
  "ready",
  "sealedBoxOpen",
  "sealedBoxSeal",
  "unwrapKey",
  "verify",
  "wrapKey",
].sort();

// Symbols intentionally exported ONLY from the browser barrel (because
// they take password / secret_key / mnemonic / TOTP-secret as input — see
// node.ts header).
const BROWSER_ONLY_EXPECTED = [
  "buildOtpauthUrl",
  "buildVaultCredentialAad",
  "buildVaultPageAad",
  "canonicalCredentialAadJson",
  "canonicalPageAadJson",
  "computeRecoveryLookupHash",
  "computeTitleSearchToken",
  "computeTotpStep",
  "deriveMasterKek",
  "deriveRecoveryKek",
  "deriveTitleSearchKey",
  "generateMnemonic",
  "generateMnemonicAsync",
  "mnemonicToSeed",
  "totpReady",
  "validateMnemonic",
  "verifyTotpCandidate",
].sort();

// Symbols intentionally exported ONLY from the node barrel (currently
// none — node.ts is a strict subset of browser.ts).
const NODE_ONLY_EXPECTED: readonly string[] = [];

describe("crypto barrel symbol parity", () => {
  it("browser and node barrels' shared surface matches the snapshot", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");

    const browserKeys = Object.keys(browser).sort();
    const nodeKeys = Object.keys(node).sort();

    const sharedActual = browserKeys.filter((k) => nodeKeys.includes(k)).sort();
    expect(sharedActual).toEqual(SHARED_EXPECTED);
  });

  it("browser-only symbols match the deliberate-divergence snapshot", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");

    const browserKeys = Object.keys(browser).sort();
    const nodeKeys = Object.keys(node).sort();

    const browserOnlyActual = browserKeys
      .filter((k) => !nodeKeys.includes(k))
      .sort();
    expect(browserOnlyActual).toEqual(BROWSER_ONLY_EXPECTED);
  });

  it("node-only symbols match the deliberate-divergence snapshot", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");

    const browserKeys = Object.keys(browser).sort();
    const nodeKeys = Object.keys(node).sort();

    const nodeOnlyActual = nodeKeys
      .filter((k) => !browserKeys.includes(k))
      .sort();
    expect(nodeOnlyActual).toEqual([...NODE_ONLY_EXPECTED]);
  });

  it("for every shared symbol, both runtimes export the same kind (function vs value)", async () => {
    const browser = (await import("../src/browser.js")) as Record<
      string,
      unknown
    >;
    const node = (await import("../src/node.js")) as Record<string, unknown>;

    for (const key of SHARED_EXPECTED) {
      const bv = browser[key];
      const nv = node[key];
      expect(typeof bv, `browser typeof ${key}`).toBe(typeof nv);
      if (typeof bv === "function") {
        expect(typeof nv).toBe("function");
      }
    }
  });

  it("ARGON2_DEFAULT_PARAMS deep-equals across runtimes", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");
    expect(browser.ARGON2_DEFAULT_PARAMS).toEqual(node.ARGON2_DEFAULT_PARAMS);
  });

  it("ARGON2_FLOOR_PARAMS deep-equals across runtimes", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");
    expect(browser.ARGON2_FLOOR_PARAMS).toEqual(node.ARGON2_FLOOR_PARAMS);
  });

  it("AAD_VERSION is the same primitive across runtimes", async () => {
    const browser = await import("../src/browser.js");
    const node = await import("../src/node.js");
    expect(browser.AAD_VERSION).toBe(node.AAD_VERSION);
  });
});
