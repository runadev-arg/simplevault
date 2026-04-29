import { describe, expect, it } from "vitest";
import {
  computeRecoveryLookupHash,
  generateMnemonic,
  mnemonicToSeed,
  validateMnemonic,
} from "../src/bip39.js";

describe("bip39.generateMnemonic", () => {
  it("returns a 24-word English mnemonic (256-bit entropy)", () => {
    const m = generateMnemonic();
    expect(typeof m).toBe("string");
    expect(m.split(" ").length).toBe(24);
  });

  it("two generates produce different mnemonics", () => {
    const a = generateMnemonic();
    const b = generateMnemonic();
    expect(a).not.toBe(b);
  });
});

describe("bip39.validateMnemonic", () => {
  it("accepts a freshly generated mnemonic", () => {
    expect(validateMnemonic(generateMnemonic())).toBe(true);
  });

  it("rejects a mnemonic with a non-wordlist word (typo)", () => {
    const m = generateMnemonic();
    const words = m.split(" ");
    words[0] = "notarealbip39word";
    expect(validateMnemonic(words.join(" "))).toBe(false);
  });

  it("rejects a checksum-broken mnemonic (last word swapped)", () => {
    // Try multiple regenerations — random mutation can occasionally land on a
    // checksum-valid alternative for a different entropy. Loop until the
    // checksum-failure branch is exercised at least once (probability of
    // 256 consecutive valid landings is astronomical).
    let sawInvalid = false;
    for (let i = 0; i < 16 && !sawInvalid; i++) {
      const m = generateMnemonic();
      const words = m.split(" ");
      const last = words[23]!;
      // Swap last with a deterministic alternative from the wordlist
      words[23] = last === "zone" ? "zoo" : "zone";
      if (!validateMnemonic(words.join(" "))) sawInvalid = true;
    }
    expect(sawInvalid).toBe(true);
  });

  it("rejects a mnemonic with the wrong word count", () => {
    const m = generateMnemonic();
    const truncated = m.split(" ").slice(0, 23).join(" ");
    expect(validateMnemonic(truncated)).toBe(false);
  });
});

describe("bip39.mnemonicToSeed", () => {
  it("returns a 64-byte Uint8Array", async () => {
    const m = generateMnemonic();
    const seed = await mnemonicToSeed(m);
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(64);
  });

  it("is deterministic in (mnemonic, passphrase)", async () => {
    const m = generateMnemonic();
    const a = await mnemonicToSeed(m, "");
    const b = await mnemonicToSeed(m, "");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("differs when passphrase differs", async () => {
    const m = generateMnemonic();
    const a = await mnemonicToSeed(m, "");
    const b = await mnemonicToSeed(m, "extra");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("bip39.computeRecoveryLookupHash", () => {
  it("returns 32-byte sha256 of canonicalised mnemonic", () => {
    const m = generateMnemonic();
    const h = computeRecoveryLookupHash(m);
    expect(h).toBeInstanceOf(Uint8Array);
    expect(h.length).toBe(32);
  });

  it("is canonicalisation-invariant: NFKD + lowercase + single-space", () => {
    const m = generateMnemonic();
    const messy = "  " + m.toUpperCase().split(" ").join("\t  ") + "  ";
    const a = computeRecoveryLookupHash(m);
    const b = computeRecoveryLookupHash(messy);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("differs across distinct mnemonics", () => {
    const a = computeRecoveryLookupHash(generateMnemonic());
    const b = computeRecoveryLookupHash(generateMnemonic());
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("bip39 barrel parity", () => {
  it("browser exports the bip39 surface; node MUST NOT (server never sees mnemonics)", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");
    for (const name of [
      "generateMnemonic",
      "validateMnemonic",
      "mnemonicToSeed",
      "computeRecoveryLookupHash",
    ]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod).not.toHaveProperty(name);
    }
  });
});
