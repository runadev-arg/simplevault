import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ARGON2_FLOOR_PARAMS, ready } from "../src/argon2id.js";
import { generateMnemonic } from "../src/bip39.js";
import {
  AAD_VERSION,
  deriveMasterKek,
  deriveRecoveryKek,
  encodeAad,
  unwrapKey,
  wrapKey,
} from "../src/key-hierarchy.js";

const enc = new TextEncoder();
const params = ARGON2_FLOOR_PARAMS; // fast for tests
const userId = enc.encode("11111111-1111-4111-8111-111111111111");

async function fresh32(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(32);
}

async function fresh16(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(16);
}

describe("key-hierarchy.deriveMasterKek", () => {
  it("returns a 32-byte key", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const k = await deriveMasterKek({
      password: "correct horse battery staple",
      secretKey,
      email: "Alice@Example.com",
      userArgonSalt,
      argon2Params: params,
    });
    expect(k.length).toBe(32);
  });

  it("different passwords → different KEKs", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const a = await deriveMasterKek({
      password: "alpha",
      secretKey,
      email: "x@y.z",
      userArgonSalt,
      argon2Params: params,
    });
    const b = await deriveMasterKek({
      password: "bravo",
      secretKey,
      email: "x@y.z",
      userArgonSalt,
      argon2Params: params,
    });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("different secretKeys → different KEKs", async () => {
    const userArgonSalt = await fresh16();
    const a = await deriveMasterKek({
      password: "p",
      secretKey: await fresh32(),
      email: "x@y.z",
      userArgonSalt,
      argon2Params: params,
    });
    const b = await deriveMasterKek({
      password: "p",
      secretKey: await fresh32(),
      email: "x@y.z",
      userArgonSalt,
      argon2Params: params,
    });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("different emails → different KEKs (HKDF salt domain separation)", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const a = await deriveMasterKek({
      password: "p",
      secretKey,
      email: "alice@x.z",
      userArgonSalt,
      argon2Params: params,
    });
    const b = await deriveMasterKek({
      password: "p",
      secretKey,
      email: "bob@x.z",
      userArgonSalt,
      argon2Params: params,
    });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("email is case-insensitive (lowercased before HKDF salt)", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const a = await deriveMasterKek({
      password: "p",
      secretKey,
      email: "Alice@Example.com",
      userArgonSalt,
      argon2Params: params,
    });
    const b = await deriveMasterKek({
      password: "p",
      secretKey,
      email: "alice@example.com",
      userArgonSalt,
      argon2Params: params,
    });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });
});

describe("key-hierarchy.deriveRecoveryKek", () => {
  it("returns a 32-byte key", async () => {
    const k = await deriveRecoveryKek({ mnemonic: generateMnemonic(), userId });
    expect(k.length).toBe(32);
  });

  it("is independent of password (deterministic in mnemonic+userId)", async () => {
    const m = generateMnemonic();
    const a = await deriveRecoveryKek({ mnemonic: m, userId });
    const b = await deriveRecoveryKek({ mnemonic: m, userId });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("different userId → different recovery KEKs", async () => {
    const m = generateMnemonic();
    const a = await deriveRecoveryKek({ mnemonic: m, userId: enc.encode("u1") });
    const b = await deriveRecoveryKek({ mnemonic: m, userId: enc.encode("u2") });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("key-hierarchy.encodeAad", () => {
  it("emits version || params(12B) || contextId", () => {
    const aad = encodeAad(params, userId);
    expect(aad[0]).toBe(AAD_VERSION);
    expect(aad.length).toBe(1 + 12 + userId.length);
    // params bytes: m_be32 || t_be32 || p_be32
    const view = new DataView(aad.buffer, aad.byteOffset + 1, 12);
    expect(view.getUint32(0, false)).toBe(params.memoryKiB);
    expect(view.getUint32(4, false)).toBe(params.iterations);
    expect(view.getUint32(8, false)).toBe(params.parallelism);
  });

  it("is deterministic", () => {
    const a = encodeAad(params, userId);
    const b = encodeAad(params, userId);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });
});

describe("key-hierarchy wrap/unwrap round-trip", () => {
  it("master_KEK round-trip: wrap → unwrap → identical bytes", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const masterDek = await fresh32();
    const masterKek = await deriveMasterKek({
      password: "correct horse battery staple",
      secretKey,
      email: "alice@x.z",
      userArgonSalt,
      argon2Params: params,
    });
    const aad = encodeAad(params, userId);
    const wrapped = await wrapKey(masterDek, masterKek, aad);
    const unwrapped = await unwrapKey(wrapped, masterKek, aad);
    expect(Buffer.from(unwrapped).equals(Buffer.from(masterDek))).toBe(true);
  });

  it("recovery_KEK round-trip: wrap with recovery_KEK → unwrap with mnemonic-derived KEK → identical bytes", async () => {
    const masterDek = await fresh32();
    const mnemonic = generateMnemonic();
    const recoveryKekA = await deriveRecoveryKek({ mnemonic, userId });
    const aad = encodeAad(params, userId);
    const wrapped = await wrapKey(masterDek, recoveryKekA, aad);
    // Re-derive on a fresh "device": same mnemonic + userId
    const recoveryKekB = await deriveRecoveryKek({ mnemonic, userId });
    const unwrapped = await unwrapKey(wrapped, recoveryKekB, aad);
    expect(Buffer.from(unwrapped).equals(Buffer.from(masterDek))).toBe(true);
  });

  it("dual-path: same master_DEK reachable via password OR recovery", async () => {
    const secretKey = await fresh32();
    const userArgonSalt = await fresh16();
    const masterDek = await fresh32();
    const mnemonic = generateMnemonic();

    const masterKek = await deriveMasterKek({
      password: "p",
      secretKey,
      email: "a@b.c",
      userArgonSalt,
      argon2Params: params,
    });
    const recoveryKek = await deriveRecoveryKek({ mnemonic, userId });

    const aad = encodeAad(params, userId);
    const wrappedByMaster = await wrapKey(masterDek, masterKek, aad);
    const wrappedByRecovery = await wrapKey(masterDek, recoveryKek, aad);

    const viaMaster = await unwrapKey(wrappedByMaster, masterKek, aad);
    const viaRecovery = await unwrapKey(wrappedByRecovery, recoveryKek, aad);
    expect(Buffer.from(viaMaster).equals(Buffer.from(masterDek))).toBe(true);
    expect(Buffer.from(viaRecovery).equals(Buffer.from(masterDek))).toBe(true);
  });
});

describe("key-hierarchy AAD downgrade defence", () => {
  it("unwrap throws when AAD argon2 params bytes change", async () => {
    const kek = await fresh32();
    const dek = await fresh32();
    const aadA = encodeAad(params, userId);
    const wrapped = await wrapKey(dek, kek, aadA);

    // Different params → different AAD
    const downgraded = { ...params, memoryKiB: params.memoryKiB - 1024 };
    const aadB = encodeAad(downgraded, userId);
    await expect(unwrapKey(wrapped, kek, aadB)).rejects.toThrow();
  });

  it("unwrap throws when AAD context (userId) changes", async () => {
    const kek = await fresh32();
    const dek = await fresh32();
    const aadA = encodeAad(params, userId);
    const wrapped = await wrapKey(dek, kek, aadA);

    const aadB = encodeAad(params, enc.encode("different-user-id"));
    await expect(unwrapKey(wrapped, kek, aadB)).rejects.toThrow();
  });

  it("unwrap throws when version byte changes", async () => {
    const kek = await fresh32();
    const dek = await fresh32();
    const aadA = encodeAad(params, userId);
    const wrapped = await wrapKey(dek, kek, aadA);
    const aadB = new Uint8Array(aadA);
    aadB[0] = (aadB[0]! + 1) & 0xff;
    await expect(unwrapKey(wrapped, kek, aadB)).rejects.toThrow();
  });
});

describe("key-hierarchy barrel parity", () => {
  it("browser exports the full hierarchy surface; node exports only server-safe symbols", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");

    // Always-shared (server-safe) symbols.
    for (const name of ["wrapKey", "unwrapKey", "encodeAad", "AAD_VERSION"]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod, `node missing ${name}`).toHaveProperty(name);
    }

    // Browser-only symbols (take password / secret_key / mnemonic and so
    // MUST NOT be reachable from the Node barrel — see node.ts invariant).
    for (const name of ["deriveMasterKek", "deriveRecoveryKek"]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod).not.toHaveProperty(name);
    }
  });
});
