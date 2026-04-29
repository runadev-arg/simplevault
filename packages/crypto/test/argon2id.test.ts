import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  ARGON2_DEFAULT_PARAMS,
  ARGON2_FLOOR_PARAMS,
  deriveKey,
  paramsToOpsMem,
  ready,
  verify,
  type Argon2Params,
} from "../src/argon2id.js";

const enc = new TextEncoder();

describe("argon2id constants", () => {
  it("ARGON2_DEFAULT_PARAMS = m=64MiB, t=3, p=1", () => {
    expect(ARGON2_DEFAULT_PARAMS).toEqual({
      memoryKiB: 64 * 1024,
      iterations: 3,
      parallelism: 1,
    });
  });

  it("ARGON2_FLOOR_PARAMS = m=19MiB, t=2, p=1 (OWASP minimum)", () => {
    expect(ARGON2_FLOOR_PARAMS).toEqual({
      memoryKiB: 19 * 1024,
      iterations: 2,
      parallelism: 1,
    });
  });

  it("paramsToOpsMem encodes for libsodium opslimit/memlimit", async () => {
    await ready();
    const { opslimit, memlimit } = paramsToOpsMem(ARGON2_DEFAULT_PARAMS);
    expect(opslimit).toBe(3);
    // memlimit is in bytes
    expect(memlimit).toBe(64 * 1024 * 1024);
  });
});

describe("deriveKey", () => {
  it("returns 32-byte Uint8Array; deterministic for fixed inputs", async () => {
    await ready();
    const password = enc.encode("correct horse battery staple");
    const salt = sodium.randombytes_buf(16);
    const k1 = await deriveKey(password, salt, ARGON2_FLOOR_PARAMS);
    const k2 = await deriveKey(password, salt, ARGON2_FLOOR_PARAMS);
    expect(k1).toBeInstanceOf(Uint8Array);
    expect(k1.length).toBe(32);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });

  it("different salts produce different outputs", async () => {
    await ready();
    const password = enc.encode("correct horse battery staple");
    const salt1 = sodium.randombytes_buf(16);
    const salt2 = sodium.randombytes_buf(16);
    const k1 = await deriveKey(password, salt1, ARGON2_FLOOR_PARAMS);
    const k2 = await deriveKey(password, salt2, ARGON2_FLOOR_PARAMS);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
  });

  it("rejects salts shorter than 16 bytes with a typed error", async () => {
    await ready();
    const password = enc.encode("pw");
    const shortSalt = new Uint8Array(8);
    await expect(deriveKey(password, shortSalt, ARGON2_FLOOR_PARAMS)).rejects.toThrow(
      /salt/i,
    );
  });

  it("default params take >50ms (sanity: not zero iterations)", async () => {
    // 50ms floor is a sanity check that we didn't accidentally pass 0
    // iterations or skip the KDF entirely. Real-world Argon2id with
    // m=64MiB,t=3 lands ~90-800ms depending on hardware.
    await ready();
    const password = enc.encode("pw");
    const salt = sodium.randombytes_buf(16);
    const t0 = performance.now();
    await deriveKey(password, salt, ARGON2_DEFAULT_PARAMS);
    const dt = performance.now() - t0;
    expect(dt).toBeGreaterThan(50);
  });
});

describe("verify", () => {
  it("true when key matches; false when password differs by one bit", async () => {
    await ready();
    const password = enc.encode("correct horse battery staple");
    const salt = sodium.randombytes_buf(16);
    const params: Argon2Params = ARGON2_FLOOR_PARAMS;
    const expected = await deriveKey(password, salt, params);
    expect(await verify(password, salt, params, expected)).toBe(true);

    const tampered = new Uint8Array(password);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    expect(await verify(tampered, salt, params, expected)).toBe(false);
  });
});

describe("barrel export parity", () => {
  it("browser and node barrels export the same argon2id symbol set", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");
    const expected = [
      "ARGON2_DEFAULT_PARAMS",
      "ARGON2_FLOOR_PARAMS",
      "deriveKey",
      "verify",
      "paramsToOpsMem",
      "ready",
    ];
    for (const name of expected) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod, `node missing ${name}`).toHaveProperty(name);
    }
  });
});
