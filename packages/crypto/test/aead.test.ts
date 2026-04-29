import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ready } from "../src/argon2id.js";
import {
  AeadKeyLengthError,
  decrypt,
  encrypt,
  type AeadCiphertext,
} from "../src/aead.js";

const enc = new TextEncoder();
const NONCE_BYTES = 24;

async function freshKey(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(32);
}

describe("aead.encrypt", () => {
  it("returns {ciphertext, nonce} with 24-byte nonce", async () => {
    const key = await freshKey();
    const pt = enc.encode("hello vault");
    const aad = enc.encode("vault:1|item:1|v:1");
    const blob = await encrypt(pt, key, aad);
    expect(blob.nonce.length).toBe(NONCE_BYTES);
    expect(blob.ciphertext).toBeInstanceOf(Uint8Array);
    // poly1305 tag adds 16 bytes
    expect(blob.ciphertext.length).toBe(pt.length + 16);
  });

  it("two encrypts of same plaintext+key+aad produce different ciphertext", async () => {
    const key = await freshKey();
    const pt = enc.encode("identical");
    const aad = enc.encode("ctx");
    const a = await encrypt(pt, key, aad);
    const b = await encrypt(pt, key, aad);
    expect(Buffer.from(a.nonce).equals(Buffer.from(b.nonce))).toBe(false);
    expect(Buffer.from(a.ciphertext).equals(Buffer.from(b.ciphertext))).toBe(false);
  });

  it("rejects keys not exactly 32 bytes with a typed error", async () => {
    await ready();
    const pt = enc.encode("x");
    const aad = new Uint8Array(0);
    await expect(encrypt(pt, new Uint8Array(31), aad)).rejects.toBeInstanceOf(
      AeadKeyLengthError,
    );
    await expect(encrypt(pt, new Uint8Array(33), aad)).rejects.toBeInstanceOf(
      AeadKeyLengthError,
    );
  });

  it("nonce uniqueness over 10000 encrypts (Set size)", async () => {
    const key = await freshKey();
    const aad = new Uint8Array(0);
    const pt = enc.encode("n");
    const seen = new Set<string>();
    for (let i = 0; i < 10000; i++) {
      const blob = await encrypt(pt, key, aad);
      seen.add(Buffer.from(blob.nonce).toString("hex"));
    }
    expect(seen.size).toBe(10000);
  });
});

describe("aead.decrypt round-trip", () => {
  it("returns original plaintext when AAD matches", async () => {
    const key = await freshKey();
    const pt = enc.encode("the quick brown fox");
    const aad = enc.encode("vault:42|item:7|v:3");
    const blob = await encrypt(pt, key, aad);
    const out = await decrypt(blob, key, aad);
    expect(Buffer.from(out).equals(Buffer.from(pt))).toBe(true);
  });

  it("throws on mutated AAD (tag mismatch)", async () => {
    const key = await freshKey();
    const pt = enc.encode("payload");
    const aad = enc.encode("ctx-A");
    const blob = await encrypt(pt, key, aad);
    const wrongAad = enc.encode("ctx-B");
    await expect(decrypt(blob, key, wrongAad)).rejects.toThrow();
  });

  it("throws on mutated ciphertext", async () => {
    const key = await freshKey();
    const pt = enc.encode("payload");
    const aad = enc.encode("ctx");
    const blob = await encrypt(pt, key, aad);
    const tampered: AeadCiphertext = {
      ciphertext: new Uint8Array(blob.ciphertext),
      nonce: blob.nonce,
    };
    tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 0x01;
    await expect(decrypt(tampered, key, aad)).rejects.toThrow();
  });

  it("throws on wrong key", async () => {
    const key = await freshKey();
    const wrongKey = await freshKey();
    const pt = enc.encode("payload");
    const aad = enc.encode("ctx");
    const blob = await encrypt(pt, key, aad);
    await expect(decrypt(blob, wrongKey, aad)).rejects.toThrow();
  });
});

describe("aead barrel parity", () => {
  it("browser and node barrels both export encrypt/decrypt", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");
    for (const name of ["encrypt", "decrypt", "AeadKeyLengthError"]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod, `node missing ${name}`).toHaveProperty(name);
    }
  });
});
