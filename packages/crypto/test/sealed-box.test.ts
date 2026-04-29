import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ready } from "../src/argon2id.js";
import {
  generateKxKeyPair,
  sealedBoxOpen,
  sealedBoxSeal,
} from "../src/sealed-box.js";

const SEALBYTES = 48; // crypto_box_SEALBYTES (= crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)

describe("sealed-box.generateKxKeyPair", () => {
  it("returns a 32-byte publicKey + 32-byte secretKey", async () => {
    await ready();
    const kp = await generateKxKeyPair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.secretKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });

  it("two consecutive calls produce different keypairs", async () => {
    const a = await generateKxKeyPair();
    const b = await generateKxKeyPair();
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(
      false,
    );
    expect(Buffer.from(a.secretKey).equals(Buffer.from(b.secretKey))).toBe(
      false,
    );
  });
});

describe("sealed-box.sealedBoxSeal", () => {
  it("returns a ciphertext of plaintext.length + crypto_box_SEALBYTES", async () => {
    const kp = await generateKxKeyPair();
    const pt = sodium.randombytes_buf(32);
    const ct = await sealedBoxSeal(pt, kp.publicKey);
    expect(ct).toBeInstanceOf(Uint8Array);
    expect(ct.length).toBe(pt.length + SEALBYTES);
  });

  it("two seals of the same plaintext+pubkey produce different ciphertexts (anonymous ephemeral)", async () => {
    const kp = await generateKxKeyPair();
    const pt = sodium.randombytes_buf(32);
    const a = await sealedBoxSeal(pt, kp.publicKey);
    const b = await sealedBoxSeal(pt, kp.publicKey);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("sealed-box round-trip", () => {
  it("sealedBoxOpen(seal(pt, pk), pk, sk) returns pt", async () => {
    const kp = await generateKxKeyPair();
    const pt = sodium.randombytes_buf(32);
    const ct = await sealedBoxSeal(pt, kp.publicKey);
    const out = await sealedBoxOpen(ct, kp.publicKey, kp.secretKey);
    expect(Buffer.from(out).equals(Buffer.from(pt))).toBe(true);
  });

  it("end-to-end: 32-byte vault_DEK seal-to-recipient round trip", async () => {
    const recipient = await generateKxKeyPair();
    const vaultDek = sodium.randombytes_buf(32);
    const wrapped = await sealedBoxSeal(vaultDek, recipient.publicKey);
    const unwrapped = await sealedBoxOpen(
      wrapped,
      recipient.publicKey,
      recipient.secretKey,
    );
    expect(unwrapped.length).toBe(32);
    expect(Buffer.from(unwrapped).equals(Buffer.from(vaultDek))).toBe(true);
  });

  it("throws when opened with the wrong recipient secretKey", async () => {
    const right = await generateKxKeyPair();
    const wrong = await generateKxKeyPair();
    const pt = sodium.randombytes_buf(32);
    const ct = await sealedBoxSeal(pt, right.publicKey);
    await expect(
      sealedBoxOpen(ct, right.publicKey, wrong.secretKey),
    ).rejects.toThrow();
  });

  it("throws when ciphertext is mutated by one byte", async () => {
    const kp = await generateKxKeyPair();
    const pt = sodium.randombytes_buf(32);
    const ct = await sealedBoxSeal(pt, kp.publicKey);
    const tampered = new Uint8Array(ct);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0x01;
    await expect(
      sealedBoxOpen(tampered, kp.publicKey, kp.secretKey),
    ).rejects.toThrow();
  });
});

describe("sealed-box barrel parity", () => {
  it("browser and node barrels both export sealed-box symbols", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");
    for (const name of ["generateKxKeyPair", "sealedBoxSeal", "sealedBoxOpen"]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod, `node missing ${name}`).toHaveProperty(name);
    }
  });
});
