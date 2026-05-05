import { generateKxKeyPair, ready } from "@simplevault/crypto/browser";
import { describe, expect, it } from "vitest";

import { generateVaultDek, unwrapVaultKey, wrapVaultKey } from "./vault-key";

describe("vault-key", () => {
  it("generateVaultDek returns 32 bytes", async () => {
    const dek = await generateVaultDek();
    expect(dek.length).toBe(32);
  });

  it("wrapVaultKey → unwrapVaultKey round-trip yields original DEK", async () => {
    await ready();
    const kp = await generateKxKeyPair();
    const dek = await generateVaultDek();
    const sealed = await wrapVaultKey(dek, kp.publicKey);
    const recovered = await unwrapVaultKey(sealed, kp.publicKey, kp.secretKey);
    expect(Array.from(recovered)).toEqual(Array.from(dek));
  });

  it("sealed box is 80 bytes (32-byte DEK + 48-byte seal overhead)", async () => {
    await ready();
    const kp = await generateKxKeyPair();
    const dek = await generateVaultDek();
    const sealed = await wrapVaultKey(dek, kp.publicKey);
    expect(sealed.length).toBe(80);
  });

  it("wrong kx_sk rejects", async () => {
    await ready();
    const kp = await generateKxKeyPair();
    const other = await generateKxKeyPair();
    const dek = await generateVaultDek();
    const sealed = await wrapVaultKey(dek, kp.publicKey);
    await expect(
      unwrapVaultKey(sealed, other.publicKey, other.secretKey),
    ).rejects.toBeTruthy();
  });

  it("tampered sealed box rejects", async () => {
    await ready();
    const kp = await generateKxKeyPair();
    const dek = await generateVaultDek();
    const sealed = await wrapVaultKey(dek, kp.publicKey);
    const tampered = new Uint8Array(sealed);
    tampered.set([0x00], 0);
    await expect(
      unwrapVaultKey(tampered, kp.publicKey, kp.secretKey),
    ).rejects.toBeTruthy();
  });
});
