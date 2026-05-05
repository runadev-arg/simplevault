import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ready } from "@simplevault/crypto/browser";

import {
  buildVaultCredentialAad,
  decryptCredential,
  encryptCredential,
} from "./credential-cipher";

const VAULT_ID = "00000000-0000-0000-0000-000000000001";
const CREDENTIAL_ID = "00000000-0000-0000-0000-000000000002";
const EMAIL = "alice@example.com";

async function freshDek(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(32);
}

function aadFor(version: number): Uint8Array {
  return buildVaultCredentialAad({
    vaultId: VAULT_ID,
    credentialId: CREDENTIAL_ID,
    version,
    email: EMAIL,
  });
}

describe("credential-cipher round-trip + tamper", () => {
  it("encrypt → decrypt yields original plaintext under matching AAD", async () => {
    const dek = await freshDek();
    const aad = aadFor(1);
    const pt = '{"name":"github","password":"x"}';
    const blob = await encryptCredential(pt, dek, aad);
    const out = await decryptCredential(blob, dek, aad);
    expect(out).toBe(pt);
  });

  it("nonce is 24 bytes and unique across two encrypts of the same plaintext", async () => {
    const dek = await freshDek();
    const aad = aadFor(1);
    const pt = '{"name":"a"}';
    const a = await encryptCredential(pt, dek, aad);
    const b = await encryptCredential(pt, dek, aad);
    expect(a.nonce.length).toBe(24);
    expect(b.nonce.length).toBe(24);
    expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce));
    // ciphertexts also differ (nonce is mixed in)
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext));
  });

  it("tampered ciphertext rejects (AEAD tag failure)", async () => {
    const dek = await freshDek();
    const aad = aadFor(1);
    const pt = '{"name":"github"}';
    const blob = await encryptCredential(pt, dek, aad);
    const tampered = new Uint8Array(blob.ciphertext);
    tampered[0] ^= 0x01;
    await expect(
      decryptCredential({ ciphertext: tampered, nonce: blob.nonce }, dek, aad),
    ).rejects.toBeTruthy();
  });

  it("wrong AAD (different version) rejects", async () => {
    const dek = await freshDek();
    const aad = aadFor(1);
    const wrongAad = aadFor(2);
    const blob = await encryptCredential('{"x":1}', dek, aad);
    await expect(
      decryptCredential(blob, dek, wrongAad),
    ).rejects.toBeTruthy();
  });

  it("wrong masterDek rejects", async () => {
    const dek = await freshDek();
    const otherDek = await freshDek();
    const aad = aadFor(1);
    const blob = await encryptCredential('{"x":1}', dek, aad);
    await expect(
      decryptCredential(blob, otherDek, aad),
    ).rejects.toBeTruthy();
  });

  it("browser-only invariant: node entry does NOT expose buildVaultCredentialAad", async () => {
    const node = (await import("@simplevault/crypto/node")) as Record<
      string,
      unknown
    >;
    expect(node.buildVaultCredentialAad).toBeUndefined();
  });
});
