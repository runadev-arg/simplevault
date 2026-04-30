import { describe, expect, it } from "vitest";
import { generateSigningKeyPair } from "../src/sign.js";

describe("Ed25519 signing keypair", () => {
  it("returns 32-byte publicKey and 64-byte secretKey", async () => {
    const kp = await generateSigningKeyPair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.secretKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(64);
  });

  it("each call returns a fresh keypair (statistical sanity)", async () => {
    const a = await generateSigningKeyPair();
    const b = await generateSigningKeyPair();
    expect(Array.from(a.publicKey)).not.toEqual(Array.from(b.publicKey));
    expect(Array.from(a.secretKey)).not.toEqual(Array.from(b.secretKey));
  });
});
