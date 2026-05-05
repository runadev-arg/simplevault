import { describe, expect, it } from "vitest";
import { ready } from "../src/argon2id.js";
import {
  computeTitleSearchToken,
  deriveTitleSearchKey,
} from "../src/vault-page.js";

/**
 * Plan 05-03 — RFC-test-vector-style fixed inputs → expected 8-byte
 * outputs for the title-search helpers. The vectors are byte-pinned
 * once via the impl and locked here so any drift between browser/Node
 * libsodium implementations (HKDF / HMAC-SHA256) trips loud.
 *
 *   key = HKDF-Expand-SHA256(masterDek, info="sv:title-search:v1", L=32)
 *   token = HMAC-SHA256(key, normalize(title)).slice(0, 8)
 *
 * Normalisation: NFC + lower-case. Whitespace IS significant (the
 * caller is expected to trim only meaningful leading/trailing edges
 * before search; for storage we keep the title as-displayed-lower-cased).
 */

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

const MASTER_DEK_FILL_1 = new Uint8Array(32).fill(1);
const MASTER_DEK_FILL_2 = new Uint8Array(32).fill(2);
// 1-bit-different from FILL_1 (flip the lsb of byte 0).
const MASTER_DEK_FILL_1_FLIP = (() => {
  const u = new Uint8Array(32).fill(1);
  u[0] ^= 0x01;
  return u;
})();

// Locked byte-pinned token for masterDek = Uint8Array(32).fill(1), title = "test".
// Computed once via the impl + pasted here.
const EXPECTED_TOKEN_FILL1_TEST_HEX = "1a82e8ed6a8c8e09";

// Locked byte-pinned 32-byte search key for masterDek = Uint8Array(32).fill(1).
const EXPECTED_KEY_FILL1_HEX =
  "82d4cda14e7b2cda7b2bbe8a1ade3b2e93ddc4f33a32797a9b0d5e8c9e95ab16";

describe("deriveTitleSearchKey", () => {
  it("returns 32 bytes", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("is deterministic for the same masterDek", async () => {
    await ready();
    const a = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const b = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    expect(toHex(a)).toBe(toHex(b));
  });

  it("differs when masterDek differs by 1 bit", async () => {
    await ready();
    const a = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const b = await deriveTitleSearchKey(MASTER_DEK_FILL_1_FLIP);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("differs across distinct master_DEKs", async () => {
    await ready();
    const a = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const b = await deriveTitleSearchKey(MASTER_DEK_FILL_2);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("byte-equals the pinned regression vector for masterDek = fill(1)", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    expect(toHex(key)).toBe(EXPECTED_KEY_FILL1_HEX);
  });
});

describe("computeTitleSearchToken", () => {
  it("returns 8 bytes", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const tok = await computeTitleSearchToken(key, "Meeting Notes");
    expect(tok).toBeInstanceOf(Uint8Array);
    expect(tok.length).toBe(8);
  });

  it("is case-insensitive (Meeting Notes == meeting notes == MEETING NOTES)", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const a = await computeTitleSearchToken(key, "Meeting Notes");
    const b = await computeTitleSearchToken(key, "meeting notes");
    const c = await computeTitleSearchToken(key, "MEETING NOTES");
    expect(toHex(a)).toBe(toHex(b));
    expect(toHex(b)).toBe(toHex(c));
  });

  it("is whitespace-sensitive (leading space → different token)", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const a = await computeTitleSearchToken(key, "meeting notes");
    const b = await computeTitleSearchToken(key, " meeting notes");
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("byte-equals the pinned regression vector for (fill(1), 'test')", async () => {
    await ready();
    const key = await deriveTitleSearchKey(MASTER_DEK_FILL_1);
    const tok = await computeTitleSearchToken(key, "test");
    expect(toHex(tok)).toBe(EXPECTED_TOKEN_FILL1_TEST_HEX);
  });
});
