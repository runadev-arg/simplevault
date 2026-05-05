import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { buildVaultPageAad, ready } from "@simplevault/crypto/browser";

import { AAD_LABEL_VAULT_PAGE } from "./aad-labels";
import { decryptPage, encryptPage, extractTitle } from "./page-cipher";

/**
 * Plan 05-03 T3 — round-trip, tamper, cross-page AAD mismatch, and
 * `extractTitle` semantics for browser-only page-cipher helpers.
 */

const VAULT_ID = "00000000-0000-0000-0000-000000000001";
const PAGE_A = "00000000-0000-0000-0000-000000000002";
const PAGE_B = "00000000-0000-0000-0000-000000000003";
const EMAIL = "alice@example.com";

async function freshDek(): Promise<Uint8Array> {
  await ready();
  return sodium.randombytes_buf(32);
}

function aadFor(pageId: string, version: number): Uint8Array {
  return buildVaultPageAad(
    { vaultId: VAULT_ID, pageId, version, email: EMAIL },
    AAD_LABEL_VAULT_PAGE,
  );
}

describe("page-cipher round-trip + tamper + AAD mismatch", () => {
  it("encrypt → decrypt yields original tiptapJsonString under matching AAD", async () => {
    const dek = await freshDek();
    const aad = aadFor(PAGE_A, 1);
    const pt = JSON.stringify({
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 1 },
          content: [{ type: "text", text: "Hello" }],
        },
      ],
    });
    const { ciphertext, nonce } = await encryptPage(pt, dek, aad);
    const out = await decryptPage(ciphertext, nonce, dek, aad);
    expect(out).toBe(pt);
  });

  it("24-byte nonce, unique across two encrypts", async () => {
    const dek = await freshDek();
    const aad = aadFor(PAGE_A, 1);
    const pt = '{"type":"doc","content":[]}';
    const a = await encryptPage(pt, dek, aad);
    const b = await encryptPage(pt, dek, aad);
    expect(a.nonce.length).toBe(24);
    expect(b.nonce.length).toBe(24);
    expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce));
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext));
  });

  it("tampered ciphertext rejects (AEAD tag failure)", async () => {
    const dek = await freshDek();
    const aad = aadFor(PAGE_A, 1);
    const blob = await encryptPage('{"type":"doc"}', dek, aad);
    const tampered = new Uint8Array(blob.ciphertext);
    tampered[0] ^= 0x01;
    await expect(
      decryptPage(tampered, blob.nonce, dek, aad),
    ).rejects.toBeTruthy();
  });

  it("cross-page AAD mismatch rejects (encrypt for pageA, decrypt as pageB)", async () => {
    const dek = await freshDek();
    const aadA = aadFor(PAGE_A, 1);
    const aadB = aadFor(PAGE_B, 1);
    const blob = await encryptPage('{"type":"doc"}', dek, aadA);
    await expect(
      decryptPage(blob.ciphertext, blob.nonce, dek, aadB),
    ).rejects.toBeTruthy();
  });

  it("wrong masterDek rejects", async () => {
    const dek = await freshDek();
    const other = await freshDek();
    const aad = aadFor(PAGE_A, 1);
    const blob = await encryptPage('{"type":"doc"}', dek, aad);
    await expect(
      decryptPage(blob.ciphertext, blob.nonce, other, aad),
    ).rejects.toBeTruthy();
  });
});

describe("extractTitle", () => {
  it("returns the first H1 text content when present", () => {
    const doc = {
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 1 },
          content: [{ type: "text", text: "Meeting Notes" }],
        },
        {
          type: "paragraph",
          content: [{ type: "text", text: "body" }],
        },
      ],
    };
    expect(extractTitle(doc)).toBe("Meeting Notes");
  });

  it("concatenates multiple text nodes inside the H1", () => {
    const doc = {
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 1 },
          content: [
            { type: "text", text: "Hello " },
            { type: "text", text: "World" },
          ],
        },
      ],
    };
    expect(extractTitle(doc)).toBe("Hello World");
  });

  it("ignores h2/h3 — only level=1 counts", () => {
    const doc = {
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 2 },
          content: [{ type: "text", text: "Subheading" }],
        },
        {
          type: "heading",
          attrs: { level: 1 },
          content: [{ type: "text", text: "Real Title" }],
        },
      ],
    };
    expect(extractTitle(doc)).toBe("Real Title");
  });

  it("returns empty string when no H1 exists", () => {
    const doc = {
      type: "doc",
      content: [
        {
          type: "paragraph",
          content: [{ type: "text", text: "no heading here" }],
        },
      ],
    };
    expect(extractTitle(doc)).toBe("");
  });

  it("returns empty string for empty doc / missing content", () => {
    expect(extractTitle({ type: "doc" })).toBe("");
    expect(extractTitle({ type: "doc", content: [] })).toBe("");
  });

  it("returns empty string when H1 has no text children", () => {
    const doc = {
      type: "doc",
      content: [{ type: "heading", attrs: { level: 1 } }],
    };
    expect(extractTitle(doc)).toBe("");
  });

  it("accepts a JSON string and parses it", () => {
    const doc = {
      type: "doc",
      content: [
        {
          type: "heading",
          attrs: { level: 1 },
          content: [{ type: "text", text: "Stringified" }],
        },
      ],
    };
    expect(extractTitle(JSON.stringify(doc))).toBe("Stringified");
  });
});
