import { ready } from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";
import { describe, expect, it } from "vitest";

import {
  decryptPage,
  encryptPage,
  extractTitle,
  type DecryptedPagePlaintext,
} from "./page-cipher";

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

const PLAIN: DecryptedPagePlaintext = {
  tiptapJson: {
    type: "doc",
    content: [
      {
        type: "heading",
        attrs: { level: 1 },
        content: [{ type: "text", text: "Hello" }],
      },
    ],
  },
  isFavorite: false,
  meta: { title: "Hello", createdAt: "2026-01-01T00:00:00.000Z" },
};

describe("page-cipher round-trip + tamper + AAD mismatch", () => {
  it("encrypt → decrypt yields original plaintext under matching AAD", async () => {
    const dek = await freshDek();
    const envelope = await encryptPage(PLAIN, dek, {
      vaultId: VAULT_ID,
      pageId: PAGE_A,
      version: 1,
      email: EMAIL,
    });
    const out = await decryptPage(
      { ciphertext: envelope.ciphertext, nonce: envelope.nonce, aadParamsJson: envelope.aadParamsJson },
      dek,
      { email: EMAIL },
    );
    expect(out.tiptapJson).toEqual(PLAIN.tiptapJson);
    expect(out.isFavorite).toBe(false);
    expect(out.meta).toEqual(PLAIN.meta);
  });

  it("24-byte nonce, unique across two encrypts", async () => {
    const dek = await freshDek();
    const a = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    const b = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    expect(a.nonce.length).toBe(24);
    expect(b.nonce.length).toBe(24);
    expect(Array.from(a.nonce)).not.toEqual(Array.from(b.nonce));
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext));
  });

  it("titleSearchToken is 8 bytes", async () => {
    const dek = await freshDek();
    const env = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    expect(env.titleSearchToken.length).toBe(8);
  });

  it("tampered ciphertext rejects (AEAD tag failure)", async () => {
    const dek = await freshDek();
    const envelope = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    const tampered = new Uint8Array(envelope.ciphertext);
    tampered.set([0x01], 0); // flip first byte to force tag failure
    await expect(
      decryptPage({ ciphertext: tampered, nonce: envelope.nonce, aadParamsJson: envelope.aadParamsJson }, dek, { email: EMAIL }),
    ).rejects.toBeTruthy();
  });

  it("cross-page AAD mismatch rejects (encrypt for pageA, decrypt as pageB)", async () => {
    const dek = await freshDek();
    const envA = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    // Manually construct aadParamsJson pointing at PAGE_B
    const wrongAadParams = JSON.stringify({ pageId: PAGE_B, vaultId: VAULT_ID, version: 1 });
    await expect(
      decryptPage({ ciphertext: envA.ciphertext, nonce: envA.nonce, aadParamsJson: wrongAadParams }, dek, { email: EMAIL }),
    ).rejects.toBeTruthy();
  });

  it("wrong masterDek rejects", async () => {
    const dek = await freshDek();
    const other = await freshDek();
    const envelope = await encryptPage(PLAIN, dek, { vaultId: VAULT_ID, pageId: PAGE_A, version: 1, email: EMAIL });
    await expect(
      decryptPage({ ciphertext: envelope.ciphertext, nonce: envelope.nonce, aadParamsJson: envelope.aadParamsJson }, other, { email: EMAIL }),
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
