import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ready } from "../src/argon2id.js";
import {
  buildVaultPageAad,
  canonicalPageAadJson,
} from "../src/vault-page.js";

/**
 * Plan 05-03 — byte-pinned regression vector for the browser-only
 * `buildVaultPageAad` helper. Sibling parity with 04-04 vault-credential
 * vector. Computed once via:
 *
 *   const c = require('crypto');
 *   const label = 'sv:vault-page:v1|';
 *   const emailHash = c.createHash('sha256').update('alice@example.com').digest();
 *   const json = '{"pageId":"00000000-0000-0000-0000-000000000002",'
 *              + '"vaultId":"00000000-0000-0000-0000-000000000001",'
 *              + '"version":1}';
 *   Buffer.concat([Buffer.from(label), emailHash, Buffer.from(json)]).toString('hex');
 *
 * The literal label byte-string lives ONLY in this test (regression-pin)
 * and in `apps/web/src/lib/crypto/aad-labels.ts` (single source of truth).
 * The crypto package itself never declares the label string; the caller
 * injects it.
 */

const LABEL = "sv:vault-page:v1|";
const EMAIL = "Alice@Example.com"; // case-mixed — verifies lower()
const VAULT_ID = "00000000-0000-0000-0000-000000000001";
const PAGE_ID = "00000000-0000-0000-0000-000000000002";
const VERSION = 1;

const EXPECTED_HEX =
  "73763a7661756c742d706167653a76317c" +
  "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976" +
  "7b22706167654964223a2230303030303030302d303030302d303030302d3030" +
  "30302d303030303030303030303032222c227661756c744964223a2230303030" +
  "303030302d303030302d303030302d303030302d303030303030303030303031" +
  "222c2276657273696f6e223a317d";

const EXPECTED_JSON =
  '{"pageId":"00000000-0000-0000-0000-000000000002","vaultId":"00000000-0000-0000-0000-000000000001","version":1}';

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("buildVaultPageAad — byte-pinned vector", () => {
  it("canonicalPageAadJson emits alphabetical key order (no whitespace)", async () => {
    await ready();
    const json = canonicalPageAadJson({
      vaultId: VAULT_ID,
      pageId: PAGE_ID,
      version: VERSION,
    });
    expect(json).toBe(EXPECTED_JSON);
  });

  it("canonicalPageAadJson is order-insensitive at the input level (alpha-true output)", async () => {
    await ready();
    // Reverse-ish object literal — output must STILL be alpha-ordered.
    const json = canonicalPageAadJson({
      version: VERSION,
      vaultId: VAULT_ID,
      pageId: PAGE_ID,
    });
    expect(json).toBe(EXPECTED_JSON);
  });

  it("byte-equals the pinned regression vector for fixed inputs", async () => {
    await ready();
    const aad = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    expect(toHex(aad)).toBe(EXPECTED_HEX);
  });

  it("normalises email to lower-case (case-flip → SAME bytes)", async () => {
    await ready();
    const a = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: "alice@example.com",
      },
      LABEL,
    );
    const b = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: "ALICE@EXAMPLE.COM",
      },
      LABEL,
    );
    expect(toHex(a)).toBe(toHex(b));
  });

  it("AAD changes when ANY of (vaultId, pageId, version, email) changes — 4 distinct AADs", async () => {
    await ready();
    const base = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    const dVault = buildVaultPageAad(
      {
        vaultId: "00000000-0000-0000-0000-0000000000ff",
        pageId: PAGE_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    const dPage = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: "00000000-0000-0000-0000-0000000000ff",
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    const dVer = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: 2,
        email: EMAIL,
      },
      LABEL,
    );
    const dEmail = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: "bob@example.com",
      },
      LABEL,
    );
    const all = [base, dVault, dPage, dVer, dEmail].map(toHex);
    const set = new Set(all);
    expect(set.size).toBe(5);
  });

  it("emailHash portion (after label, 32 bytes) equals sha256(lower(email))", async () => {
    await ready();
    const aad = buildVaultPageAad(
      {
        vaultId: VAULT_ID,
        pageId: PAGE_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    const labelBytes = sodium.from_string(LABEL);
    const expectedHash = sodium.crypto_hash_sha256(
      sodium.from_string(EMAIL.toLowerCase()),
    );
    const slice = aad.slice(labelBytes.length, labelBytes.length + 32);
    expect(toHex(slice)).toBe(toHex(expectedHash));
  });

  it("browser-only invariant: node.ts does NOT export buildVaultPageAad", async () => {
    const node = (await import("../src/node.js")) as Record<string, unknown>;
    expect(node.buildVaultPageAad).toBeUndefined();
    expect(node.canonicalPageAadJson).toBeUndefined();
  });
});
