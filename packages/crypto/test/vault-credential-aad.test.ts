import { describe, expect, it } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { ready } from "../src/argon2id.js";
import {
  buildVaultCredentialAad,
  canonicalCredentialAadJson,
} from "../src/vault-credential.js";

/**
 * Plan 04-04 — byte-pinned regression vector for the browser-only
 * `buildVaultCredentialAad` helper. The vector was computed once via:
 *
 *   const c = require('crypto');
 *   const label = 'sv:vault-credential:v1|';
 *   const emailHash = c.createHash('sha256')
 *     .update('alice@example.com').digest();
 *   const json = '{"credentialId":"00000000-0000-0000-0000-000000000002",'
 *              + '"vaultId":"00000000-0000-0000-0000-000000000001",'
 *              + '"version":1}';
 *   Buffer.concat([Buffer.from(label), emailHash, Buffer.from(json)])
 *     .toString('hex');
 *
 * The literal label byte-string lives ONLY in this test (regression-pin)
 * and in `apps/web/src/lib/crypto/aad-labels.ts` (single source of truth).
 * The crypto package itself never declares the label string; the caller
 * injects it.
 */

const LABEL = "sv:vault-credential:v1|";
const EMAIL = "Alice@Example.com"; // case-mixed — verifies lower()
const VAULT_ID = "00000000-0000-0000-0000-000000000001";
const CREDENTIAL_ID = "00000000-0000-0000-0000-000000000002";
const VERSION = 1;

const EXPECTED_HEX =
  "73763a7661756c742d63726564656e7469616c3a76317c" +
  "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976" +
  "7b2263726564656e7469616c4964223a2230303030303030302d303030302d30" +
  "3030302d303030302d303030303030303030303032222c227661756c74496422" +
  "3a2230303030303030302d303030302d303030302d303030302d303030303030" +
  "303030303031222c2276657273696f6e223a317d";

const EXPECTED_JSON =
  '{"credentialId":"00000000-0000-0000-0000-000000000002","vaultId":"00000000-0000-0000-0000-000000000001","version":1}';

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("buildVaultCredentialAad — byte-pinned vector", () => {
  it("canonicalCredentialAadJson emits alphabetical key order (no whitespace)", async () => {
    await ready();
    const json = canonicalCredentialAadJson({
      vaultId: VAULT_ID,
      credentialId: CREDENTIAL_ID,
      version: VERSION,
    });
    expect(json).toBe(EXPECTED_JSON);
  });

  it("byte-equals the pinned regression vector for fixed inputs", async () => {
    await ready();
    const aad = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    expect(toHex(aad)).toBe(EXPECTED_HEX);
  });

  it("normalises email to lower-case (case-flip → SAME bytes)", async () => {
    await ready();
    const a = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: VERSION,
        email: "alice@example.com",
      },
      LABEL,
    );
    const b = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: VERSION,
        email: "ALICE@EXAMPLE.COM",
      },
      LABEL,
    );
    expect(toHex(a)).toBe(toHex(b));
  });

  it("changing version yields different AAD (same length)", async () => {
    await ready();
    const a = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: 1,
        email: EMAIL,
      },
      LABEL,
    );
    const b = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: 2,
        email: EMAIL,
      },
      LABEL,
    );
    expect(a.length).toBe(b.length);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("changing vaultId yields different AAD", async () => {
    await ready();
    const a = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    const b = buildVaultCredentialAad(
      {
        vaultId: "00000000-0000-0000-0000-0000000000ff",
        credentialId: CREDENTIAL_ID,
        version: VERSION,
        email: EMAIL,
      },
      LABEL,
    );
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it("emailHash portion (bytes 23..55) equals sha256(lower(email))", async () => {
    await ready();
    const aad = buildVaultCredentialAad(
      {
        vaultId: VAULT_ID,
        credentialId: CREDENTIAL_ID,
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

  it("browser-only invariant: node.ts does NOT export buildVaultCredentialAad", async () => {
    const node = (await import("../src/node.js")) as Record<string, unknown>;
    expect(node.buildVaultCredentialAad).toBeUndefined();
    expect(node.canonicalCredentialAadJson).toBeUndefined();
  });
});
