import sodium from "libsodium-wrappers-sumo";

/**
 * Phase 05 Plan 03 — browser-only vault-page AAD builder + title-search
 * HKDF helpers. Sibling parity with `vault-credential.ts`.
 *
 * The plaintext page blob is wrapped under master_DEK (per-vault DEK in
 * future multi-vault setups) with AAD =
 *   utf8(label) || sha256(lower(email)) || canonicalJson({pageId, vaultId, version})
 *
 * Canonical JSON: keys sorted lexicographically (pageId < vaultId <
 * version), no whitespace, UTF-8. Hand-rolled string template — does
 * NOT depend on `Object.keys` order semantics.
 *
 * The label is INJECTED (not hard-coded here) because the canonical
 * source of truth lives in `apps/web/src/lib/crypto/aad-labels.ts` and
 * `@simplevault/crypto` cannot import from `apps/web`. The web caller
 * passes `AAD_LABEL_VAULT_PAGE`. The aad-parity test (apps/web)
 * enforces that the literal is imported, never re-declared.
 *
 * Title-search helpers:
 *   - `deriveTitleSearchKey(masterDek)` — HKDF-Expand-SHA256 with info
 *     `"sv:title-search:v1"`, length 32. Per-vault deterministic key.
 *     master_DEK is treated as the PRK directly (no Extract step) since
 *     it is already a uniformly-random 32-byte secret from the master
 *     key hierarchy.
 *   - `computeTitleSearchToken(key, title)` — HMAC-SHA256(key,
 *     normalize(title)) truncated to 8 bytes. Normalisation: NFC +
 *     lower-case (whitespace IS significant). Indexable, prefix/eq
 *     lookup, ~2^-32 collision per pair (acceptable for ≤50-user scale).
 *
 * Browser-only: NOT re-exported from `node.ts` (server has no business
 * deriving page AAD or title-search keys). Enforced by parity.test.ts.
 *
 * `await ready()` (libsodium init) is the caller's responsibility.
 */

export interface VaultPageAadInput {
  vaultId: string;
  pageId: string;
  version: number;
  email: string;
}

export function canonicalPageAadJson(v: {
  vaultId: string;
  pageId: string;
  version: number;
}): string {
  // Alphabetical key order: pageId < vaultId < version. No whitespace.
  return (
    `{"pageId":${JSON.stringify(v.pageId)},` +
    `"vaultId":${JSON.stringify(v.vaultId)},` +
    `"version":${v.version}}`
  );
}

export function buildVaultPageAad(
  input: VaultPageAadInput,
  label: string,
): Uint8Array {
  // Defensive — libsodium must be ready for crypto_hash_sha256.
  if (!sodium.crypto_hash_sha256) {
    throw new Error(
      "buildVaultPageAad: libsodium not ready — await ready() first",
    );
  }
  const labelBytes = sodium.from_string(label);
  const emailLower = input.email.trim().toLowerCase();
  const emailHash = sodium.crypto_hash_sha256(sodium.from_string(emailLower));
  const json = canonicalPageAadJson({
    vaultId: input.vaultId,
    pageId: input.pageId,
    version: input.version,
  });
  const jsonBytes = sodium.from_string(json);
  const out = new Uint8Array(
    labelBytes.length + emailHash.length + jsonBytes.length,
  );
  out.set(labelBytes, 0);
  out.set(emailHash, labelBytes.length);
  out.set(jsonBytes, labelBytes.length + emailHash.length);
  return out;
}

/**
 * HKDF-Expand-SHA256 per RFC 5869 §2.3.
 *   T(0) = empty
 *   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
 *   OKM  = T(1) || T(2) || ... truncated to L
 *
 * libsodium-wrappers-sumo does not expose `crypto_kdf_hkdf_sha256_expand`
 * in the JS bindings, so we compose it from `crypto_auth_hmacsha256_*`.
 * PRK MUST be exactly 32 bytes (HMAC-SHA256 key length) — typical for a
 * master_DEK from the SimpleVault key hierarchy.
 */
function hkdfExpandSha256(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (prk.length !== 32) {
    throw new Error("hkdfExpandSha256: PRK must be 32 bytes (HMAC-SHA256 key)");
  }
  const hashLen = 32;
  const N = Math.ceil(length / hashLen);
  if (N === 0 || N > 255) {
    throw new Error("hkdfExpandSha256: length out of range (1..255*32)");
  }
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let pos = 0;
  for (let i = 1; i <= N; i++) {
    const state = sodium.crypto_auth_hmacsha256_init(prk);
    if (prev.length) {
      sodium.crypto_auth_hmacsha256_update(state, prev);
    }
    sodium.crypto_auth_hmacsha256_update(state, info);
    sodium.crypto_auth_hmacsha256_update(state, new Uint8Array([i]));
    prev = sodium.crypto_auth_hmacsha256_final(state);
    const take = Math.min(hashLen, length - pos);
    out.set(prev.subarray(0, take), pos);
    pos += take;
  }
  return out;
}

const TITLE_SEARCH_HKDF_INFO = "sv:title-search:v1";

/**
 * Derives the per-vault title-search key via HKDF-Expand-SHA256.
 *   key = HKDF-Expand-SHA256(masterDek, info="sv:title-search:v1", L=32)
 */
export async function deriveTitleSearchKey(
  masterDek: Uint8Array,
): Promise<Uint8Array> {
  if (!sodium.crypto_auth_hmacsha256_init) {
    throw new Error(
      "deriveTitleSearchKey: libsodium not ready — await ready() first",
    );
  }
  const info = sodium.from_string(TITLE_SEARCH_HKDF_INFO);
  return hkdfExpandSha256(masterDek, info, 32);
}

/**
 * Computes the 8-byte HMAC-SHA256 title-search token.
 *   token = HMAC-SHA256(key, normalize(title)).slice(0, 8)
 *
 * Title normalisation: Unicode NFC + lower-case. Whitespace is significant
 * (the caller decides whether to trim). The key MUST be 32 bytes (output
 * of `deriveTitleSearchKey`).
 */
export async function computeTitleSearchToken(
  key: Uint8Array,
  title: string,
): Promise<Uint8Array> {
  if (!sodium.crypto_auth_hmacsha256) {
    throw new Error(
      "computeTitleSearchToken: libsodium not ready — await ready() first",
    );
  }
  if (key.length !== 32) {
    throw new Error("computeTitleSearchToken: key must be 32 bytes");
  }
  const normalised = title.normalize("NFC").toLowerCase();
  const tag = sodium.crypto_auth_hmacsha256(
    sodium.from_string(normalised),
    key,
  );
  return tag.subarray(0, 8);
}
