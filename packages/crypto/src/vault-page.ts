import sodium from "libsodium-wrappers-sumo";

/**
 * Phase 05 Plan 01 — browser-only vault-page AAD builder + title-search
 * HKDF helpers (STUBS — full impl + parity tests in Plan 05-03).
 *
 * Sibling parity with `vault-credential.ts`. The plaintext page blob is
 * wrapped under vault_DEK with AAD =
 *   utf8(label) || sha256(lower(email)) || canonicalJson({pageId, vaultId, version})
 *
 * Canonical JSON: keys sorted lexicographically (pageId < vaultId <
 * version), no whitespace, UTF-8. Hand-rolled string template — does
 * NOT depend on `Object.keys` order semantics.
 *
 * The label is INJECTED (not hard-coded here) because the canonical
 * source of truth lives in `apps/web/src/lib/crypto/aad-labels.ts` and
 * `@simplevault/crypto` cannot import from `apps/web`. The web caller
 * passes `AAD_LABEL_VAULT_PAGE`. Plan 05-03 lands the aad-parity test
 * (apps/web) that enforces the literal is imported, never re-declared.
 *
 * Title-search helpers:
 *   - `deriveTitleSearchKey(masterDek)` — HKDF-Expand-SHA256 with info
 *     `"sv:title-search:v1"`, length 32. Per-vault deterministic key.
 *   - `computeTitleSearchToken(key, title)` — HMAC-SHA256(key, normalize(title))
 *     truncated to 8 bytes. Indexable, prefix/eq lookup, 2^-32 collision
 *     per pair (acceptable for ≤50-user scale).
 *
 * Browser-only: NOT re-exported from `node.ts` (server has no business
 * deriving page AAD or title-search keys). Enforced by parity.test.ts.
 */

export interface VaultPageAadInput {
  vaultId: string;
  pageId: string;
  version: number;
  email: string;
}

class NotImplementedError extends Error {
  constructor(name: string) {
    super(
      `@simplevault/crypto.${name}() — stub from Plan 05-01; full impl lands in Plan 05-03`,
    );
    this.name = "NotImplementedError";
  }
}

export function canonicalPageAadJson(_v: {
  vaultId: string;
  pageId: string;
  version: number;
}): string {
  // Stub — Plan 05-03 lands the canonical-JSON template + parity tests.
  // Reference shape: `{"pageId":...,"vaultId":...,"version":N}` (alpha key
  // order, no whitespace). Touch sodium.from_string in 05-03; not needed
  // for the stub.
  void sodium;
  throw new NotImplementedError("canonicalPageAadJson");
}

export function buildVaultPageAad(
  _input: VaultPageAadInput,
  _label: string,
): Uint8Array {
  throw new NotImplementedError("buildVaultPageAad");
}

/**
 * Derives the per-vault title-search key via HKDF-Expand-SHA256.
 *   key = HKDF-Expand-SHA256(masterDek, info="sv:title-search:v1", L=32)
 *
 * Plan 05-03 lands the libsodium-backed implementation + parity tests.
 */
export function deriveTitleSearchKey(
  _masterDek: Uint8Array,
): Promise<Uint8Array> {
  return Promise.reject(new NotImplementedError("deriveTitleSearchKey"));
}

/**
 * Computes the 8-byte HMAC-SHA256 title-search token.
 *   token = HMAC-SHA256(key, normalize(title)).slice(0, 8)
 *
 * Title normalisation policy (Unicode NFC + lowercase + trim) is finalised
 * in Plan 05-03 alongside the parity tests.
 */
export function computeTitleSearchToken(
  _key: Uint8Array,
  _title: string,
): Promise<Uint8Array> {
  return Promise.reject(new NotImplementedError("computeTitleSearchToken"));
}
