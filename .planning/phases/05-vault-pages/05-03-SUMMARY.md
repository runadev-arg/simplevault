---
phase: 05-vault-pages
plan: 05-03
title: Crypto — buildVaultPageAad + page-cipher + parity extension + title-search vectors
status: closed
wave: 2
---

# Plan 05-03 — Summary

## Outcome

Browser-only crypto helpers for Phase 05 vault-pages. Sibling parity with 04-04's `buildVaultCredentialAad` + `credential-cipher.ts`.

## Landed

### `packages/crypto/src/vault-page.ts` (full impl, was 05-01 stubs)
- `canonicalPageAadJson({pageId, vaultId, version})` — hand-rolled alpha-key template (`pageId < vaultId < version`), no whitespace, no `Object.keys` order dependency.
- `buildVaultPageAad(input, label)` — `utf8(label) || sha256(lower(email)) || canonicalJson(...)`. Label injected by caller (single-source-of-truth in `aad-labels.ts`).
- `deriveTitleSearchKey(masterDek)` — HKDF-Expand-SHA256 (RFC 5869 §2.3, composed from `crypto_auth_hmacsha256_*` because libsodium-wrappers-sumo does not expose `crypto_kdf_hkdf_sha256_expand` in JS), `info="sv:title-search:v1"`, `L=32`.
- `computeTitleSearchToken(key, title)` — HMAC-SHA256(key, NFC+lower(title)).slice(0,8).

### `apps/web/src/lib/crypto/page-cipher.ts`
- `encryptPage(tiptapJsonString, masterDek, aad) → {ciphertext, nonce}` (XChaCha20-Poly1305 IETF, 24-byte random nonce per encrypt).
- `decryptPage(ciphertext, nonce, masterDek, aad) → tiptapJsonString`.
- `buildVaultPageAad(input)` thin wrapper that injects `AAD_LABEL_VAULT_PAGE`.
- `extractTitle(tiptapJson)` — first `heading.level=1` text content (concatenated); `""` fallback.

### Tests added
- `packages/crypto/test/vault-page-aad.test.ts` (7 tests) — byte-pinned vector, alpha-key order, email lower-case parity, 4-axis distinctness (vault/page/version/email), browser-only invariant.
- `packages/crypto/test/title-search.test.ts` (9 tests) — 32-byte key (deterministic, 1-bit-diff sensitivity, pinned hex), 8-byte token (case-insensitive, whitespace-sensitive, pinned hex).
- `apps/web/src/lib/crypto/page-cipher.test.ts` (12 tests) — round-trip, tamper, cross-page AAD mismatch, wrong-DEK, extractTitle (7 cases).
- `apps/web/src/lib/crypto/aad-parity.test.ts` extended (5 → 8 tests) — `page-cipher.ts` added to FILES audit; recursive walk of `apps/web/src` bans inline `"sv:vault-page:v1|"` literal outside aad-labels.ts.

## Pinned vectors (locked, byte-equal)

```
buildVaultPageAad(VAULT=…001, PAGE=…002, version=1, email=Alice@Example.com), label="sv:vault-page:v1|":
  73763a7661756c742d706167653a76317c
  ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
  7b22706167654964223a2230303030...303030322c227661756c744964223a22
  …01222c2276657273696f6e223a317d

deriveTitleSearchKey(masterDek = Uint8Array(32).fill(1)):
  f28b525f55d6a43b0044b6c967ee9e69f2a7de78eb031c1a52cf9b3cea03c10a

computeTitleSearchToken(↑key, "test"):
  cd205b72e4ecceac
```

## Test counts

| Suite | Before | After |
|---|---|---|
| `@simplevault/crypto` | 98 | 114 |
| `apps/web` `aad-parity.test.ts` | 5 | 8 |
| `apps/web` `page-cipher.test.ts` | — | 12 |

## Grep gate

```
grep -rn "sv:vault-page" apps/web/src
→ aad-labels.ts (source of truth)
→ aad-labels.test.ts (pinned-value spec)
→ aad-parity.test.ts (parity gate; literal in assertion + regex)
```

No inline duplicates anywhere else.

## Vitest pin

`packages/crypto/package.json` bumped from `^2.1.8` → `^2.1.9` (matches `apps/web`).

## Commits

1. `66a1968` — `test(05-03-T1): RED specs for buildVaultPageAad + title-search vectors`
2. `a1ce7f0` (deviation — see below) — contains the GREEN impl + parity-test extension that should have been a standalone `feat(05-03-T2)` commit.
3. `74a2982` — `test(05-03-T3): RED page-cipher round-trip + extractTitle specs`
4. `0680845` — `feat(05-03-T3): GREEN page-cipher + extractTitle for vault pages`

## Deviations

- **T2 GREEN was swept into a sibling commit.** While staging the T2 GREEN files, a parallel sibling agent (Plan 05-04 T2) committed concurrently and the resulting commit `a1ce7f0` (titled `feat(05-04-T2)`) absorbed three 05-03 files: `packages/crypto/src/vault-page.ts`, `packages/crypto/test/title-search.test.ts` (pinned-vector update), and `apps/web/src/lib/crypto/aad-parity.test.ts`. The CONTENT is correct and all gates pass; only the commit attribution is off. No revert was attempted (destructive; would conflict with parallel sibling work).
- T3 was executed as RED + GREEN even though the plan marks it `type="auto"` — kept the TDD discipline because the user prompt specified RED-then-GREEN per task.
- T3 signature was simplified to match the user prompt (`encryptPage(tiptapJsonString, masterDek, aad)`) rather than the plan-file's richer `encryptPage({tiptapJson, isFavorite, ...meta}, masterDek, {vaultId, pageId, version, email})`. Title-search-token computation and `aadParamsJson` round-tripping now belong to the consumer (Plan 05-05 page editor flow).
- HKDF-Expand was hand-rolled from `crypto_auth_hmacsha256_*` because libsodium-wrappers-sumo does not expose `crypto_kdf_hkdf_sha256_expand` in its JS bindings. RFC 5869 §2.3 implementation; PRK fixed at 32 bytes (matches master_DEK).
