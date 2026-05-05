---
phase: 04-personal-vault-credentials
plan: 04-04
title: Web crypto — buildVaultCredentialAad + credential-cipher + AAD parity test (closure summary)
status: closed
closes_finding: FINDING-0026
---

# Plan 04-04 — closure summary

Three atomic commits land the browser-only AAD builder, the credential
encrypt/decrypt wrappers, and the structural FINDING-0026 closure
(no inline `"sv:..:v1|"` literal allowed in any derivation file).

## Commits

- `df9145a` test(04-04-T1): vault-credential AAD vector + credential cipher round-trip + parity (RED)
- `5d3facc` feat(04-04-T2): buildVaultCredentialAad + encryptCredential/decryptCredential (GREEN)
- `b0161f9` test(04-04-T3): aad-parity asserts label imported from aad-labels.ts (FINDING-0026 closure)

## Test counts

- `@simplevault/crypto`: 92 → 98 (+6 in `test/vault-credential-aad.test.ts`)
- `@simplevault/web`: 7 → 27 (+19; +6 cipher, +6 parity, +7 from sibling Plan 04-05 password generator)

## AAD construction (FROZEN at v1)

```
AAD = utf8(AAD_LABEL_VAULT_CREDENTIAL) || sha256(lower(email)) || canonicalJson({credentialId, vaultId, version})
```

Canonical JSON keys are alphabetically ordered (`credentialId` <
`vaultId` < `version`), no whitespace, UTF-8. Hand-rolled string
template — does NOT depend on `Object.keys` order semantics. Bumping
the v-suffix in the label is a data-migration event.

### Byte-pinned regression vector

For:
- vaultId = `00000000-0000-0000-0000-000000000001`
- credentialId = `00000000-0000-0000-0000-000000000002`
- version = `1`
- email = `Alice@Example.com` (case-mixed; lower-cased before hashing)
- label = `sv:vault-credential:v1|`

Expected emailHash (sha256 of `alice@example.com`):
`ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976`

Expected canonical JSON:
`{"credentialId":"00000000-0000-0000-0000-000000000002","vaultId":"00000000-0000-0000-0000-000000000001","version":1}`

Expected full AAD (171 bytes, hex):
```
73763a7661756c742d63726564656e7469616c3a76317c
ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
7b2263726564656e7469616c4964223a2230303030303030302d303030302d30
3030302d303030302d303030303030303030303032222c227661756c74496422
3a2230303030303030302d303030302d303030302d303030302d303030303030
303030303031222c2276657273696f6e223a317d
```

The vector was computed with this one-liner (commit: regenerate via
the same recipe if inputs change):

```bash
node -e "
const c = require('crypto');
const label = 'sv:vault-credential:v1|';
const emailHash = c.createHash('sha256').update('alice@example.com').digest();
const json = '{\"credentialId\":\"00000000-0000-0000-0000-000000000002\",\"vaultId\":\"00000000-0000-0000-0000-000000000001\",\"version\":1}';
console.log(Buffer.concat([Buffer.from(label,'utf8'), emailHash, Buffer.from(json,'utf8')]).toString('hex'));
"
```

## Browser-only invariant

`buildVaultCredentialAad` and `canonicalCredentialAadJson` are
re-exported from `packages/crypto/src/browser.ts` only. They are NOT
re-exported from `node.ts`. Enforced by:
- `packages/crypto/test/parity.test.ts` — `BROWSER_ONLY_EXPECTED` snapshot
- `packages/crypto/test/vault-credential-aad.test.ts` — runtime `await import("@simplevault/crypto/node")` assertion
- `apps/web/src/lib/crypto/credential-cipher.test.ts` — same runtime assertion

## FINDING-0026 closure mechanism

`apps/web/src/lib/crypto/aad-parity.test.ts` runs three regex-based
assertions against every file under `apps/web/src/lib/crypto/` (minus
the constants module + the two parity tests):

```ts
const matches = src.match(/"sv:[^"]+v1\|"/g) ?? [];
expect(matches).toEqual([]);
```

Any contributor who copy-pastes a label literal into a derivation file
fails this test loud at CI time, before drift can ship.

Refactors required to land this closure:
- `signup-derivations.ts`: 4 inline literals → 4 `AAD_LABEL_*` imports
- `step-up-flow.ts`: 3 inline literal references → `AAD_LABEL_MASTER` import
- `totp-wrap.ts`, `twofa-client.ts`, `enroll-totp-flow.tsx`: JSDoc mentions rephrased to use the symbolic names

Final parity-grep state — `grep -r "sv:user-master\|sv:user-recovery\|sv:user-sign-sk\|sv:user-kx-sk\|sv:user-totp\|sv:vault-credential" apps/web/src` returns hits ONLY in:
- `aad-labels.ts` (single source of truth)
- `aad-labels.test.ts` (Phase 04-01 constants spec)
- `aad-parity.test.ts` (this plan's closure spec)

## Deviation from INDEX Truth 6

INDEX Truth 6 mentions `kdf_params` as an AAD field. This plan
INTENTIONALLY excludes it from the credential AAD JSON because:

- `master_DEK` is wrapped under `master_KEK` with `kdf_params` already
  bound into THAT wrapping AAD (Phase 02). Re-binding `kdf_params`
  here would be redundant — any KDF-param downgrade fails earlier at
  the `master_DEK` unwrap step.
- Credential blobs are wrapped under `master_DEK` directly (no
  per-blob KDF), so there are no per-blob KDF params to bind.
- Keeping the canonical JSON to three keys (`credentialId`, `vaultId`,
  `version`) keeps the AAD compact and the canonical-string template
  trivially correct.

Documented for the Phase-04 INDEX update (Plan 04-12 or wherever the
INDEX is regenerated next).

## Cross-plan handoffs (live)

- Plan 04-09 imports `buildVaultCredentialAad` + `decryptCredential`
  from `@simplevault/crypto/browser` and
  `apps/web/src/lib/crypto/credential-cipher.ts`. Reads the canonical
  JSON portion (`aadParamsJson`) from the server and re-derives the
  full AAD by re-prepending label + email-hash.
- Plan 04-10 imports `encryptCredential` for the save flow.
- Plan 04-06 (typed API client) does NOT touch crypto — boundary clean.
- Phase 05 reuses the same scheme version-anchored at v1.
