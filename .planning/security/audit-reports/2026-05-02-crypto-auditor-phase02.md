# crypto-auditor — Phase 02 (Auth + Crypto core)

**Date:** 2026-05-02
**Auditor:** crypto-auditor
**Scope:** Phase 02 deliverables — `packages/crypto/`, `apps/api/src/auth/`,
`apps/api/src/crypto/`, `apps/web/src/lib/crypto/`, `apps/web/src/lib/auth/`,
`apps/web/src/app/(signup|login|authed)/`, `packages/db/src/schema/users.ts`
+ `packages/db/drizzle/0001_unusual_moonstone.sql`.
**Method:** Static read-only review; cross-reference with
`.planning/research/CRYPTO-STACK.md`, `.planning/security/THREAT-MODEL.md`,
12× phase-02 SUMMARY docs, and the symbol-parity / AEAD / hierarchy test
suite under `packages/crypto/test/`.
**Verdict:** **PASS-WITH-CONCERNS** — no Critical or High issues; two
Medium findings (drift-risk + defence-in-depth gap) and three Low/Info.
Phase 02 gate may proceed for the crypto-auditor pillar.

---

## 1. Two-secret invariant (REQ-CRYPTO-003)

**Server never sees password, secret_key plaintext, or mnemonic.**

- `apps/api/src/auth/signup/signup.dto.ts:51-72` — Zod schema is `.strict()`;
  rejects any field outside the locked 10-field envelope. Bytea fields are
  fixed-length-validated (32B verifier, 16B userArgonSalt, 32B userPubKey,
  32B recoveryInnerHash) before reaching the service.
- `apps/api/src/auth/signup/signup.service.ts:88-103` — server only persists
  the *result* of client-side derivations; no derivation of secret_key /
  master_password / mnemonic anywhere in API code.
- `apps/api/src/auth/login/login.service.ts:62-83` — login compares the
  client-supplied `argon2SecretKeyHash` (32B verifier) constant-time vs the
  stored verifier; the raw secret_key is never reconstructed server-side.
- `packages/crypto/src/node.ts:14-23` (header) + `test/parity.test.ts:53-61`
  enforces, by import barrel + snapshot test, that
  `deriveMasterKek` / `deriveRecoveryKek` / `generateMnemonic` /
  `validateMnemonic` / `mnemonicToSeed` / `computeRecoveryLookupHash` are
  **NOT** exported from the Node barrel. Any future contributor who tries
  to call them from API code gets a compile error. Strong invariant.
- Pino redaction list (`apps/api/src/app.module.ts:36-119`) names
  `password`, `secret_key`, `recoveryPhrase`, `mnemonic`, `master_kek`,
  `dek`, `kek`, every wrapped-key column, and access/refresh tokens —
  defence-in-depth even though the Zod schema rejects the fields first.

**Verdict: pass.** Two-secret invariant intact at type-system + DTO + log
layers.

## 2. Argon2id parameters

- `packages/crypto/src/argon2id.ts:17-31` — `ARGON2_DEFAULT_PARAMS = m=64
  MiB / t=3 / p=1`; `ARGON2_FLOOR_PARAMS = m=19 MiB (19456 KiB) / t=2 / p=1`.
  Matches OWASP Password Storage Cheat Sheet 2024 minimum.
- `apps/api/src/crypto/crypto.service.ts:106-113` — boot-time floor check;
  the API container will refuse to start if env-configured params drop
  below the floor. CALIBRATE-or-die posture.
- `apps/api/src/auth/signup/signup.service.ts:37-50` — request-time floor
  check via `validateArgon2ParamsAboveFloor()`; signup with downgraded
  params returns 400 + emits `auth.signup.fail reason=kdf_downgrade`.
- `packages/crypto/src/calibrate.ts:33-85` — calibration target 750ms ±
  250ms (within CRYPTO-STACK.md §2 target band); bounded by FLOOR below
  and 256 MiB cap above; never returns weaker than floor.
- AAD binds the params (see §3) — DB rewrite of `argon2_params` to a
  weaker tuple breaks every AEAD unwrap.
- Per-user `argon2_params` stored in `users.argon2_params` (jsonb,
  `users.ts:43-45`) for re-derivation on each login.

**Verdict: pass.** Calibration + floor + AAD-binding + per-user persistence
all aligned.

## 3. AAD binding and label freeze

**Per-user binder = `SHA256(lower(email))` — frozen by 02-10 §2 + 02-11.**

- `apps/web/src/lib/crypto/aad-labels.ts:14-17` — module-level constants
  for the four FROZEN labels: `sv:user-master:v1|`, `sv:user-recovery:v1|`,
  `sv:user-sign-sk:v1|`, `sv:user-kx-sk:v1|`. Header explicitly says "Pull
  from this module — never repeat literals."
- `apps/web/src/lib/crypto/login-derivations.ts:43-49` — login imports the
  constants and produces AAD via `aadFor(label, params, emailHash)`.
- `apps/web/src/lib/crypto/signup-derivations.ts:152, 157, 162, 167` —
  signup uses **inline string literals** (`"sv:user-master:v1|"` etc.)
  rather than the centralised constants. **See FINDING-0026 (Medium):**
  byte-equal today, but a future single-side rename will silently break
  every existing wrap. The aad-labels.ts header documents the contract;
  the signup site violates it.
- `packages/crypto/src/key-hierarchy.ts:71-83` (`encodeAad`) — wire format
  is fixed: `version_byte (0x01) || memoryKiB_be32 || iterations_be32 ||
  parallelism_be32 || contextId`. Argon2 params are part of the AAD, so
  KDF-downgrade (operator rewrites `users.argon2_params`) will tag-fail
  every unwrap.

**Verdict: pass on byte-equality today; medium drift-risk** (FINDING-0026).

## 4. BIP-39

- `packages/crypto/src/bip39.ts:23-24, 31-49` — 256-bit entropy (24 words +
  8-bit checksum), entropy from `sodium.randombytes_buf(32)` (not
  `bip39.generateMnemonic()` which would pull `crypto.randomBytes` and
  break browser parity).
- `packages/crypto/src/bip39.ts:55-57, 65-73` — uses `bip39.validateMnemonic`
  for checksum validation; `mnemonicToSeed` uses the spec-defined
  PBKDF2-HMAC-SHA512 2048 rounds via the `bip39` library.
- `packages/crypto/src/bip39.ts:85-92` — canonicaliser (NFKD + lowercase
  + collapse internal whitespace) is applied **only** to the lookup-hash
  computation, **not** to the seed input — comment explicitly disclaims
  reusing it for `mnemonicToSeed`. Correct (BIP-39 spec normalises NFKD
  internally during seed derivation).
- `apps/web/src/app/signup/steps/RecoveryPhraseConfirmStep.tsx:33-61` —
  4-word challenge with positions chosen via `sodium.randombytes_uniform`
  (unbiased rejection sampling); on any wrong answer, `back-to-recovery-
  reveal` re-rolls the indices, so a brute-force run against a fixed
  challenge is not possible. Real verification, not a UI gate.
- `apps/web/src/app/signup/steps/RecoveryPhraseRevealStep.tsx:18-24` — same
  unbiased index picker for initial challenge.
- Server-side recovery secret split: client computes
  `sha256(NFKD(canonical(mnemonic)))` → server applies the outer
  `HMAC-SHA256(SERVER_RECOVERY_HMAC_SECRET, innerSha)` (signup.service.ts:52
  + crypto.service.ts:122-124). Mnemonic itself never reaches the server;
  the `users.recovery_hmac` UNIQUE index lookup is forgery-resistant
  without the server secret.

**Verdict: pass.**

## 5. Constant-time comparisons

- `apps/api/src/common/timing-floor.ts:41-44` — `constantTimeEqual32` uses
  `node:crypto.timingSafeEqual` after a length check; rejects len mismatch
  before the timing primitive (acceptable — the alternative would mean
  the function leaks "wrong length" by NOT timing-comparing).
- `apps/api/src/auth/login/login.service.ts:75-79` — login *always* runs
  the constant-time path: when no user row, `dummyHash()` (deterministic
  derivative of `JWT_SECRET`) is substituted. The wall-time of the
  user-not-found path is indistinguishable from the wrong-password path
  modulo DB-lookup jitter — exactly the timing-floor pattern in
  CRYPTO-STACK §10.
- `apps/api/src/crypto/crypto.service.ts:137-140` — generic
  `constantTimeEqual()` for future verifier comparisons.
- `packages/crypto/src/argon2id.ts:98-107` — `verify()` uses
  `sodium.memcmp` (constant-time on libsodium side).
- No `===` or `Buffer.compare` on secret-derived values found in the auth
  surface.

**Verdict: pass.**

## 6. Sealed-box / symbol parity

- `packages/crypto/src/sealed-box.ts:89-126` — `generateKxKeyPair` /
  `sealedBoxSeal` / `sealedBoxOpen` use libsodium `crypto_box_*` (X25519
  + ChaCha20-Poly1305 inside seal). Sender-anonymity property documented
  + load-bearing rationale for shared-vault wrapping.
- `packages/crypto/src/node.ts:74-80` re-exports the sealed-box surface —
  appropriate (no secret-handling input).
- `packages/crypto/src/browser.ts:7-13` re-exports everything via `export *`.
- `packages/crypto/test/parity.test.ts:25-90` snapshots the deliberate
  divergence: BROWSER_ONLY = `computeRecoveryLookupHash`, `deriveMasterKek`,
  `deriveRecoveryKek`, `generateMnemonic`, `generateMnemonicAsync`,
  `mnemonicToSeed`, `validateMnemonic`. Any drift will fail the test.

**Verdict: pass.** Symbol-parity guarantee enforced by passing test.

## 7. `GET /auth/params`

- `apps/api/src/auth/login/login.controller.ts:42-58` — returns global
  `argon2Params` + global `serverArgonSalt`. No per-user data, no email
  echo, no existence-check; identical body for every caller.
- The `serverArgonSalt` is operator-managed (env var, validated in
  `crypto.service.ts:78-89`), at-least 16 bytes, treated as an
  anti-enumeration server pepper rather than a per-user secret. Plan 11
  load-bearing decision documented in 02-PHASE-SUMMARY.md §4.
- Throttled via `RateLimits.authParamsIp` to prevent crawl-spam.

**Verdict: pass.** Anti-enumeration property preserved.

## 8. Memory hygiene / wipe semantics

- `apps/web/src/lib/auth/key-store.ts:60-67` — `wipe()` zero-overwrites
  every Uint8Array via `.fill(0)` then drops the Map.
- `apps/web/src/app/signup/steps/SubmittingStep.tsx:82-90` — calls
  `keyStore.wipe()` AND additionally explicit `.fill(0)` on local
  references after the network call returns 201.
- `apps/web/src/app/signup/steps/SubmittingStep.tsx:96-103` — error-path
  also wipes (try/catch ignored — best-effort).
- `apps/web/src/app/signup/page.tsx:166-173` — unmount cleanup wipes via
  lazy import.
- `apps/web/src/app/login/page.tsx:168-180` — error path wipes
  `derivedRefs.{masterKek,masterDek,signingSk,kxSk}` and the typed
  `secretKey` Uint8Array, then full `keyStore.wipe()`.
- `apps/web/src/lib/auth/auth-context.tsx:79-89` — logout always wipes
  even if API logout call rejects.

Strings (master_password, mnemonic) cannot be reliably zeroed in JS — the
key-store header documents this and recommends short scopes; both pages
keep the password in component state only until derivation completes,
then drop the reference (best-effort; engine may retain copies).

**Verdict: pass.** Best-effort wipe coverage on every flow exit point.
See FINDING-0029 (Low) for one minor hardening.

## 9. `node:crypto` purity in web bundle

- `grep -rn 'node:crypto|require..crypto.|from .crypto.' apps/web/src` →
  zero matches.
- `grep -rn 'node:crypto|...' packages/crypto/src` → zero matches; package
  uses `libsodium-wrappers-sumo` and `@noble/hashes` only.
- Client crypto entry is `@simplevault/crypto/browser` (verified at
  `apps/web/src/lib/crypto/signup-derivations.ts:1-13` +
  `login-derivations.ts:1-9` — both import from the `/browser`
  conditional-exports leaf).
- The 02-04 SUMMARY documents a regex-based verification step for
  `dist/browser.js`; the package's TypeScript-only sources are
  `node:crypto`-clean by inspection. No regression introduced in the
  Phase-02 deliverables.

**Verdict: pass** (pending ongoing CI guard — see Info I1).

## 10. CSP for libsodium WASM

- `apps/web/src/lib/csp.ts:17-19` —
  `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'`.
  No `'unsafe-inline'`, no `'unsafe-eval'`. `'wasm-unsafe-eval'` is the
  narrow directive that allows WebAssembly compilation only — does NOT
  relax JS eval.
- Other directives are tight: `default-src 'self'`, `frame-ancestors
  'none'`, `frame-src 'none'`, `object-src 'none'`, `base-uri 'none'`.
- HSTS 1y + preload, COOP/CORP same-origin, X-Frame-Options DENY,
  no-referrer, no Permissions-Policy access for sensors. Solid baseline
  for the auth surface.

**Verdict: pass.**

## 11. AEAD / wire format

- `packages/crypto/src/aead.ts:38-54` — `XChaCha20-Poly1305-IETF`,
  fresh 24-byte nonce per call via `sodium.randombytes_buf(NONCE_BYTES)`,
  AAD mandatory in the function signature (callers must explicitly pass
  `new Uint8Array(0)` for "no AAD" — type-enforced explicitness).
- 32-byte key-length assertion at every entry; mismatched-key bytes
  throw before the primitive runs.
- `aead.test.ts` and `key-hierarchy.test.ts` cover round-trips +
  tag-mismatch on tampered AAD / ciphertext / nonce.
- Signup wrap sites pack as `nonce(24B) || ciphertext+tag` — DB blob shape
  decoded symmetrically at login (`unpackWrapped` slices the first 24B
  off).

**Verdict: pass.**

## 12. Refresh-token rotation + family revocation (REQ-AUTH-005)

(Out of crypto-auditor scope strictly, but cross-cuts wrapped-key flow.)

- `apps/api/src/auth/sessions/session.service.ts:131-156` — login mints
  a 32-byte random refresh token, stores BLAKE2b-256 hash, fresh
  `family_id`, 30-day TTL, `__Host-refresh` cookie.
- `session.service.ts:163-237` — rotate path uses `SELECT ... FOR UPDATE`;
  reuse is detected if `used_at` is non-null and triggers family-revoke
  before throwing.
- `auth/refresh/refresh.controller.ts:59-71` — refresh-reuse audit-emits
  `auth.refresh.reuse_detected` (Phase 10 hash-chain ingestion shape).
- Cookie attributes: `httpOnly`, `secure`, `sameSite: strict`, `path: /`.
  `__Host-` prefix forces same-origin deployment and Path=/.

**Verdict: pass.** Crypto-auditor signs off on the refresh material
(token entropy, hashing, secure storage); auth-flow-auditor will
separately verify the protocol semantics.

## 13. Schema review (`packages/db/src/schema/users.ts` +
`drizzle/0001_unusual_moonstone.sql`)

- Every secret-bearing column is `bytea NOT NULL`:
  `argon2_secret_key_hash`, `server_argon_salt`, `user_argon_salt`,
  `wrapped_master_dek`, `wrapped_master_dek_recovery`, `recovery_hmac`,
  `wrapped_user_signing_sk`, `wrapped_user_kx_sk`. Public key
  `user_pub_key` also `bytea NOT NULL`.
- `argon2_params` is `jsonb NOT NULL` — typed by Drizzle as
  `{memoryKiB, iterations, parallelism: 1}`; ANY DB-side mutation breaks
  the AEAD tag (params bound into AAD, see §3).
- `users_recovery_hmac_idx` is UNIQUE — appropriate, the HMAC is
  256-bit; brute-force-collision is infeasible. The unique index allows
  O(log n) recovery-flow lookup without scanning.
- `users_email_lower_idx` UNIQUE on `lower(email)` — case-insensitive
  uniqueness, single source of truth for the email canonicalisation rule.
- `0001_unusual_moonstone.sql:26` drops the prior `users_email_unique`
  constraint, replaced by the lower(email) functional unique index.

**Verdict: pass.** Schema mirrors the wire-shape contract exactly.

---

## Regression check vs Phase-01 controls

| Control | Phase-01 status | Phase-02 status |
|---|---|---|
| CSP nonce-per-request, no `unsafe-*` | OK | OK; added `wasm-unsafe-eval` for libsodium (narrow scope) |
| helmet + CORS allowlist + ValidationPipe | OK | OK; new auth controllers use `Throttle` decorator + Zod-strict DTOs |
| Pino redaction list | OK | EXTENDED — 50+ new auth/crypto field paths added (`app.module.ts:36-119`) |
| `internal: true` backend network | OK | unchanged |
| Container hardening (cap_drop ALL, non-root, RO rootfs) | OK | unchanged |
| Lockfile + `--frozen-lockfile` + `pnpm audit` H/Critical block | OK | unchanged; new deps `bip39@3.x`, `libsodium-wrappers-sumo@0.7.15`, `@noble/hashes@1.6.x` are pinned |

**No regressions.**

---

## Findings summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 2 |
| Info | 1 |

See `.planning/security/FINDINGS.md` for FINDING-0026..FINDING-0030.

---

## Verdict

**PASS-WITH-CONCERNS**

No Critical or High issues found. The Phase 02 cryptographic implementation
correctly upholds the two-secret invariant, AAD-binding, Argon2id floor +
AAD-pinning, BIP-39 24-word entropy, constant-time login with timing-floor,
sealed-box symbol parity, server-side mnemonic-blindness via inner-sha256
+ outer-HMAC split, in-memory-only key-store with wipe(), and CSP that
narrowly admits libsodium WASM without weakening JS execution policy.

Two Medium findings (label drift-risk in signup-derivations.ts;
defence-in-depth length check missing on `secretKey` in `deriveMasterKek`)
are tracked as OPEN but **do not block the Phase 02 gate** (gate rule:
no Critical/High open). Operator-discretion fix in Phase 02 follow-up or
defer to Phase 04.

Phase 02 crypto-auditor pillar: **PASS-WITH-CONCERNS**.
