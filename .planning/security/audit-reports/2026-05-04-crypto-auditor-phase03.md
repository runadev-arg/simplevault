# crypto-auditor — Phase 03 (2FA + sessions)

**Date:** 2026-05-04
**Auditor:** crypto-auditor
**Scope:** Phase 03 deliverables — `packages/crypto/src/totp.ts` (+ barrel
purity in `browser.ts` / `node.ts` / `index.ts`), `packages/crypto/test/totp.test.ts`,
`apps/api/src/twofa/{totp,webauthn,step-up,methods}/`,
`apps/api/src/auth/jwt/{jwt.service.ts,jwt-auth.guard.ts,public.decorator.ts}`,
`packages/db/src/schema/{webauthn_credentials,webauthn_challenges,totp_credentials}.ts`,
`apps/web/src/lib/crypto/{aad-labels,totp-wrap}.ts` +
`apps/web/src/lib/api/twofa-client.ts` (defence-in-depth boundary).
**Method:** Static read-only review; cross-reference with
`.planning/phases/03-2fa-sessions/03-INDEX.md` (Truths 1-20, Key Links 1-13),
`03-VERIFICATION.md`, plans 03-{02,03,04}-SUMMARY, the parity / RFC-6238
test suite, and the `@simplewebauthn/server@11.0.0` source under
`node_modules/.pnpm/@simplewebauthn+server@11.0.0/`.
**Verdict:** **PASS-WITH-CONCERNS** — no Critical or High issues; one Low
(client AAD trust pattern) and two Info (secret-grep noise in pino
redaction list, simplewebauthn challenge entropy via WebCrypto rather than
`node:crypto`). Phase 03 gate may proceed for the crypto-auditor pillar.

---

## Per-gate-item verification (Phase 03 INDEX "Security gate" / Key Links)

| # | Gate item | Result | Evidence (1-line) |
|---|---|---|---|
| 1 | TOTP secret encryption is browser-only — server-side grep clean for `master_DEK`/`master_kek`/`computeTotpStep`/`verifyTotpCandidate` (only doc-string assertions allowed) | **PASS** | All 6 server-side hits are doc-string + pino-redaction list; zero call sites or imports — see grep table below. |
| 2 | AAD label `"sv:user-totp:v1\|"` follows Phase 02 scheme (per-user binder = `SHA256(lower(email))`) | **PASS** | `apps/web/src/lib/crypto/aad-labels.ts:25` defines the constant; `totp-wrap.ts:40-50` builds AAD = `encodeAad(argon2Params, label \|\| sha256(lower(email)))`, identical shape to Phase 02. |
| 3 | WebAuthn challenge nonces = 32 random bytes from `crypto.randomBytes` (or libsodium `randombytes_buf`) | **PASS** | `@simplewebauthn/server@11.0.0/esm/helpers/generateChallenge.js` allocates `new Uint8Array(32)` and fills via `WebCrypto.getRandomValues` (CSPRNG-grade; same source as `crypto.randomBytes` on Node 18+). Schema comment in `packages/db/src/schema/webauthn_challenges.ts:14` documents the contract; `bytea("challenge")` round-trips the bytes verbatim. |
| 4 | Challenge consume is atomic single-statement `DELETE … RETURNING` | **PASS** | `webauthn-register.service.ts:168-172` and `webauthn-auth.service.ts:147-151` both use `this.db.db.execute(sql\`DELETE FROM webauthn_challenges WHERE user_id = ${userId} AND kind = '...' RETURNING challenge, expires_at\`)` — no SELECT-then-DELETE anywhere. |
| 5 | `@simplewebauthn/server` v11+ called with **explicit** `expectedRPID` and `expectedOrigin` | **PASS** | Pinned `@simplewebauthn/server@11.0.0`. `webauthn-register.service.ts:186-192` passes both `expectedOrigin: this.origin` + `expectedRPID: this.rpId` + `requireUserVerification: true`; same triplet at `webauthn-auth.service.ts:190-202`. Boot-time fail-fast for `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` in production at `webauthn-register.service.ts:63-66`. |
| 6 | WebAuthn counter regression check (`new <= stored && stored > 0` → reject) | **PASS** | `webauthn-auth.service.ts:222`: `if (cred.counter > 0 && newCounter <= cred.counter) { failAudit('counter_regression'); throw verificationFailed(); }`. Stored-counter-zero exception (sync passkeys that never increment) documented inline. |
| 7 | Step-up JWT signed with the SAME key as access JWT (no split-secret confusion) | **PASS** | `step-up-jwt.service.ts:56` — `this.secret = this.jwt.exposeSecret()`; the `purpose:"2fa-stepup"` claim is the discriminator. `jwt-auth.guard.ts:83-88` rejects any token where `payload.purpose !== undefined`; `step-up-jwt.service.ts:81-83` rejects any token where `payload.purpose !== "2fa-stepup"`. Mutually exclusive verifiers over a single shared HS256 key. |

---

## Server-side grep results

Per Key Link 3, server-side (`apps/api/src/`) MUST contain ZERO call/import
references to `master_DEK`, `master_kek`, `computeTotpStep`, or
`verifyTotpCandidate`. Doc-string assertions and pino-redaction wildcards
are explicitly allowed.

```
$ grep -rn "master_DEK\|master_kek\|computeTotpStep\|verifyTotpCandidate" apps/api/src/

apps/api/src/app.module.ts:91:  "*.master_kek",
apps/api/src/twofa/step-up/step-up-material.controller.ts:27: * needs to derive `master_DEK` to decrypt those secrets, and the
apps/api/src/twofa/step-up/step-up-material.controller.ts:33: *   - userArgonSalt + argon2Params + wrappedMasterDek → derive master_DEK
apps/api/src/twofa/step-up/step-up-material.controller.ts:38: *     with master_DEK, then runs RFC 6238 against to derive the candidate
apps/api/src/twofa/step-up/step-up-material.controller.ts:47: *     ceremony is browser-native + server-verified; no master_DEK
apps/api/src/twofa/totp/totp.service.ts:32: *    `computeTotpStep` / `verifyTotpCandidate` / `buildOtpauthUrl`).
```

| Hit | Classification |
|---|---|
| `app.module.ts:91` | **Pino redaction wildcard** — defence-in-depth log scrub (`*.master_kek`); no code reads/derives the value. |
| `step-up-material.controller.ts:27,33,38,47` | **Doc-string** — JSDoc explaining what the *client* does after receiving the wrap material. The endpoint returns wrapped blobs only; no server-side derivation. Code body (`get()`, lines 76-136) selects pre-existing `wrappedMasterDek` + `wrappedSecret` columns and base64-encodes them — never derives `master_DEK`. |
| `totp.service.ts:32` | **Doc-string** — SECURITY-INVARIANT comment that explicitly NAMES the symbols absent from the server-side import graph; `totp.service.ts` imports `node:crypto` (`createHash`, `randomBytes`) and `drizzle-orm` only. No `@simplevault/crypto/browser` import; no RFC 6238 arithmetic. |

**Grep clean. Gate 1 satisfied.**

A complementary positive grep confirms the totp helper trio is reachable
ONLY via `@simplevault/crypto/browser`:

```
$ grep -rn "computeTotpStep\|verifyTotpCandidate\|buildOtpauthUrl" packages/crypto/src/
packages/crypto/src/totp.ts:53:export function computeTotpStep(...)
packages/crypto/src/totp.ts:98:export function verifyTotpCandidate(...)
packages/crypto/src/totp.ts:129:export function buildOtpauthUrl(...)
packages/crypto/src/browser.ts:16:export * from "./totp.js";   # browser barrel re-exports
# packages/crypto/src/node.ts — DOES NOT include "./totp.js"
```

`test/parity.test.ts:54-66` snapshots `BROWSER_ONLY_EXPECTED` to include
`buildOtpauthUrl`, `computeTotpStep`, `totpReady`, `verifyTotpCandidate`;
`test/totp.test.ts:172-177` asserts `node.computeTotpStep === undefined`.
Drift = test failure.

---

## Additional crypto-auditor findings

### RFC 6238 vector coverage (Plan 03 — packages/crypto/test/totp.test.ts)

- `test/totp.test.ts:33-38` pins all 4 RFC 6238 Appendix B SHA-1 vectors
  (t = 59 / 1111111109 / 1234567890 / 2000000000) at both 6-digit and
  8-digit widths. Zero-padding edge case (`005924`) tested explicitly.
- Drift window tested: `currentStep ± 1` accept paths pass, `± 2` reject.
- Strict format guard (`/^\d{6}$/`) tested: 5-digit, 7-digit, non-numeric,
  empty all reject.
- Wrong-secret rejection tested.
- Constant-time scan implemented (full `2*drift+1` slot walk after first
  hit, line 117-119) — guards against drift-slot timing leak.

### TOTP replay guard (Key Link 4)

`totp.service.ts:172-199` — atomic CAS:
```
UPDATE totp_credentials
   SET last_used_step = $cs, last_used_at = now()
 WHERE id = $cid AND user_id = $uid AND last_used_step < $cs
RETURNING id;
```
Zero-rows → 401 `AUTH_2FA_TOTP_REPLAY`. Drift normalisation happens
client-side in `verifyTotpCandidate` (the matched step is sent verbatim
as `candidateStep`); server enforces the strict `<` comparison. Anti-
enumeration: cross-user / wrong-credential-id all collapse to identical
401 (line 192-197 comment).

### Step-up token surface (Key Link 5)

- TTL = 120s default, env-tunable via `STEP_UP_TOKEN_TTL`
  (`step-up-jwt.service.ts:36, 57-60`).
- Claims: `{sub, purpose:"2fa-stepup", epoch, iat, exp}`. NO `sid`/`fam`.
- Both verifiers (`StepUpJwtService.verify` + `JwtAuthGuard.canActivate`)
  read the `purpose` claim; mutually exclusive accept paths.
- `Require2FAStepUpGuard` (`step-up.guard.ts:36-67`) is wired to
  `/2fa/webauthn/{begin-auth, finish-auth}`, `/2fa/totp/verify`,
  `/2fa/step-up-material` — all four routes carry `@Public()` to opt out
  of the global access-token guard, then attach the step-up guard
  explicitly. The intersection of "Public" + "step-up-required" is the
  desired safety property; no route is accidentally completely open.

### TOTP issuance-nonce (Plan 03-03 finish-register precondition)

- 32 random bytes via `randomBytes(32).toString("base64url")`
  (`totp.service.ts:101`). `SET ... EX 120 NX` Redis write at
  `totp.service.ts:105`. Atomic `GETDEL` consume at line 130.
- Pre-image-resistant Redis key: `sha256(nonce)` rather than the raw
  nonce (line 76-77 + ratiionale comment). Defence in depth against a
  Redis snapshot leaking active enrolment tokens.
- Registration-step burn: `last_used_step = candidateStep` at insert
  (line 143) blocks replay of the registration code at `/verify`.

### WebAuthn ceremony correctness (Plans 03-02 + 03-08)

- `userVerification = "required"` on both registration and authentication
  (`webauthn-register.service.ts:111`, `webauthn-auth.service.ts:100`,
  + `requireUserVerification: true` on both verify calls).
- `attestationType = "none"` (`webauthn-register.service.ts:109`); plan
  decision documented in `03-INDEX.md` operator decision #3.
- `supportedAlgorithmIDs = [-7, -257]` (ES256 + RS256) at line 114.
- `excludeCredentials` on registration and `allowCredentials` on auth
  populated from existing rows so a registered passkey cannot be
  re-enrolled and an unregistered credential cannot complete auth.
- Counter regression check + audit emit on `counter_regression` reason.
- Schema: `bytea` for `credential_id` / `public_key` / `aaguid`,
  unique-index on `credential_id`, `bigint` counter — types match wire
  shape exactly.

### Schema review (Plan 03-01)

- `webauthn_challenges`: `(user_id, kind)` UNIQUE composite; `kind`
  is enum-at-app-layer ("register"|"auth"). UPSERT pattern for
  re-issuance is harmless (same user/kind row gets replaced; FK cascade
  on user delete cleans up).
- `webauthn_credentials`: `credential_id` UNIQUE globally — required
  for passkey discovery / cross-account-collision detection.
- `totp_credentials`: `wrapped_secret` + `encrypted_secret_aad` both
  `bytea NOT NULL`; `last_used_step bigint NOT NULL DEFAULT 0`. The
  `last_used_at` is nullable (set on first verify) — fine; the CAS uses
  `last_used_step`, not the timestamp.

---

## Findings filed

| ID | Severity | Title |
|---|---|---|
| FINDING-0040 | **Low** | Client trusts server-supplied `encryptedSecretAad` at TOTP unwrap instead of recomputing locally |
| FINDING-0041 | **Info** | `master_kek` literal in pino redaction list — appears in server-side grep noise (expected, defence-in-depth) |
| FINDING-0042 | **Info** | WebAuthn challenge entropy via `WebCrypto.getRandomValues` (not `node:crypto.randomBytes` directly) — equivalent CSPRNG, but worth pinning the contract in CI |

### FINDING-0040 — Low — Client trusts server-supplied AAD at TOTP unwrap

**Where:** `apps/web/src/lib/crypto/totp-wrap.ts:79-92` (`unwrapTotpSecret`)
+ `apps/web/src/lib/api/twofa-client.ts:188+` (callsite at TOTP step-up).

**What:** At wrap time, the browser builds the AAD locally as
`encodeAad(argon2Params, "sv:user-totp:v1|" || sha256(lower(email)))`.
At unwrap time, the browser receives `encryptedSecretAad` back from the
server (round-tripped through `totp_credentials.encrypted_secret_aad`)
and feeds it verbatim to `decrypt(...)`. It does NOT recompute the AAD
locally and assert equality with the server-supplied bytes.

**Why it's defence-in-depth-only today:** the AAD is bound by the
Poly1305 tag under `master_DEK`. Tampering with the AAD bytes alone
fails the tag check at `aead.decrypt`. So a passive server cannot swap
labels and have decrypt succeed.

**Drift risk:** if the AAD scheme is ever revised (e.g., add a "TOTP
generation count" binder in v2), an active server could replay the
*old* AAD bytes and the client would unwrap successfully — the server-
supplied value bypasses the client's understanding of the contract.
This mirrors Phase 02 FINDING-0026's drift-risk pattern.

**Fix sketch:** in `unwrapTotpSecret`, accept `email` + `argon2Params`
as additional parameters, recompute `expectedAad = computeTotpAad(...)`,
and `sodium.memcmp(expectedAad, suppliedAad)` before calling `decrypt`.
Tag check still runs as the second line of defence.

**Severity:** Low. Phase 03 ships ONE label, so today's contract is
byte-equal between wrap and unwrap; the gap only opens if the scheme
ever evolves without updating both call sites.

### FINDING-0041 — Info — `master_kek` in pino redaction list

`apps/api/src/app.module.ts:91` declares `"*.master_kek"` in the pino
log-scrub wildcard list. This is correct and load-bearing (it's the
defence-in-depth scrub from Phase 02 FINDING-0010 closure). The Phase
03 gate's literal grep flags this hit; document it as expected so
future auditors don't flag it as a false-positive Critical. No fix
needed.

### FINDING-0042 — Info — WebAuthn challenge CSPRNG path

`@simplewebauthn/server@11.0.0/esm/helpers/generateChallenge.js` uses
`globalThis.crypto.getRandomValues` rather than `node:crypto.randomBytes`
directly. On Node 18+ both ultimately resolve to the same OpenSSL CSPRNG;
on older runtimes the WebCrypto path may not be present. Production
deploys to Dokploy on Node 22 — fine. Worth pinning a CI check that
`process.versions.node >= "20"` so a future runtime regression doesn't
silently cause `globalThis.crypto` to be absent. No code change in
Phase 03.

---

## Regression check vs Phase-02 controls

| Control | Phase 02 status | Phase 03 status |
|---|---|---|
| Two-secret invariant (server never sees password / secret_key / mnemonic) | OK | **EXTENDED** — TOTP secret added to the never-server-side list; `node.ts` barrel still excludes; symbol-parity test extended (`test/parity.test.ts:54-66`). |
| AAD label freeze (`sv:user-*:v1\|`) | OK with FINDING-0026 drift-risk | **PRESERVED** — new `AAD_LABEL_TOTP` lives in the same `aad-labels.ts` module; the wrap site centralises through it. |
| Argon2id calibration + floor + AAD-binding | OK | unchanged |
| `@simplevault/crypto/browser` vs `/node` symbol parity | OK | **EXTENDED** — TOTP trio added to `BROWSER_ONLY_EXPECTED`. |
| AEAD wire format `nonce(24B) || ciphertext+tag` | OK | **REUSED** — TOTP wrap follows identical packing (`totp-wrap.ts:65-67`); client unpack at `unwrapTotpSecret:84-89` symmetric. |
| Constant-time comparisons (libsodium memcmp / timingSafeEqual) | OK | **EXTENDED** — `verifyTotpCandidate` walks the full drift window and uses `sodium.memcmp` for the candidate compare. |
| Pino redaction list | OK | unchanged (no new secret-bearing field types introduced). |
| `__Host-refresh` cookie attributes | OK | **PRESERVED** — `httpOnly`, `secure`, `sameSite:strict`, `path:/` reused at WebAuthn-finish-auth + TOTP-verify (`webauthn-auth.controller.ts:111-117`, `totp.controller.ts:205-211`). |
| JWT signing (HS256, `kid:"primary"`) | OK | **EXTENDED** — `epoch` claim added (Plan 04); step-up JWT shares the secret + adds `purpose` discriminator (Plan 02). |

**No regressions.**

---

## Findings summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Info | 2 |

See `.planning/security/FINDINGS.md` for FINDING-0040..FINDING-0042
(filed by parent orchestrator after this report lands).

---

## Verdict

**PASS-WITH-CONCERNS**

No Critical or High issues found. All seven Phase 03 crypto gate items
pass with explicit code evidence. The TOTP secret never reaches the
server (grep clean modulo doc-string + redaction-wildcard noise — both
load-bearing and expected); the AAD label `"sv:user-totp:v1|"` follows
the Phase 02 scheme byte-for-byte, including per-user
`SHA256(lower(email))` binder; WebAuthn challenges are 32 random bytes
from the WebCrypto CSPRNG and consumed atomically via single-statement
`DELETE … RETURNING`; `@simplewebauthn/server@11.0.0` is invoked with
explicit `expectedRPID` + `expectedOrigin` and boot-time fail-fast on
unset env in production; the counter regression check is exactly
`stored > 0 && new <= stored`; the step-up JWT shares one HS256 secret
with the access JWT and the two verifiers are mutually exclusive on the
`purpose` claim.

The single Low finding (FINDING-0040) is a defence-in-depth gap rather
than a live exposure: tag-check under `master_DEK` already protects
TOTP-secret integrity; the gap only opens if the AAD scheme ever evolves.
This matches the Phase 02 FINDING-0026 pattern and **does not block the
Phase 03 gate** (gate rule: no Critical/High open).

Phase 03 crypto-auditor pillar: **PASS-WITH-CONCERNS**.
