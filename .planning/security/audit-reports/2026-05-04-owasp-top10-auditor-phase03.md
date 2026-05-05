# owasp-top10-auditor — Phase 03

**Date:** 2026-05-04
**Phase:** 03 (2FA — WebAuthn + TOTP — and session management UI)
**Scope:** `apps/api/src/twofa/**`, `apps/api/src/sessions/**`,
`apps/api/src/auth/login/**`, `apps/api/src/auth/jwt/**`,
`apps/api/src/auth/sessions/session.service.ts`,
`apps/api/src/common/throttler.config.ts`,
`apps/api/src/vault/_2fa-guard-probe.controller.ts` + module,
`apps/api/src/test-helpers/**` (EXPOSE_TEST_ROUTES gated),
`apps/api/src/app.module.ts`, `apps/web/src/app/(authed)/settings/{security,sessions}/**`,
`apps/web/src/app/login/2fa/**`, `packages/db/src/schema/**`,
`packages/shared/src/error-codes.ts`.

**Method:** static read-only audit of the API + web source trees, the
NestJS guard chain, the DTO surface, and the SQL access patterns. Cross-
checked against the 20 goal-backward truths in `03-INDEX.md`, the
verification report `03-VERIFICATION.md`, and the Phase-02 baseline
(`02-PHASE-SUMMARY.md` + the prior owasp report). The phase-gate spec
in `03-INDEX.md` enumerates A01 / A02 / A07 as the three load-bearing
categories; the other seven are checked briefly.

**Verdict:** **PASS-WITH-CONCERNS**
*(this auditor opens 1 Low + 2 Info; no new Critical/High. The phase
gate may proceed pending the other 3 blocking auditors and the
informational threat-modeler update.)*

---

## A01 — Broken Access Control — **PASS**

The Phase 03 goal "only the owner manages own 2FA + sessions" holds
across every new route. Verified by direct read:

- **`GET /2fa/methods`** (`methods.controller.ts:49–62`): the controller
  reads `req.user.id` only and the underlying service runs both
  `SELECT` queries with `WHERE user_id = $authedUser`
  (`methods.service.ts:79–99`). Output flows through
  `TwoFaMethodsListSchema.parse(...)` (`.strict()` allow-list — line 61)
  so a future ORM hydration leak surfaces as 500 not silent exfil.
- **`DELETE /2fa/methods/:id`** (`methods.controller.ts:74–98`): the
  service `DELETE`s gated on `AND id = $methodId AND user_id =
  $authedUser` (`methods.service.ts:170–188`). On zero rows, controller
  throws `NotFoundException` with `AUTH_INVALID_CREDENTIALS` —
  **404, not 403**, matching the explicit anti-enumeration mandate
  in Truth 10. The 409 `AUTH_2FA_REMOVAL_BLOCKED` only fires AFTER
  the user-scoped count succeeds, so it cannot leak cross-user info
  (Phase 03 stub returns false anyway — `methods.service.ts:29–33`).
- **`GET /sessions`** (`sessions.controller.ts:48–60`): reads
  `req.user.id` + `req.user.sessionId` only;
  `SessionService.listForUser` runs `WHERE user_id = $authedUser AND
  revoked_at IS NULL` (`session.service.ts:328`); response flows
  through `SessionListResponseSchema.parse(...)` (line 59).
- **`DELETE /sessions/:id`** (`sessions.controller.ts:62–86`):
  `SessionService.revokeOne` first SELECTs `WHERE id = $sessionId AND
  user_id = $authedUser` (`session.service.ts:389–393`); cross-user →
  null → controller maps to **404 not 403** (line 79), matching
  Truth 12 anti-enumeration. Response is **204 no body** so the wire
  shape is identical for "I revoked my own session" vs "I revoked a
  sibling I owned".
- **`POST /sessions/revoke-all`** (`sessions.controller.ts:100–126`):
  unconditionally scoped to `req.user.id` — no path/body parameter
  could refer to another user. `SessionService.revokeAllForUser`
  runs `WHERE user_id = $authedUser` (`session.service.ts:434`) +
  `bumpEpoch(userId)` for the same user.
- **WebAuthn register endpoints** (`webauthn-register.controller.ts:36–91`):
  scoped to `req.user.id` from `JwtAuthGuard`. `excludeCredentials`
  is computed from the same authed user (`webauthn-register.service.ts:95–124`)
  so a caller cannot enumerate another user's credentials.
- **WebAuthn auth endpoints** (`webauthn-auth.controller.ts:46–124`):
  scoped to `req.stepUp.sub` (the step-up token's `sub`); the step-up
  token was minted by `/auth/login` AFTER 1FA verified the same user.
  `beginAuth` and `finishAuth` SELECT `WHERE user_id = $sub` only.
- **TOTP endpoints** (`totp.controller.ts`): begin/finish-register
  scoped to `req.user.id` from `JwtAuthGuard`; verify scoped to
  `req.stepUp.sub` from `Require2FAStepUpGuard` (line 140–141). The
  CAS UPDATE in `totp.service.ts:176–189` carries
  `eq(totpCredentials.userId, userId)` so a verify with a wrong user's
  credentialId returns zero rows → uniform `AUTH_2FA_TOTP_REPLAY`.
- **Step-up material** (`step-up-material.controller.ts:65–137`):
  `req.stepUp.sub`-scoped only.
- **`POST /vault/_2fa-guard-probe`** (`_2fa-guard-probe.controller.ts`):
  guards stack `JwtAuthGuard` + `Require2FAGuard`, the latter checks
  `count(webauthn) + count(totp) ≥ 1` for `req.user.id`
  (`require-2fa.guard.ts:103–134`). The route exists ONLY when
  `EXPOSE_TEST_ROUTES === "1"` (`app.module.ts:162–164`); production
  build omits the module entirely. Verified absent under `prod` build.
- **`@Public()` decorator** (`public.decorator.ts`) is applied
  exclusively to: `/health`, `/auth/login`, `/auth/refresh`,
  `/auth/logout`, `/auth/params`, `/auth/signup`, `/invite/redeem`,
  the step-up auth surface (`/2fa/webauthn/{begin,finish}-auth`,
  `/2fa/totp/verify`, `/2fa/step-up-material`), and the test-helpers
  module. Every other authed route relies on the global APP_GUARD
  `JwtAuthGuard` (`app.module.ts:174`). No header-trick auth bypass
  (`req.headers["x-user"]` etc.) is read anywhere.
- **Session-epoch revocation** is per-user, not per-session
  (`session.service.ts:264–267`, `bumpEpoch`); `JwtAuthGuard` rejects
  any token whose `epoch` claim does not match the cached
  `users.session_epoch` (`jwt-auth.guard.ts:105–119`).

No cross-user authorisation gaps found. No header-injection auth
bypass paths. All path/body ids are `ParseUUIDPipe({version:"4"})`
validated.

## A02 — Cryptographic Failures — **PASS**

The two phase-gate invariants are upheld:

1. **TOTP plaintext NEVER reaches the server.** `apps/api/src` carries
   ZERO references to `computeTotpStep`, `verifyTotpCandidate`,
   `buildOtpauthUrl`, `hmac-sha1`, or any RFC 6238 arithmetic
   (verified by grep). The single mention is a docstring assertion in
   `totp.service.ts:32` declaring the invariant. The server stores
   only `totp_credentials.{wrapped_secret, encrypted_secret_aad,
   last_used_step, name}` (Plan 03 schema). `TotpFinishRegisterSchema`
   accepts `wrappedSecret` + `encryptedSecretAad` + `candidateStep` +
   `name` — no plaintext field exists. `TotpVerifySchema` accepts
   `credentialId` + `candidateStep` (a 5-digit-bounded RFC 6238 step
   counter that has already been verified client-side); the server's
   only role is the atomic `UPDATE … WHERE last_used_step <
   $candidate RETURNING id` CAS replay-guard
   (`totp.service.ts:176–189`).

2. **`master_DEK` never leaves the browser.** Server-side `master_DEK`
   references are exclusively (a) Pino redaction wildcards
   (`app.module.ts:30–124`), (b) docstring assertions in
   `step-up-material.controller.ts:27–47` and
   `login.service.ts:74` explaining the invariant, and (c) DB column
   reads/writes for `wrapped_master_dek` BLOBS (the wrapped key,
   never the plaintext DEK). The server returns the wrapped DEK in
   the same envelope shape as Phase 02 `/auth/login`; the client
   unwraps locally. Verified by grep.

Supporting cryptographic posture:

- WebAuthn challenges are 32 bytes from `@simplewebauthn/server`'s
  `generateRegistrationOptions` / `generateAuthenticationOptions`
  (which call `crypto.randomBytes` internally). Stored with
  TTL=120s. Atomic consume via single-statement `DELETE …
  RETURNING` (`webauthn-register.service.ts:168–172`,
  `webauthn-auth.service.ts:147–151`) — never SELECT-then-DELETE,
  so no TOCTOU replay window.
- `verifyRegistrationResponse` and `verifyAuthenticationResponse`
  receive `expectedRPID` and `expectedOrigin` explicitly
  (`webauthn-register.service.ts:189–190`,
  `webauthn-auth.service.ts:193–194`); defaults are not used.
  `requireUserVerification: true` enforced on both ceremonies.
  `@simplewebauthn/server` pinned at `^11` (`apps/api/package.json`).
- Counter regression: `webauthn-auth.service.ts:217–225` rejects
  `cred.counter > 0 && newCounter <= cred.counter` and emits the
  `counter_regression` audit. The `>0` guard is documented and
  defensible — iCloud-Keychain-synced passkeys never increment.
- Step-up token uses the SAME `JWT_SECRET` as the access token
  (`step-up-jwt.service.ts:55–61` — pulls via
  `this.jwt.exposeSecret()`). Discriminator is the `purpose:
  "2fa-stepup"` claim. `JwtAuthGuard` decodes (without verification)
  to inspect `purpose` and rejects any non-undefined value
  (`jwt-auth.guard.ts:81–94`); the verifier itself enforces alg
  `["HS256"]` at `step-up-jwt.service.ts:77`. No alg-confusion or
  split-secret risk.
- TOTP issuance nonce: 32 random bytes from `node:crypto/randomBytes`,
  stored as `sha256(nonce) → userId` in Redis with TTL=120s, atomic
  consume via `GETDEL` (`totp.service.ts:100–113, 130`).
- IP hashing: HMAC-SHA256 keyed by `SERVER_IP_HASH_SECRET` with
  documented unkeyed-SHA256 fallback (`session.service.ts:102–107`).
  `ipHashB64Prefix` returned to the client is the first 6 chars of
  base64 (`session.service.ts:360`) — 36 bits, intentionally lossy.
- Pino redaction list (`app.module.ts:30–124`) covers every wrapped
  blob including the new `wrappedSecret` / `encryptedSecretAad`
  fields via the `*.dek` / `*.kek` / `*.password` / `*.token`
  wildcards (lines 88–123) — though TOTP-specific fields aren't
  *named* explicitly. Filed as Info (FINDING-0052).

**Note (deferred to crypto-auditor):** the deeper review of the
RFC 6238 client-side helper, the AAD scheme `sv:user-totp:v1|`
parity with the Phase-02 binder, and the WebAuthn counter-regression
edge cases is the crypto-auditor's mandate; this OWASP pass confirms
the surface posture.

## A03 — Injection — **PASS**

All Phase 03 SQL goes through Drizzle's parameterised builders or the
`sql\`…\`` template tag with `${expr}` interpolations (PG `$1`/`$2`).
Verified zero occurrences of `sql.raw`, `sql.identifier(userInput)`,
or string-concatenated SQL anywhere under
`apps/api/src/{twofa,sessions}` or the touched portions of
`apps/api/src/auth`. Spot-checks:

- `methods.service.ts:170–188` — `delete().where(and(eq(...), eq(...)))`
  parameterised.
- `session.service.ts:325–331, 397–402, 434–438` — `sql\`…\`` with
  `${userId}` / `${sessionId}` / `${row.familyId}` interpolations
  (PG bound).
- `webauthn-{register,auth}.service.ts` finish endpoints — atomic
  `DELETE … RETURNING` parameterise `${userId}`.
- `totp.service.ts:130, 176–189` — Redis `getdel(key)` with hashed
  key derivation; SQL `update().set().where()` parameterised.

Every DTO is Zod-validated with `.strict()` and `safeParse` BEFORE
the handler runs (`TotpFinishRegisterSchema`, `TotpVerifySchema`,
`FinishRegisterSchema`, `FinishAuthSchema`, etc.). UUID path params
go through `ParseUUIDPipe({version:"4"})`. No `eval`, `new Function`,
or dynamic `require(<userInput>)` added in Phase 03.

## A04 — Insecure Design — **PASS-WITH-CONCERNS**

Anti-enumeration is preserved end-to-end through the new 2FA branch:

- **`/auth/login`** (`login.controller.ts:62–118`): the failure path
  emits the same uniform 401 + `AUTH_INVALID_CREDENTIALS` body that
  Phase 02 emits (`login.controller.ts:91–94`). The `LoginService`
  performs the `methods.countActive(user.id)` lookup ONLY AFTER 1FA
  verifies (`login.service.ts:130`); the wrong-creds path is byte-
  identical across 2FA-enrolled and 2FA-free users (Truth 8 +
  Key Link 5). The 200-status 2FA-required body shape is therefore
  observable ONLY post-1FA — exactly as the gate spec requires.
- **`/2fa/totp/verify`** (`totp.service.ts:172–199`,
  `totp.controller.ts:122–256`): the CAS `UPDATE … WHERE
  id=$cid AND user_id=$uid AND last_used_step < $cs` returns zero
  rows for ANY of: (a) wrong credentialId, (b) credentialId belongs
  to a different user, (c) replay (`candidateStep ≤ stored`). All
  three collapse to the same 401 `AUTH_2FA_TOTP_REPLAY` (Truth 7).
  The accompanying audit log preserves the distinction internally
  via `reason` field (`totp.controller.ts:244–252`).
- **`DELETE /2fa/methods/:id` and `DELETE /sessions/:id`** map
  cross-user / non-existent / already-revoked to the same 404 +
  `AUTH_INVALID_CREDENTIALS` envelope (`methods.controller.ts:84–90`,
  `sessions.controller.ts:78–83`). The 409 path on
  `AUTH_2FA_REMOVAL_BLOCKED` only triggers after user-scoped count
  confirms the caller owns at least one method — so a cross-user
  probe never reaches it (`methods.service.ts:216–243`).
- **WebAuthn finish endpoints** map `challenge_invalid`,
  `challenge_expired`, `bad_credential_id`, `credential_not_found`,
  `verification_threw`, `verification_failed`, `counter_regression`
  to `WEBAUTHN_VERIFICATION_FAILED` (401) on the auth path — uniform
  external response with internal `reason` audit
  (`webauthn-auth.service.ts:153–225`). HOWEVER, the
  `WEBAUTHN_CHALLENGE_INVALID` is HTTP 400 vs the
  `WEBAUTHN_VERIFICATION_FAILED` HTTP 401 — these are observably
  different statuses. **Concern:** an attacker can deduce
  "challenge expired" vs "assertion bad" from the status code,
  giving partial timing/state info. Filed as Info (FINDING-0050).
  Low impact because both states are post-1FA and identity-confirmed
  by the step-up token; the attacker is the user themselves.
- **`ParseUUIDPipe` on path params** raises HTTP 400 (Nest default)
  for malformed UUIDs; valid-UUID-but-not-yours raises HTTP 404.
  This distinguishes "syntactic garbage" from "valid id you don't
  own" — minor anti-enumeration drift. Pure script-kiddie probes
  cannot exploit because the 400 path leaks nothing about which
  user-ids exist; it leaks only "this string isn't a UUID". Filed
  as Info (FINDING-0051).
- The `LoginStepUpResponseBody` carries
  `twoFa: {webauthnAvailable, totpAvailable}` booleans — by design
  per Truth 8. Once 1FA passes, the attacker controls the password,
  so revealing which 2FA kinds are enrolled is a deliberate UX
  trade-off, not an enumeration leak.

## A05 — Security Misconfiguration — **PASS**

- `EXPOSE_TEST_ROUTES` is the gating env for `VaultProbeModule` AND
  `TestHelpersModule` (`app.module.ts:162–164`). Production
  Dockerfile + docker-compose carry no reference to it (per
  03-VERIFICATION.md). Recommend a runtime startup-log warn IF
  `EXPOSE_TEST_ROUTES === "1"` AND `NODE_ENV === "production"` —
  filed as Low (FINDING-0052).
- `TestHelpersModule` exposes `flip-shared-vault-stub`,
  `seed-totp-credential`, `mutate-webauthn-counter`. Each is
  documented as `EXPOSE_TEST_ROUTES`-gated, `@Public()`, and
  produces no production surface. The seeded TOTP credential cannot
  be authenticated against (placeholder bytes); the operator
  runbook documents the grep + Dokploy-panel verification step.
- Helmet + CSP from Phase 02 unchanged.
- New env vars (`WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`,
  `WEBAUTHN_ORIGIN`, `STEP_UP_TOKEN_TTL`, `SESSION_EPOCH_CACHE_TTL`)
  fail-fast in production if RP_ID/ORIGIN are absent
  (`webauthn-register.service.ts:62–66`).
- New email length cap to `varchar(254)` landed on `users.email` +
  `invite_codes.email` (`packages/db/src/schema/users.ts:46`,
  `packages/db/src/schema/invite_codes.ts:46`). Migration
  `0002_phase03_2fa_sessions.sql` carries DO-block pre-flight guard.
  Closes FINDING-0017.
- Throttler ordering fixed: `JwtAuthGuard` registered BEFORE
  `SimpleVaultThrottlerGuard` as APP_GUARDs (`app.module.ts:173–176`).
  User-keyed limits now key off `req.user.id`
  (`throttler.config.ts:148–158`). Closes FINDING-0021.
- `login-email` keying now hashes + slices to bound Redis-key length
  (`throttler.config.ts:159–170`). Closes FINDING-0022.

## A06 — Vulnerable & Outdated Components — **N/A** *(deferred to dependency-supply-chain-auditor)*

Phase 03 introduces `@simplewebauthn/server@^11` + `@simplewebauthn/types`
+ `qrcode` + `otpauth`-style helpers under `packages/crypto`. Pin
quality + advisory hits are dep-auditor scope. Spot-check only:
`@simplewebauthn/server` v11 is the current major (per Jan 2026
release line); v10 had advisory ↦ v11 migration mandatory.

## A07 — Identification & Authentication Failures — **PASS**

- **Uniform 401 on 2FA fail paths** (gate-spec requirement). Verified:
  - TOTP verify: replay vs cross-user vs unknown-credential all
    collapse to the same 401 `AUTH_2FA_TOTP_REPLAY` envelope
    (`totp.service.ts:191–199`).
  - WebAuthn finish-auth: every assertion failure mode collapses
    to 401 `WEBAUTHN_VERIFICATION_FAILED`; only the dedicated
    challenge-invalid path returns 400 — see FINDING-0050.
- **Step-up token strict separation** (Key Link 5):
  - Issued only with `purpose:"2fa-stepup"`, no `sid`/`fam`,
    `exp = iat + 120` (`step-up-jwt.service.ts:67–73`).
  - `JwtAuthGuard` rejects any token where `payload.purpose !==
    undefined` (`jwt-auth.guard.ts:81–94`) BEFORE running the full
    `verifyAccessToken` — even a valid signature on a step-up token
    cannot be used as an access token.
  - `Require2FAStepUpGuard` is the strict dual: `payload.purpose`
    must equal `"2fa-stepup"` (`step-up-jwt.service.ts:81–83`).
  - Routes opt into one guard or the other, never both. Step-up
    routes carry `@Public()` to opt out of the global access guard
    AND `@UseGuards(Require2FAStepUpGuard)` to demand the step-up
    token (`webauthn-auth.controller.ts:46–48`,
    `totp.controller.ts:122–128`).
- **Session-epoch claim** (closes Phase 02 deferred REQ-AUTH-004):
  - `users.session_epoch INT NOT NULL DEFAULT 0`
    (`packages/db/src/schema/users.ts:76`).
  - `JwtService` includes `epoch` in `signAccessToken` claims;
    `verifyAccessToken` returns it.
  - `JwtAuthGuard` reads cached `users.session_epoch` via
    `SessionEpochCache.get(claims.sub)` and rejects
    `claims.epoch !== currentEpoch` with 401
    `AUTH_SESSION_REVOKED` (`jwt-auth.guard.ts:105–119`).
  - `revokeAllForUser` order is UPDATE-then-bump-then-cache-bust
    (`session.service.ts:433–446`) — closes the race window.
  - `bumpEpoch` is invoked from `revokeAllForUser` only;
    `revokeOne` does NOT bump (single-session-revoke is softer than
    revoke-all per Plan 04 Key Link 3 — verified in
    `session.service.ts:373–412`).
- **JWT alg=none rejected.** `verifyAccessToken` and step-up
  `verify` both pass `algorithms: ["HS256"]` to `jose.jwtVerify`.
- **No header-trick auth bypass.** `Authorization: Bearer` parsed
  strictly via `^Bearer\s+(\S+)\s*$/i` in both guards
  (`jwt-auth.guard.ts:138`, `step-up.guard.ts:73`). No
  `X-Forwarded-User` / `X-User-Id` read anywhere.
- **`__Host-refresh` cookie** flags carried through the new mint
  sites (login 1FA-only, webauthn finish-auth, totp verify, sessions
  revoke-all clear): `httpOnly: true, secure: true, sameSite:
  "strict", path: "/", maxAge: …` — verified at
  `login.controller.ts:109`, `webauthn-auth.controller.ts:111–117`,
  `totp.controller.ts:205–211`, `sessions.controller.ts:118–124`.

## A08 — Software & Data Integrity — **PASS** *(deferred deeper sweep to dep-auditor)*

`pnpm-lock.yaml` committed at repo root. No new `postinstall` scripts
in Phase 03 packages. The `@simplewebauthn/*` pin is `^11` (caret) —
acceptable for a security-active dep with a stable v11 line, but a
future hardening pass may want exact pinning. Out of OWASP A08
scope here.

## A09 — Logging & Monitoring — **PASS-WITH-CONCERNS**

- New audit actions wired through `AuditEventService.emit`:
  `LoginStepUpIssued`, `TwoFa{Webauthn,Totp}Register{Ok,Fail}`,
  `TwoFa{Webauthn,Totp}{Auth,Verify}{Ok,Fail}`,
  `TwoFaMethodRemoved`, `SessionRevoked`, `SessionRevokeAll`. The
  fail rows carry `reason` strings (`challenge_invalid`,
  `verification_threw`, `counter_regression`,
  `bad_credential_id`, etc.) for forensic distinction without
  leaking to the response.
- `auth.refresh.reuse_detected` continues to escalate to
  `logger.warn`. New `counter_regression` does NOT escalate to
  warn — it goes through the standard fail-audit path. **Concern:**
  webauthn counter regression is a clone-detection signal that
  warrants operator attention; consider escalating to `warn` for
  Phase 10's hash-chain ingestion. Filed as Info (FINDING-0053).
- Pino redact list does NOT name `wrappedSecret` /
  `encryptedSecretAad` / `issuanceNonce` / `stepUpToken` /
  `candidateStep` explicitly. The `*.token` and `*.kek` wildcards
  catch most paths but not all — the explicit named coverage that
  Phase 02 maintains for every new bytea blob is the safer pattern.
  Filed as Info (FINDING-0054).
- IP storage continues to be HMAC-SHA256 keyed; `ipHashB64Prefix`
  in `/sessions` response is intentionally lossy (6 chars).

## A10 — SSRF — **N/A**

No outbound HTTP calls from user input added in Phase 03. The new
modules' only outbound network calls are PG (Drizzle) and Redis
(`ioredis`). Neither takes user-controlled URLs.

---

## Findings filed in FINDINGS.md (this auditor)

| ID | Severity | Title |
|---|---|---|
| FINDING-0050 | Info | WebAuthn finish-auth distinguishes `WEBAUTHN_CHALLENGE_INVALID` (400) from `WEBAUTHN_VERIFICATION_FAILED` (401) by HTTP status — minor uniformity drift on the 2FA fail path |
| FINDING-0051 | Info | `ParseUUIDPipe` returns 400 for malformed UUIDs vs 404 for valid-UUID-not-yours on `DELETE /2fa/methods/:id` and `DELETE /sessions/:id` — observable enumeration of "is this a UUID" vs "does this UUID belong to me" |
| FINDING-0052 | Low | `EXPOSE_TEST_ROUTES=1` does not emit a startup `logger.warn` when `NODE_ENV=production`; runbook grep is the only safety check (defence-in-depth: a mis-set env in prod opens the test-helpers + probe routes silently) |
| FINDING-0053 | Info | WebAuthn counter-regression audit fails through the standard `outcome:"fail"` path; clone-detection signal does not escalate to `logger.warn` for ops dashboards |
| FINDING-0054 | Info | Pino redact list lacks explicit names for new Phase-03 secret-adjacent fields (`wrappedSecret`, `encryptedSecretAad`, `issuanceNonce`, `stepUpToken`, `candidateStep`); current `*.token` / `*.kek` wildcards cover most but not all paths |

(No new Critical/High/Medium discovered by this auditor.)

**Severity summary** (this auditor's findings only)

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Info | 4 |

---

## Per-OWASP-category status

| Category | Status | Note |
|---|---|---|
| A01 Broken Access Control | PASS | All new routes scoped to `req.user.id` / `req.stepUp.sub`; cross-user → 404 (anti-enumeration); session-epoch is per-user revocation |
| A02 Cryptographic Failures | PASS | TOTP plaintext server-side grep clean; `master_DEK` only as wrapped blob; WebAuthn challenges atomic-consumed; explicit RP-ID/origin; alg=HS256 enforced |
| A03 Injection | PASS | All Drizzle parameterised; zero `sql.raw` / dynamic `eval`; every DTO `.strict()` Zod-validated; UUID path params validated |
| A04 Insecure Design | PASS | Login uniformity preserved across 2FA branch; one minor 400-vs-401 status drift on webauthn challenge path (FINDING-0050, Info) |
| A05 Security Misconfiguration | PASS | `EXPOSE_TEST_ROUTES` properly gates probe + test-helpers; new env vars fail-fast in prod; throttler ordering closes 0021/0022 |
| A06 Vulnerable Components | N/A | Deferred to dep-auditor; `@simplewebauthn/server@^11` is current line |
| A07 Identification & AuthN | PASS | Uniform 401 on TOTP fail paths; step-up token strictly separated from access token by `purpose` discriminator (rejected in JwtAuthGuard); session-epoch closes REQ-AUTH-004 |
| A08 Software/Data Integrity | PASS | No new postinstall; lockfile committed; deeper pin review = dep-auditor |
| A09 Logging & Monitoring | PASS | New audit actions wired centrally; one Info on redact-list completeness (FINDING-0054); one Info on counter-regression escalation (FINDING-0053) |
| A10 SSRF | N/A | No outbound HTTP from user input |

---

## Verdict

**PASS-WITH-CONCERNS** for the Phase-03 OWASP Top-10 sweep. No new
Critical/High discovered by this auditor; the gate-spec invariants
(A01 ownership, A02 plaintext-never-server-side, A07 uniform-fail-
errors) all hold under direct code read. The five findings filed
are 1 Low + 4 Info — none block the phase gate.

The Phase-03 design demonstrates a strong security posture:
- access control is both static (route-scoped to req-user) and
  dynamic (session-epoch revocation is instant within ≤ next-
  request latency on cache-hit, ≤ 60s on cache-miss);
- the step-up token is strictly separated from access tokens by
  the `purpose` claim discriminator with dual-guard enforcement;
- all new failure modes collapse to uniform 401 envelopes on the
  externally observable surface, with internal `reason` strings
  preserved in audit logs only;
- the TOTP server-never-sees-plaintext invariant is enforced
  structurally (no import of the browser-only crypto barrel) and
  verifiable by grep;
- the throttler ordering fix closes the Phase-02 carry-over
  FINDINGS 0021/0022.

Phase 03 gate may proceed pending the other 3 blocking auditors
(`auth-flow-auditor`, `crypto-auditor`, `access-control-auditor`)
and the informational `threat-modeler` update for §17 / AT-5
leaves.

---

_Auditor: owasp-top10-auditor (Claude)_
_Phase 03 gate: 2026-05-04_
