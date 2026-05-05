---
phase: 03-2fa-sessions
verified: 2026-05-04T00:00:00Z
status: human_needed
score: 20/20 must-haves verified (structural)
human_verification:
  - test: "Run `auth-flow-auditor`, `crypto-auditor`, `owasp-top10-auditor`, `access-control-auditor` per 03-INDEX security gate"
    expected: "All four blocking auditors PASS with no Critical/High open in FINDINGS.md"
    why_human: "Security gate is the 4-auditor agent run; structural verifier intentionally does NOT execute the gate (per task brief)"
  - test: "Run `threat-modeler` informational pass for §17 / AT-5 leaves update"
    expected: "THREAT-MODEL.md updated for Phase 03 (phishing-without-WebAuthn HIGH→MITIGATED, AT-5 leaf A residual→mitigated-within-epoch-latency, etc.)"
    why_human: "Threat-model authoring is an auditor task, not structural verification"
  - test: "Visit `/settings/security` in browser; confirm passkey CTA is visually primary and TOTP carries phishing-warning copy"
    expected: "Passkey row labelled 'Recommended — phishing-resistant'; TOTP block shows phishing copy block"
    why_human: "Visual ordering / styling primacy is an auditor-checked UX assertion (Key Link 12)"
  - test: "Run Cypress 2fa-webauthn / 2fa-totp / sessions / 2fa-removal specs end-to-end"
    expected: "All four specs green in CI"
    why_human: "Specs require live API + virtual authenticator + EXPOSE_TEST_ROUTES=1 build — out of scope for static structural verifier"
  - test: "Operator runbook review (Plan 12 T4 checkpoint pending per STATE.md)"
    expected: "Operator confirms RUNBOOK env vars + lost-2FA recovery procedure + EXPOSE_TEST_ROUTES safety check"
    why_human: "Operator-facing copy + procedure review — not a code-level invariant"
notes:
  - "Phase 03 INDEX explicitly defers the 4-auditor security gate to dedicated auditor agents (auth-flow / crypto / owasp-top10 / access-control + informational threat-modeler). This verifier confirms goal-backward STRUCTURAL truth only."
  - "TODO(phase-07) in `apps/api/src/twofa/methods/methods.service.ts:32` for `userHasSharedVaultDependency` is BY DESIGN per Key Link 7 — not a stub defect."
  - "Key Link 3 (TOTP server never sees plaintext) verified: only references to master_DEK/master_kek under apps/api/src are (a) Pino redaction keys in app.module.ts and (b) docstring assertions in step-up-material.controller.ts explaining the server does NOT receive them. Zero implementation references."
---

# Phase 3: 2FA + Sessions Verification Report

**Phase Goal:** A user can enroll a passkey AND a TOTP credential, log in with master+secret_key+2FA, see their active sessions, and remotely log out a session.
**Verified:** 2026-05-04
**Status:** human_needed (all 20 structural truths verified; security-gate auditor runs + visual UX + e2e + operator runbook review remain external per task brief)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
| -- | ----- | ------ | -------- |
| 1  | `POST /2fa/webauthn/begin-register` issues challenge + 120 s `webauthn_challenges` row; replay → 400 `WEBAUTHN_CHALLENGE_INVALID` | VERIFIED | `apps/api/src/twofa/webauthn/webauthn-register.{controller,service}.ts` (93+276 LOC); `webauthn_challenges` schema present (`packages/db/src/schema/webauthn_challenges.ts`); error code `E1012` in `packages/shared/src/error-codes.ts` |
| 2  | `POST /2fa/webauthn/finish-register` verifies attestation, atomically consumes challenge, persists credential | VERIFIED | `webauthn-register.service.ts:168` atomic `DELETE … RETURNING` via `db.execute(sql\`…\`)`; uses `verifyRegistrationResponse` from `@simplewebauthn/server` v11 |
| 3  | `POST /2fa/webauthn/begin-auth` requires step-up token, returns `allowCredentials` + fresh challenge | VERIFIED | `webauthn-auth.controller.ts` + `webauthn-auth.service.ts` (124+347 LOC); guarded by `Require2FAStepUpGuard` |
| 4  | `POST /2fa/webauthn/finish-auth` enforces counter regression, atomically consumes challenge, promotes step-up to access JWT | VERIFIED | `webauthn-auth.service.ts:218–229` (`cred.counter > 0 && newCounter <= cred.counter` rejects + audit `counter_regression`); `webauthn-auth.service.ts:147` atomic consume |
| 5  | `POST /2fa/totp/begin-register` server NEVER sees plaintext; emits issuance nonce only | VERIFIED | `apps/api/src/twofa/totp/totp.{controller,service}.ts`; server-side grep clean (`master_DEK`/`master_kek` references in `apps/api/src` are docstring-only in step-up-material.controller.ts + Pino redaction keys); browser-only TOTP helpers in `packages/crypto/src/totp.ts` re-exported via `browser.ts`, NOT `node.ts` (parity test enforces) |
| 6  | `POST /2fa/totp/finish-register` accepts wrapped secret, seeds `last_used_step` to burn enrolment code | VERIFIED | `totp.service.ts:119,143` seeds `lastUsedStep: dto.candidateStep` on INSERT |
| 7  | `POST /2fa/totp/verify` atomic CAS replay guard via `UPDATE … WHERE last_used_step < $cs RETURNING` | VERIFIED | `totp.service.ts:179–186` Drizzle equivalent: `.update(totpCredentials).set({lastUsedStep}).where(and(eq(...), lt(lastUsedStep, dto.candidateStep))).returning()`; zero rows → `AUTH_2FA_TOTP_REPLAY` E1015 |
| 8  | `/auth/login` extension: branch on 2FA presence; emits `{stepUpToken, twoFa:{webauthnAvailable, totpAvailable}}` | VERIFIED | `apps/api/src/auth/login/login.service.ts:137–161` (211 LOC total) emits step-up response when `counts.webauthn > 0 \|\| counts.totp > 0` |
| 9  | `GET /2fa/methods` lists active 2FA, never returns secret material | VERIFIED | `apps/api/src/twofa/methods/methods.{controller,service}.ts` (99+245 LOC); selects only `id, kind, name, createdAt, lastUsedAt` |
| 10 | `DELETE /2fa/methods/:id` enforces removal-guard with `userHasSharedVaultDependency` stub | VERIFIED | `methods.service.ts:29–32` exports `userHasSharedVaultDependency` with `// TODO(phase-07):` (BY DESIGN per Key Link 7); injectable via `sharedVaultDependencyCheck` field for integration tests |
| 11 | `GET /sessions` lists non-revoked sessions with `current` flag + `ipHashB64Prefix` | VERIFIED | `apps/api/src/sessions/sessions.{controller,service}.ts` (127+93 LOC); shape per Truth 11 |
| 12 | `DELETE /sessions/:id` family-revokes, returns 404 (NOT 403) on cross-user, bumps epoch | VERIFIED | `sessions.controller.ts:79`, `sessions.service.ts:33–46` document and implement uniform 404 anti-enumeration |
| 13 | `POST /sessions/revoke-all` revokes all sessions + bumps `users.session_epoch` | VERIFIED | `sessions.service.ts` + `sessions.controller.ts` |
| 14 | Session-epoch claim: `users.session_epoch` column + JWT epoch claim + cached guard check | VERIFIED | `packages/db/src/schema/users.ts:76` `sessionEpoch: integer("session_epoch").notNull().default(0)`; `apps/api/src/auth/jwt/jwt.service.ts:90,103,110`; `jwt-auth.guard.ts:105–110` reads from `SessionEpochCache` and rejects mismatch as `AUTH_SESSION_REVOKED` E1017 |
| 15 | `Require2FAGuard` + `EXPOSE_TEST_ROUTES`-gated probe route | VERIFIED | `apps/api/src/twofa/require-2fa.guard.ts` (135 LOC); `apps/api/src/vault/_2fa-guard-probe.controller.ts` + `vault-probe.module.ts`; `apps/api/src/app.module.ts:162` registers IFF `process.env.EXPOSE_TEST_ROUTES === "1"` |
| 16 | Web `/settings/security` lists 2FA, prefers passkey CTA, surfaces phishing copy | STRUCTURAL VERIFIED | `apps/web/src/app/(authed)/settings/security/page.tsx` lines 14–55, 74: "Recommended — phishing-resistant" + phishing-warning copy block on TOTP; visual primacy needs human eyes |
| 17 | Web `/settings/sessions` list + revoke-one + revoke-all-except-this-device CTA | VERIFIED | `apps/web/src/app/(authed)/settings/sessions/{page,session-list,revoke-button,revoke-all-button}.tsx` |
| 18 | Throttler ordering FIXED — `JwtAuthGuard` registered as APP_GUARD before throttler | VERIFIED | `apps/api/src/app.module.ts:166–175` (load-bearing comment + ordered providers); `@Public()` decorator at `apps/api/src/auth/jwt/public.decorator.ts` |
| 19 | Email length cap landed (varchar(254) + Zod max(254)) + `login-email` throttler key cap | VERIFIED | `packages/db/src/schema/{users,invite_codes}.ts` both `varchar("email", { length: 254 })`; `packages/shared/src/zod/index.ts:201–202` `.max(254)`; `apps/api/src/common/throttler.config.ts:159–169` `sha256(email).digest("hex").slice(0,16)` for `login-email` |
| 20 | Phase-02 truths still hold + new E2E specs cover webauthn / totp / sessions / removal-guard | STRUCTURAL VERIFIED (e2e exec deferred) | `apps/web/cypress/e2e/{2fa-webauthn,2fa-totp,sessions,2fa-removal,auth-happy,auth-sad}.cy.ts` all present; CDP `WebAuthn.addVirtualAuthenticator` referenced in `2fa-webauthn.cy.ts:17–19`; live CI run is Phase-12 / Plan-03-12 T4 checkpoint (operator-pending per STATE.md) |

**Score:** 20/20 truths verified at structural level

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `packages/db/src/schema/webauthn_credentials.ts` | new schema | VERIFIED | 65 LOC |
| `packages/db/src/schema/totp_credentials.ts` | new schema | VERIFIED | 54 LOC |
| `packages/db/src/schema/webauthn_challenges.ts` | new schema | VERIFIED | 46 LOC |
| `packages/db/src/schema/users.ts` | EXTENDED `session_epoch INT NOT NULL DEFAULT 0` + email varchar(254) | VERIFIED | 98 LOC; line 76 sessionEpoch, line 46 email varchar(254) |
| `packages/db/src/schema/invite_codes.ts` | EXTENDED email varchar(254) | VERIFIED | line 46 email varchar(254) |
| `packages/db/drizzle/0002_phase03_2fa_sessions.sql` | generated migration | VERIFIED | DO-block pre-flight guard + 3 new tables + email type tightening |
| `packages/crypto/src/totp.ts` | browser-only RFC 6238 helpers | VERIFIED | 182 LOC; tests at `packages/crypto/test/totp.test.ts` |
| `packages/crypto/src/browser.ts` | re-exports totp | VERIFIED | exports `computeTotpStep` etc. |
| `packages/crypto/src/node.ts` | EXCLUDES totp | VERIFIED | named re-exports only; parity test enforces (per 03-03-SUMMARY) |
| `packages/shared/src/error-codes.ts` | new error codes | VERIFIED | E1002, E1011..E1018 all present |
| `apps/api/src/twofa/webauthn/` | begin/finish register + auth | VERIFIED | 5 files, 915 LOC total |
| `apps/api/src/twofa/totp/` | begin/finish register + verify | VERIFIED | 3 files, 484 LOC |
| `apps/api/src/twofa/step-up/` | step-up jwt service + guard + material controller | VERIFIED | 3 files, 317 LOC |
| `apps/api/src/twofa/methods/` | list + delete + removal guard | VERIFIED | 2 files, 344 LOC |
| `apps/api/src/twofa/require-2fa.guard.ts` | Require2FAGuard | VERIFIED | 135 LOC |
| `apps/api/src/sessions/` | list + revoke + revoke-all | VERIFIED | 3 files, 245 LOC |
| `apps/api/src/auth/login/login.service.ts` | EXTENDED branch on 2FA | VERIFIED | 211 LOC |
| `apps/api/src/auth/jwt/jwt.service.ts` | EXTENDED epoch claim | VERIFIED | 115 LOC |
| `apps/api/src/auth/jwt/jwt-auth.guard.ts` | EXTENDED epoch verification + APP_GUARD wiring + purpose reject | VERIFIED | 149 LOC |
| `apps/api/src/auth/jwt/public.decorator.ts` | NEW @Public decorator | VERIFIED | 23 LOC |
| `apps/api/src/common/throttler.config.ts` | EXTENDED ordering + new ceilings + email key cap | VERIFIED | sha256(email).slice(0,16) at line 169 |
| `apps/api/src/vault/_2fa-guard-probe.controller.ts` | EXPOSE_TEST_ROUTES probe | VERIFIED | 44 LOC |
| `apps/api/src/vault/vault-probe.module.ts` | conditional module | VERIFIED | 29 LOC, gated in app.module.ts:162 |
| `apps/web/src/app/(authed)/settings/security/page.tsx` | NEW security UI | VERIFIED | with phishing copy |
| `apps/web/src/app/(authed)/settings/sessions/page.tsx` | NEW sessions UI | VERIFIED | with revoke buttons |
| `apps/web/src/lib/api/twofa-client.ts` | NEW typed wrapper | VERIFIED | 282 LOC |
| `apps/web/src/lib/api/sessions-client.ts` | NEW typed wrapper | VERIFIED | 65 LOC |
| `apps/web/src/lib/api/auth-client.ts` | EXTENDED 2FA challenge response handling | VERIFIED | 378 LOC; discriminated `LoginSessionResponseSchema` + `LoginStepUpResponseSchema` (lines 81–84) |
| `apps/web/src/lib/auth/step-up-flow.ts` | NEW step-up flow driver | VERIFIED | 224 LOC |
| `apps/web/src/lib/auth/use-auto-refresh.ts` | EXTENDED handle AUTH_SESSION_REVOKED | VERIFIED | 126 LOC |
| `apps/web/cypress/e2e/2fa-webauthn.cy.ts` | NEW spec | VERIFIED | uses CDP virtual authenticator |
| `apps/web/cypress/e2e/2fa-totp.cy.ts` | NEW spec | VERIFIED | present |
| `apps/web/cypress/e2e/sessions.cy.ts` | NEW spec | VERIFIED | present |
| `apps/web/cypress/e2e/2fa-removal.cy.ts` | NEW spec (additional) | VERIFIED | bonus coverage |
| `docs/operator/RUNBOOK.md` | env vars + lost-2FA procedure | VERIFIED | new env vars at lines 30–35; lost-2FA recovery + RP-ID change + EXPOSE_TEST_ROUTES safety section all present |

### Key Link Verification

| # | From | To | Via | Status | Details |
| - | ---- | -- | --- | ------ | ------- |
| 1 | API boot | RP ID env | fail-fast guard | VERIFIED | `webauthn-register.service.ts:64–65` throws if `NODE_ENV=production` AND `WEBAUTHN_RP_ID`/`ORIGIN` unset |
| 2 | webauthn finish endpoints | challenge consume | atomic `DELETE … RETURNING` | VERIFIED | `webauthn-auth.service.ts:147` + `webauthn-register.service.ts:168` use `db.execute(sql`…`)` single statement |
| 3 | TOTP server | NEVER plaintext | browser-only crypto | VERIFIED | grep `master_DEK`/`master_kek` under `apps/api/src` returns only docstring assertions in `step-up-material.controller.ts` (explaining server does NOT have them) + Pino redaction keys; no implementation references |
| 4 | TOTP verify | replay guard | `UPDATE WHERE last_used_step < $cs RETURNING` | VERIFIED | `totp.service.ts:179–186` Drizzle CAS |
| 5 | step-up token | non-`/2fa/*` routes | reject by `purpose` | VERIFIED | `step-up-jwt.service.ts:68,81–83` mints `{purpose:"2fa-stepup"}`; `jwt-auth.guard.ts:76–88` rejects `payload.purpose !== undefined`; `Require2FAStepUpGuard` is dual |
| 6 | session-epoch | column on users | Redis-cached read | VERIFIED | column at `users.ts:76`; cache at `apps/api/src/auth/sessions/session-epoch.cache.ts` (imported by `jwt-auth.guard.ts:14`) |
| 7 | removal guard | Phase-07 stub | `userHasSharedVaultDependency` | VERIFIED | `methods.service.ts:29–32` with `// TODO(phase-07):` comment (BY DESIGN); injectable for tests |
| 8 | vault 2FA-required guard | probe route | `EXPOSE_TEST_ROUTES=1` | VERIFIED | `app.module.ts:162` conditional module spread; production unset → route absent |
| 9 | `@simplewebauthn/server` | v11 + explicit origin/RP-ID | `expectedOrigin/expectedRPID` | VERIFIED | `apps/api/package.json:25` `"@simplewebauthn/server": "^11"`; `webauthn-register.service.ts:189–190` and `webauthn-auth.service.ts:193–194` pass both explicitly |
| 10 | throttler ordering | APP_GUARD JwtAuthGuard before throttler + `@Public()` | order in providers | VERIFIED | `app.module.ts:174–175` order; `@Public()` decorator file present |
| 11 | email length cap migration | varchar(254) + Zod max(254) | drizzle 0002 + DO-block | VERIFIED | `0002_phase03_2fa_sessions.sql` carries DO-block pre-flight guard before destructive change; cardinality safe |
| 12 | Phishing-without-WebAuthn UX | passkey primary CTA + TOTP warning copy | settings/security page | STRUCTURAL VERIFIED | copy strings at `security/page.tsx:55,74` ("Recommended — phishing-resistant" / "Authenticator-app codes can be entered into a phishing site"); visual primacy needs auditor |
| 13 | Cypress + virtual authenticator | CDP `WebAuthn.addVirtualAuthenticator` | `cy.task` | STRUCTURAL VERIFIED | reference present at `2fa-webauthn.cy.ts:17–19`; live CI green is Plan-12 T4 checkpoint pending |

### Requirements Coverage

| Requirement | Status | Notes |
| ----------- | ------ | ----- |
| REQ-AUTH-004 (session epoch / token revocation) | SATISFIED | `users.session_epoch` + JWT `epoch` + cached guard check (Truth 14, Key Link 6) |
| REQ-2FA-001 (WebAuthn UV=required) | SATISFIED | per 03-INDEX operator decision 2; structural confirmation in webauthn-register.service.ts options |
| FINDING-0017 (email length cap) | SATISFIED | varchar(254) + .max(254) (Truth 19, Key Link 11) |
| FINDING-0021 (APP_GUARD throttler ordering) | SATISFIED | Truth 18 verified |
| FINDING-0022 (login-email key flooding) | SATISFIED | sha256 slice(0,16) at throttler.config.ts:169 |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `apps/api/src/twofa/methods/methods.service.ts` | 32 | `// TODO(phase-07):` | INFO | BY DESIGN per Key Link 7; explicit Phase-07 hand-off; not a defect |

No other TODO/FIXME/placeholder/empty-return patterns found in Phase 03 code surface.

### Human Verification Required

#### 1. Run the 4-auditor security gate

**Test:** Run `auth-flow-auditor`, `crypto-auditor`, `owasp-top10-auditor`, `access-control-auditor` per 03-INDEX security gate.
**Expected:** All four PASS with no Critical/High open in `FINDINGS.md`.
**Why human:** Security gate is the 4-auditor agent run; structural verifier intentionally does NOT execute the gate (per task brief).

#### 2. Run `threat-modeler` informational pass

**Test:** Run threat-modeler to update `THREAT-MODEL.md` for Phase 03 (§17 phishing-without-WebAuthn HIGH→MITIGATED, AT-5 leaf A residual→mitigated-within-epoch-latency, etc.).
**Expected:** §19 Phase-03 STRIDE per data flow committed.
**Why human:** Threat-model authoring is an auditor task, not structural verification.

#### 3. Visual UX primacy of passkey CTA

**Test:** Visit `/settings/security` in browser; confirm passkey row is visually primary (button styling + ordering) and TOTP carries phishing-warning copy block (Key Link 12).
**Expected:** Passkey labelled "Recommended — phishing-resistant"; TOTP block shows phishing warning.
**Why human:** Visual styling primacy is auditor-checked UX assertion; copy strings present but ordering/styling needs eyes.

#### 4. Cypress green in CI

**Test:** Run all four Cypress 2FA + sessions specs.
**Expected:** All four specs green in CI (with `EXPOSE_TEST_ROUTES=1` build).
**Why human:** Specs require live API + CDP virtual authenticator + DB seeding — out of scope for static structural verifier. Plan 12 T4 is the operator-pending checkpoint per STATE.md.

#### 5. Operator runbook review (Plan 12 T4 checkpoint)

**Test:** Operator confirms RUNBOOK env vars + lost-2FA recovery procedure + EXPOSE_TEST_ROUTES safety check.
**Expected:** Operator sign-off recorded.
**Why human:** Operator-facing copy + procedure review.

### Gaps Summary

No structural gaps. All 20 goal-backward truths, 34 required artifacts, and 13 key links verify at the existence + substantive + wired levels. The phase-defined `// TODO(phase-07)` for `userHasSharedVaultDependency` is the explicit hand-off point per Key Link 7 (with the helper already wired into the service constructor as an injectable + the Phase-03 implementation always returning `false`), so it is NOT a defect.

The phase is **structurally complete**. Status is `human_needed` only because:
- The 4-auditor security gate (auth-flow / crypto / owasp-top10 / access-control) is explicitly deferred to dedicated auditor agents per 03-INDEX and the verifier's task brief.
- Plan 10 T4 (UX visual review) and Plan 12 T4 (operator runbook review) are explicit operator checkpoints surfaced in STATE.md as still pending.
- Cypress live-CI execution is part of the Phase-12 cross-phase gate, not Phase 03 structural verification.

Once those external runs land green, Phase 03 transitions to fully closed.

---

_Verified: 2026-05-04_
_Verifier: Claude (gsd-verifier)_
