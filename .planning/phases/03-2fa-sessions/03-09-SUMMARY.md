---
phase: 03-2fa-sessions
plan: 09
subsystem: auth-throttler-ordering
tags: [auth, throttler, app-guard, finding-0021, finding-0022, public-decorator]
requires:
  - 03-02 (WebauthnAuthController step-up routes — opt out via @Public())
  - 03-03 (TotpController.verify step-up route — opt out via @Public())
  - 03-05 (SessionsController user-keyed ceilings — start working post-reorder)
  - 03-06 (MethodsController user-keyed ceilings — start working post-reorder)
  - 03-07 (Require2FAGuard probe + Require2FAStepUpGuard — both still operate alongside the global JwtAuthGuard)
  - 03-08 (/auth/login already on the public allow-list — Plan 09 just adds @Public() to it)
provides:
  - "@Public() decorator + IS_PUBLIC_KEY metadata"
  - "JwtAuthGuard reads @Public() via Reflector and short-circuits"
  - "JwtAuthGuard registered as APP_GUARD before SimpleVaultThrottlerGuard"
  - "login-email throttler keying via sha256(email).slice(0,16) — bounded Redis key length, PII-free"
affects:
  - 03-10 / 03-11 (Web — no impact; web client doesn't see the guard ordering, only end-to-end behaviour)
  - 03-12 (E2E Cypress — should add an explicit test that the same JWT exhausts the per-user budget across two IPs)
  - Phase 04+ controllers (new routes default to JWT-required; opt out with @Public())
tech-stack:
  added: []
  patterns:
    - "Global JwtAuthGuard via APP_GUARD with @Public() opt-out — standard NestJS pattern (NestJS docs: Authentication / Setting up a guard globally)"
    - "Order-of-registration matters: APP_GUARD providers fire in registration order; JwtAuthGuard MUST be registered before SimpleVaultThrottlerGuard for `req.user.id` to be available when the throttler's generateKey runs"
    - "Step-up routes mark @Public() to opt out of JwtAuthGuard's access-token check, then apply Require2FAStepUpGuard via @UseGuards — the step-up token's purpose:'2fa-stepup' claim is rejected by JwtAuthGuard's pre-decode discriminator (Plan 02 / Key Link 5)"
    - "Bounded Redis keys: any throttler key derived from req.body MUST be hash-and-sliced to a fixed length, since guards run BEFORE Zod validation pipes — input is unvalidated at key-derivation time"
key-files:
  created:
    - apps/api/src/auth/jwt/public.decorator.ts
  modified:
    - apps/api/src/auth/jwt/jwt-auth.guard.ts (Reflector dependency + IS_PUBLIC_KEY short-circuit)
    - apps/api/src/app.module.ts (JwtAuthGuard APP_GUARD before throttler)
    - apps/api/src/health/health.controller.ts (@Public)
    - apps/api/src/invite/invite.controller.ts (@Public on /redeem)
    - apps/api/src/auth/signup/signup.controller.ts (@Public)
    - apps/api/src/auth/login/login.controller.ts (@Public on /params + /login)
    - apps/api/src/auth/refresh/refresh.controller.ts (@Public)
    - apps/api/src/auth/logout/logout.controller.ts (@Public)
    - apps/api/src/twofa/webauthn/webauthn-auth.controller.ts (class-level @Public — both step-up routes)
    - apps/api/src/twofa/totp/totp.controller.ts (@Public on /verify only — register routes still need access JWT)
    - apps/api/src/common/throttler.config.ts (login-email keying via createHash + bounded-key invariant comment)
    - apps/api/test/jwt-epoch.spec.ts (Reflector ctor arg + ExecutionContext.getHandler/getClass stubs)
duration: ~25min
completed: 2026-05-04
---

# Phase 03 Plan 09: Throttler ordering fix + login-email keying — FINDING-0021 + 0022 closure

`JwtAuthGuard` is now a global APP_GUARD registered BEFORE
`SimpleVaultThrottlerGuard`, so every Phase-03 user-keyed throttler ceiling
(`me-user`, `2fa-register-user`, `2fa-methods-list-user`,
`2fa-methods-delete-user`, `sessions-list-user`, `sessions-revoke-user`,
`sessions-revoke-all-user`) keys correctly off `req.user.id` instead of
silently falling back to IP. Truly-public routes opt out via the new
`@Public()` decorator. The `login-email` ceiling now hashes the email to
16 hex chars before keying — bounded Redis keys, PII-free.

**Status:** COMPLETE
**Date:** 2026-05-04
**Commits:** `859c7e4` (T1), `8e3215c` (T2), `a4283a0` (T3)
**Tasks:** 3/3
**Findings closed:** FINDING-0021, FINDING-0022 (both Medium → FIXED-PENDING-VERIFICATION pending live e2e re-run)

---

## What landed

### Task 1 — `refactor(03-09-T1): @Public() decorator + JwtAuthGuard Reflector integration` (`859c7e4`)

**`apps/api/src/auth/jwt/public.decorator.ts` (new)** — exports
`IS_PUBLIC_KEY` metadata key + `Public()` decorator (a `SetMetadata`
wrapper). Applied at method or class level; method-level overrides class-
level via `Reflector.getAllAndOverride([handler, class])`.

**`apps/api/src/auth/jwt/jwt-auth.guard.ts`** — adds a `Reflector`
constructor dependency and short-circuits to `true` whenever
`IS_PUBLIC_KEY` is set. The check happens BEFORE any bearer-token
inspection, so `@Public()` routes carry zero auth overhead. The existing
`purpose !== undefined` step-up-token rejection still runs after the
public check passes through to the auth path (i.e. for non-public routes
only — exactly what we want).

**Test fix (`apps/api/test/jwt-epoch.spec.ts`)** — `JwtAuthGuard`'s
constructor signature now takes a third arg (`Reflector`); the unit-test
guard receives a vanilla `new Reflector()` and the `ctxWithBearer` helper
exposes `getHandler()` + `getClass()` on the mocked `ExecutionContext` so
`Reflector.getAllAndOverride` resolves to `undefined` (i.e. not public).
All 32/32 specs remain green.

### Task 2 — `refactor(03-09-T2): JwtAuthGuard moved to APP_GUARD before throttler — FINDING-0021 closure` (`8e3215c`)

**`apps/api/src/app.module.ts`** — replaces the single `APP_GUARD` entry
with two, REGISTRATION ORDER LOAD-BEARING:

```ts
providers: [
  { provide: APP_GUARD, useClass: JwtAuthGuard },           // FIRST
  { provide: APP_GUARD, useClass: SimpleVaultThrottlerGuard }, // SECOND
],
```

NestJS executes APP_GUARDs in registration order; the second one only
fires if the first allowed. After this change, every non-`@Public()`
route runs JwtAuthGuard first, populates `req.user.id`, and the throttler
sees the populated request — closing FINDING-0021's silent IP-keying
fallback.

**Public route allow-list** — every controller method that must be
reachable without an access JWT now carries `@Public()`:

| Route | File | Why public |
|---|---|---|
| `GET /health` | `apps/api/src/health/health.controller.ts` | Liveness probe (Dokploy/k8s); skipped by throttler too |
| `POST /invite/redeem` | `apps/api/src/invite/invite.controller.ts` | Invite redemption is the entry point — caller has no JWT yet |
| `POST /auth/signup` | `apps/api/src/auth/signup/signup.controller.ts` | Account creation; pre-auth |
| `GET /auth/params` | `apps/api/src/auth/login/login.controller.ts` | Public Argon2 params; required before login can compute the verifier |
| `POST /auth/login` | `apps/api/src/auth/login/login.controller.ts` | Login mints the JWT — can't require one to call it |
| `POST /auth/refresh` | `apps/api/src/auth/refresh/refresh.controller.ts` | Auths via `__Host-refresh` cookie, not Bearer |
| `POST /auth/logout` | `apps/api/src/auth/logout/logout.controller.ts` | Best-effort cookie clear; cookie may already be expired |
| `POST /2fa/webauthn/begin-auth` | `apps/api/src/twofa/webauthn/webauthn-auth.controller.ts` | Carries a step-up token (`purpose:"2fa-stepup"`); JwtAuthGuard would reject it. Auth provided by `Require2FAStepUpGuard` (class-level `@UseGuards`). |
| `POST /2fa/webauthn/finish-auth` | `apps/api/src/twofa/webauthn/webauthn-auth.controller.ts` | Same — class-level `@Public()` covers both methods |
| `POST /2fa/totp/verify` | `apps/api/src/twofa/totp/totp.controller.ts` | Same — method-level `@Public()` (the `/begin-register` + `/finish-register` siblings still require access JWT) |

**Auth-required routes** — every other endpoint is now JWT-required by
default via the global guard. The pre-existing per-controller
`@UseGuards(JwtAuthGuard)` on `/me`, `/2fa/webauthn/{begin,finish}-register`,
`/2fa/totp/{begin,finish}-register`, `/2fa/methods`, `/sessions/*`, and
`/vault/_2fa-guard-probe` is kept as harmless defence-in-depth (the
second invocation is a free Reflector hit + a Redis cache hit on the
session-epoch — no DB or new auth work).

**Verification status (live e2e):** the FINDING-0021 reproduction
described in the plan ("101 `/me` from IP-1 then one from IP-2 with
the same JWT — second IP gets immediate 429") requires Postgres + Redis
+ a running API container. NOT executed in this commit window. Marked
FIXED-PENDING-VERIFICATION pending re-run during
`/gsd:verify-work 3` (Plan 12 + auditors). The unit-spec suite (32/32)
verifies the guard's behavioural contract — the live test verifies the
APP_GUARD wiring at the framework layer.

### Task 3 — `fix(03-09-T3): throttler login-email keying via sha256(email).slice(0,16) — FINDING-0022 closure` (`a4283a0`)

**`apps/api/src/common/throttler.config.ts`** — `generateKey` now hashes
the lowercased email with `crypto.createHash("sha256")` and slices the
hex digest to 16 chars before forming the tracker:

```ts
const hashed = createHash("sha256").update(email).digest("hex").slice(0, 16);
tracker = `em:${hashed}`;
```

Effect:
- Redis key length is fixed at 16 hex chars regardless of input — caps
  per-key memory under a flood of arbitrary-length email values.
- The lowercased email PII no longer appears in any Redis key (one-way
  hash).
- 64-bit collision space at our ≤50-user scale: accidental collisions
  are negligible AND a colliding pair only TIGHTENS the throttle (false-
  positive 429), never loosens it.
- Existing `login-email` semantics preserved — the same email always
  hashes to the same key, so 10/email/h continues to enforce.

A new header comment block on the file documents the LOAD-BEARING
invariant that the throttler runs BEFORE Zod validation (guards before
pipes), so any future ceiling that keys off `req.body` MUST bound input
length OR hash to fixed length. Cross-references FINDING-0017 (Plan 01
storage-cap fix) as the second defence-in-depth layer.

---

## Truths verified

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T18 | "Throttler ordering FIXED (FINDING-0021 fold-in). JwtAuthGuard registered as APP_GUARD (with @Public() opt-out for /auth/login, /auth/refresh, /auth/logout, /auth/params, /auth/signup, /invite/redeem, /health) so it runs BEFORE the global SimpleVaultThrottlerGuard. New user-keyed ceilings all key correctly off req.user.id. /me user-keyed limit becomes correct as a side effect." | OK at the code layer (APP_GUARD ordering verified by `grep -n APP_GUARD apps/api/src/app.module.ts` + the JwtAuthGuard provider appears first); LIVE 101/101 reproduction deferred to Plan 12 / verify-work auditors |
| T19 | "Email length cap landed (FINDING-0017 fold-in). [...] Throttler `login-email` keying caps via `sha256(email).slice(0,16)` (closes FINDING-0022 by the same fix)." | OK — `sha256(email).digest('hex').slice(0,16)` in `generateKey`. The storage-cap arm of T19 (`varchar(254)`) was already landed in Plan 01; this commit closes the throttler-key arm. |

---

## Decisions made

1. **Class-level `@Public()` on `WebauthnAuthController`** instead of
   per-method. Both controller methods use the same step-up auth
   pathway, and `Reflector.getAllAndOverride` checks handler first
   then class — no per-method override needed. Reduces decorator noise
   and prevents drift if a third step-up route is added.

2. **Method-level `@Public()` on `TotpController.verify` only.** The
   sibling `/begin-register` and `/finish-register` routes still
   require an access JWT (the user is enrolling a NEW credential under
   their existing identity), so a class-level `@Public()` would have
   been wrong. Method-level keeps the surface explicit.

3. **Kept all pre-existing `@UseGuards(JwtAuthGuard)` decorators.**
   Plan 09 explicitly calls this "optional cleanup; keeping it is
   harmless". The double-invocation hits the SessionEpochCache on the
   second run (Redis GET, ~1ms), so the cost is negligible. Removing
   them would have churned 7 controllers for no behavioural change;
   left as future hygiene if a Phase 13 cleanup pass wants it.

4. **`@Public()` returns `MethodDecorator & ClassDecorator`** rather
   than the broader `CustomDecorator` returned by Nest's `SetMetadata`.
   The narrowed signature documents the intended usage sites and
   prevents accidental application to parameter / property targets.

5. **Hex-slice(0,16) chosen over base64url-slice(0,11) or fixed-length
   binary**. Three reasons:
   - 16 hex chars = exactly 64 bits of collision resistance — same
     guarantee as base64url at one fewer character but consistently
     readable in logs / Redis MONITOR output.
   - The other throttler keys in this file use ASCII tracker prefixes
     (`user:`, `em:`) — staying ASCII keeps Redis tooling (CLI scan,
     redis-cli pattern matching) consistent.
   - Fixed length, not user-controllable — caps memory regardless of
     input.

6. **`createHash` import via `node:crypto`** (NOT `crypto`). Matches
   the rest of the codebase's `node:`-prefix convention for built-ins
   (see `node:crypto` in `apps/api/src/auth/jwt/jwt.service.ts`). The
   prefix is the modern recommended form and avoids ambiguity with
   the `crypto` userland package on npm.

---

## FINDINGS update

Both findings transition from `OPEN` → `FIXED-PENDING-VERIFICATION`.
Promotion to `VERIFIED-CLOSED` requires the live e2e reproduction
(Plan 12) re-run by the rate-limit-dos auditor.

### FINDING-0021 — `/me` throttler keys by IP, not user-id

- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** `8e3215c`
- **Fix summary:** JwtAuthGuard moved to APP_GUARD with registration
  order before SimpleVaultThrottlerGuard. `@Public()` opt-out
  decorator created (commit `859c7e4`). 10 routes opted out of the
  global guard.
- **Re-run pending:** auditor to execute the original reproduction
  (101 `/me` from IP-1 then one from IP-2 with the same JWT — expect
  2nd-IP request to 429 immediately). Live stack required.

### FINDING-0022 — `login-email` keying does not bound input length

- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** `a4283a0`
- **Fix summary:** `generateKey` for `login-email` now keys via
  `sha256(email).slice(0,16)` — fixed-length, no PII in Redis,
  prevents key-flooding amplification. Defence-in-depth via Plan 01's
  `varchar(254)` storage cap (FINDING-0017) still in place; the
  throttler fix is independent because guards run before Zod.
- **Re-run pending:** auditor to execute the original reproduction
  (5 `POST /auth/login` with 4KB random emails, then
  `redis-cli --scan --pattern 'login-email:em:*'` — expect 5 keys
  each of length `login-email:em:<16-hex-chars>`).

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm typecheck` (apps/api) | GREEN |
| `pnpm test` (apps/api, vitest) | GREEN — 32/32 (no regressions; jwt-epoch.spec.ts updated for new ctor signature) |
| `pnpm build` (apps/api, nest build) | GREEN |
| Lint (apps/api) | UNCHANGED — same 8 pre-existing errors at HEAD as at parent commit `5049b0b` (4 in `methods.service.ts` userHasSharedVaultDependency stub + Number() no-op conversions; 4 parsing errors on test files outside the lint tsconfig project). NO new errors introduced. The signup.controller.ts import-order error introduced during T2 was fixed in the same commit before staging. |
| FINDING-0021 live reproduction (101/101 `/me` user-key check) | NOT RUN — requires live Postgres + Redis + API; deferred to verify-work / Plan 12 auditor pass |
| FINDING-0022 live reproduction (Redis key length cap) | NOT RUN — same as above |

---

## Hand-offs

**Plan 03-10 / 03-11 (Web /settings/security + /sessions):** no impact.
The web client doesn't see the guard ordering — it just sees that the
existing `Authorization: Bearer <jwt>` flow continues to work for
authed routes and that step-up routes continue to accept step-up
tokens. The discriminated `LoginResponse` from Plan 08 still works
end-to-end.

**Plan 03-12 (E2E Cypress):** add an explicit regression spec for the
APP_GUARD ordering — a single user authenticated, two browsers (or two
distinct IPs via proxy), each hitting `/me` 60+ times. Pre-Plan-09
both browsers would get a fresh budget; post-Plan-09 the second
browser exhausts the same `me-user` ceiling. This is the live
reproduction of FINDING-0021's negative case.

**Phase 04+ controllers:** new routes default to JWT-required (the
global guard runs). To make a route public, decorate with `@Public()`
from `apps/api/src/auth/jwt/public.decorator.ts`. Step-up routes
combine `@Public()` (opt out of access-token check) with
`@UseGuards(Require2FAStepUpGuard)`.

---

## Files

**Created:**
- `apps/api/src/auth/jwt/public.decorator.ts`
- `.planning/phases/03-2fa-sessions/03-09-SUMMARY.md` (this doc)

**Modified:**
- `apps/api/src/auth/jwt/jwt-auth.guard.ts` (Reflector + IS_PUBLIC_KEY short-circuit)
- `apps/api/src/app.module.ts` (JwtAuthGuard APP_GUARD before throttler)
- `apps/api/src/health/health.controller.ts`
- `apps/api/src/invite/invite.controller.ts`
- `apps/api/src/auth/signup/signup.controller.ts`
- `apps/api/src/auth/login/login.controller.ts`
- `apps/api/src/auth/refresh/refresh.controller.ts`
- `apps/api/src/auth/logout/logout.controller.ts`
- `apps/api/src/twofa/webauthn/webauthn-auth.controller.ts`
- `apps/api/src/twofa/totp/totp.controller.ts`
- `apps/api/src/common/throttler.config.ts`
- `apps/api/test/jwt-epoch.spec.ts`
- `.planning/security/FINDINGS.md` (FINDING-0021 + 0022 → FIXED-PENDING-VERIFICATION)

---

## Next plans unblocked

- **Plan 03-10** (Web `/settings/security` 2FA enrol + remove)
- **Plan 03-11** (Web `/settings/sessions` list + revoke-one + revoke-all)

Both are Wave 6 and run in parallel.
