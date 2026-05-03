---
phase: 03-2fa-sessions
plan: 08
subsystem: auth-login-2fa-branch
tags: [auth, login, 2fa, step-up, anti-enumeration, truth-8, web-client]
requires:
  - 03-02 (StepUpJwtService — same JWT_SECRET, purpose:"2fa-stepup" claim)
  - 03-04 (session-epoch JWT claim — login signs epoch into the access token AND replays it into the step-up token)
  - 03-06 (MethodsService.countActive / list — extended here with countByKind for the per-kind availability flags)
provides:
  - "POST /auth/login branches on 2FA presence (Truth 8)"
  - "MethodsService.countByKind(userId): {webauthn, totp} (per-kind active-method count)"
  - "LoginStepUpResponseBody DTO + LoginStepUpResponseSchema (zod)"
  - "Audit action `auth.login.step_up_issued` with `data.kind:'step-up'` (the `auth.login.ok` event also carries `data.kind:'session'`)"
  - "Web client login() returns a discriminated union (Phase-02 session shape | step-up shape)"
affects:
  - 03-09 (throttler ordering — when JwtAuthGuard becomes APP_GUARD, /auth/login must remain @Public — already on the enumerated allow-list per the INDEX Key Link 10)
  - 03-10 (web /login/2fa page — consumes the sessionStorage-stashed step-up token + twoFa flags)
  - 03-12 (Cypress E2E — must cover both branches; existing 21/21 Phase-02 specs cover the 1FA-only path regression)
tech-stack:
  added: []
  patterns:
    - "Discriminated login response: 2FA-required carries `kind:'2fa-required'`; 1FA-only stays Phase-02 byte-equal (no `kind` field — regression-free)"
    - "Anti-enumeration via post-1FA branching: the 2FA-vs-no-2FA decision happens AFTER the constant-time hash compare. Wrong-creds path is byte-identical across 2FA-enrolled and 2FA-free users (Truth 8)"
    - "Module-cycle resolution: AuthModule ↔ TwoFaModule with `forwardRef(() => ...)` on BOTH sides + `@Inject(forwardRef(() => ...))` on the LoginService constructor params"
    - "Step-up token NEVER carries sid/fam — single-use authorisation to `/2fa/*`. The `__Host-refresh` cookie is intentionally NOT set on the 2FA-required branch (no refresh family yet — created by /2fa/.../finish-auth or /2fa/totp/verify on success)"
key-files:
  created:
    - apps/api/test/login-2fa-branch.spec.ts
  modified:
    - apps/api/src/auth/login/login.service.ts (branches on methods.countActive; emits step-up token; AuditAction.LoginStepUpIssued)
    - apps/api/src/auth/login/login.controller.ts (handles result.kind; skips Set-Cookie on 2fa-required)
    - apps/api/src/auth/login/login.dto.ts (LoginStepUpResponseBody)
    - apps/api/src/auth/auth.module.ts (forwardRef(() => TwoFaModule))
    - apps/api/src/twofa/twofa.module.ts (forwardRef(() => AuthModule))
    - apps/api/src/twofa/methods/methods.service.ts (countByKind primitive — countActive now derived as the sum)
    - apps/api/src/common/audit-events.ts (AuditAction.LoginStepUpIssued = "auth.login.step_up_issued")
    - packages/shared/src/zod/index.ts (LoginStepUpResponseSchema)
    - apps/web/src/lib/api/auth-client.ts (LoginResponseSchema → z.union; LoginSessionResponseSchema + LoginStepUpResponseSchema; types LoginSessionResponse + LoginStepUpResponse)
    - apps/web/src/app/login/page.tsx (branches on `loginRes.kind === "2fa-required"`; sessionStorage hand-off to /login/2fa; 1FA-only path unchanged)
duration: ~45min
completed: 2026-05-02
---

# Phase 03 Plan 08: `/auth/login` branches on 2FA presence (Truth 8) Summary

`/auth/login` now returns either the existing Phase-02 full-session body
(byte-equal regression-free) OR a brand-new 2FA-required body
(`{kind:"2fa-required", stepUpToken, twoFa:{webauthnAvailable, totpAvailable}}`)
when the verified user has ≥1 active 2FA method. The branch HAPPENS AFTER
1FA — wrong-creds path stays uniform across 2FA-enrolled vs 2FA-free users
(anti-enumeration preserved, Truth 8 + Key Link 5).

**Status:** COMPLETE
**Date:** 2026-05-02
**Commits:** `73cef47` (T1 API), `713a5fb` (T2 web)
**Tasks:** 2/2

---

## What landed

### Task 1 — `feat(03-08-T1): /auth/login branches on 2FA presence + step-up emit` (`73cef47`)

**`LoginService.login(...)` (`apps/api/src/auth/login/login.service.ts`)**
- Return type lifted from `LoginOk | null` to `LoginResult | null` where
  `LoginResult = LoginOk | LoginStepUp`. Both `LoginOk` and `LoginStepUp`
  carry an explicit `kind` field (`"session"` / `"2fa-required"`); the
  controller branches on it.
- After the constant-time compare passes, calls
  `methods.countActive(user.id)` (Plan 06's primitive, sum of the
  webauthn + totp tables). When `>= 1`, signs a step-up token via
  `stepUpJwt.sign(user.id, currentEpoch)` and returns the 2FA-required
  body. When `0`, falls through to the Phase-02 session-mint code path
  unchanged.
- Per-kind counts are read via the new `methods.countByKind(user.id)`
  helper (returns `{webauthn, totp}`); these populate
  `twoFa.{webauthnAvailable, totpAvailable}` on the step-up body so the
  web `/login/2fa` page (Plan 10) only renders ceremonies the user
  actually has enrolled.
- New audit action `auth.login.step_up_issued` emitted on the 2FA
  branch with `data: {kind: "step-up"}`. The legacy `auth.login.ok`
  event now carries `data: {familyId, kind: "session"}` — both forensic
  markers per Truth 8 must-have ("the audit row records whether the
  response was step-up or full session").
- The `dummyHash() + constantTimeEqual32` timing-floor is unchanged.
  The `methods.countActive` query runs ONLY after the user row was
  found and the hash matched — pre-1FA paths NEVER touch the 2FA
  tables, so wrong-creds wall-time is identical for 2FA-enrolled and
  2FA-free users (Truth 8 anti-enumeration).

**Module wiring (`auth.module.ts`, `twofa.module.ts`)**
- `LoginService` now depends on `MethodsService` + `StepUpJwtService`
  (both exported by `TwoFaModule`). `TwoFaModule` already imported
  `AuthModule` (for `JwtService`); the new dependency creates a cycle.
- Resolved via `forwardRef(() => TwoFaModule)` on `AuthModule` AND
  `forwardRef(() => AuthModule)` on `TwoFaModule`. The constructor
  params of `LoginService` use `@Inject(forwardRef(() => ...))`.
- See [NestJS docs — Circular dependency](https://docs.nestjs.com/fundamentals/circular-dependency).

**`LoginController.login(...)`**
- Branches on `result.kind`:
  - `"session"` → existing Phase-02 path: set `__Host-refresh` cookie +
    return the legacy body byte-equal.
  - `"2fa-required"` → return the step-up body. NO Set-Cookie. The
    user has no refresh family yet; the family is created by
    `/2fa/webauthn/finish-auth` or `/2fa/totp/verify` once the 2FA
    ceremony completes.

**`MethodsService.countByKind(userId)`** — new primitive returning
`{webauthn, totp}`. The existing `countActive` is now derived as the
sum of the two values (single source of truth, no drift).

**Zod (`packages/shared/src/zod/index.ts`)** — added
`LoginStepUpResponseSchema` for the 2FA-required body. The existing
`LoginResponseSchema` (Phase-02 1FA body) is unchanged in `shared`
because Phase-02 callers consume only the legacy shape from there;
the union lives in the web client where the discrimination is needed.

**Test (`apps/api/test/login-2fa-branch.spec.ts`)** — 8 invariants,
mock-based (fake DbService + sessions + methods stubs; real
`JwtService` + real `StepUpJwtService` so JWT crypto is honest):
1. Wrong creds against a 2FA-free user → null (no oracle).
2. Wrong creds against a 2FA-enrolled user → null (byte-equal to (1)
   — anti-enumeration).
3. Unknown email → null (uniform with wrong creds).
4. Correct creds + 0 active methods → `{kind:"session"}` with the
   Phase-02 body intact + refresh family created.
5. Correct creds + ≥1 active method → `{kind:"2fa-required"}` with
   stepUpToken + twoFa flags; NO accessToken in body; NO refresh
   family created.
6. Step-up token claims: `purpose:"2fa-stepup"`, `epoch` matches the
   user's session_epoch, `exp = iat + 120`.
7. Step-up token rejected by `JwtService.verifyAccessToken`
   (Key Link 5 dual: a step-up token cannot impersonate an access
   token even though they share `JWT_SECRET`).
8. `twoFa.{webauthnAvailable, totpAvailable}` reflect per-kind counts
   (webauthn-only, totp-only, both — all three combinations
   asserted).

Verify gate: `pnpm --filter @simplevault/api test` 32/32 GREEN
(8 new + 24 prior across `jwt-epoch.spec.ts`, `2fa-removal.spec.ts`,
`2fa-required-guard.spec.ts`). `pnpm --filter @simplevault/api build`
green. `pnpm --filter @simplevault/shared build` green.

### Task 2 — `feat(03-08-T2): web auth-client handles discriminated login response` (`713a5fb`)

**`apps/web/src/lib/api/auth-client.ts`**:
- Split the legacy `LoginResponseSchema` into
  `LoginSessionResponseSchema` (Phase-02 1FA body — UNCHANGED, no
  `kind` field) + new `LoginStepUpResponseSchema` (`{kind, stepUpToken,
  twoFa}`).
- `LoginResponseSchema = z.union([stepUp, session])` — the union order
  matters: the explicit-discriminator shape goes FIRST so a future
  extension of the step-up shape never accidentally matches as a
  session shape.
- Exposed `LoginSessionResponse` + `LoginStepUpResponse` types
  alongside the union `LoginResponse`. Existing callers that only
  use the session branch can narrow via
  `Exclude<LoginResponse, {kind: "2fa-required"}>` or via a runtime
  `"kind" in res`-check.

**`apps/web/src/app/login/page.tsx`**:
- After `apiLogin(...)` resolves, check
  `(loginRes as { kind?: unknown }).kind === "2fa-required"`. If true:
  - Stash `{token, twoFa}` in `sessionStorage` under the key
    `"sv:step-up"` for the `/login/2fa` page (Plan 10) to pick up.
  - Wipe any partial 1FA in-memory state (`accessTokenStore.wipe`,
    `keyStore.wipe`, zero the `secretKey` Uint8Array).
  - Redirect to `/login/2fa` (404 until Plan 10 ships — see
    inter-wave gap below).
- Otherwise: continue Phase-02 flow unchanged
  (`accessTokenStore.set(...)` → `unlockSecrets(...)` →
  `keyStore.set(...)` → `/me`).
- TS narrowing for the post-early-return path uses
  `Exclude<typeof loginRes, { kind: "2fa-required" }>` — `as`-casts
  alone don't narrow the union; the explicit `Exclude` is the
  language-level idiom for this pattern.

Verify gate: `pnpm --filter @simplevault/web build` GREEN
(production Next.js build).

---

## Truths verified

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T8 | `/auth/login` returns `{stepUpToken, twoFa:{webauthnAvailable, totpAvailable}}` (HTTP 200, NO accessToken, NO `__Host-refresh` cookie, NO wrapped material) when the verified user has ≥1 active 2FA method. Step-up token: `{sub, purpose:"2fa-stepup", epoch}`, `exp = iat + STEP_UP_TOKEN_TTL`, NO `sid`/`fam`. Body shape distinguishes only AFTER 1FA passes — wrong-creds path is byte-equal across 2FA-enrolled and 2FA-free users (anti-enumeration). | OK — `LoginService` branches strictly after the constant-time compare; `LoginController` skips Set-Cookie on the 2fa-required path. Audit row carries `data.kind: "step-up"` for forensics. Spec (1) + (1') + (1'') exercise the byte-equal wrong-creds path. |

---

## Decisions Made

1. **No `kind` discriminator on the 1FA-only branch.** The plan's
   pseudocode showed both branches carrying `kind:"session"` /
   `kind:"2fa-required"`. The plan's must-have section explicitly
   says "POST /auth/login when verified user has 0 active 2FA
   methods: response IS Phase-02's existing 200 body — REGRESSION-FREE"
   AND "Existing 21/21 Phase-02 E2E suite still passes". Adding a
   `kind:"session"` field would break byte-equal regression for
   every Phase-02 caller. Instead: 1FA branch keeps the legacy body
   shape (no `kind`); 2FA branch carries `kind:"2fa-required"`. The
   web client distinguishes via `"kind" in body`. Documented inline
   in `LoginStepUpResponseBody` jsdoc.

2. **Step-up + audit event carry `data.kind` strings (`"session"` /
   `"step-up"`)** — Truth 8's must-have ("audit event records whether
   the response was step-up or full session") is satisfied by adding
   the `kind` to the existing `auth.login.ok` event AND by
   introducing `auth.login.step_up_issued` for the step-up branch.
   Two-event approach (rather than overloading `LoginOk` with both
   outcomes) lets a future operator dashboard partition by action
   name AND by `data.kind` — orthogonal axes, useful for forensics.

3. **forwardRef on BOTH sides of AuthModule ↔ TwoFaModule.** The
   alternative was extracting `MethodsService` + `StepUpJwtService`
   into a shared submodule both root modules import. The forwardRef
   pattern is 4 lines of code total + matches the surrounding NestJS
   idiom; the submodule extraction would have churned 6 files and
   created a third module to maintain. Re-evaluate in Phase 13 if a
   third pair of cross-references appears.

4. **`countByKind` is the new primitive; `countActive` is the
   derived sum.** Two reasons:
   (a) Single source of truth — the per-kind counts power both the
   2FA-required body's `twoFa` flags AND the existing `countActive`
   call sites (removal-guard, Require2FAGuard's count reader).
   (b) Performance — both queries run regardless (we always need
   the totals to decide branching), so deriving `countActive` from
   `countByKind` adds zero round-trips.

5. **No refresh family on the 2FA-required branch.** The user has
   not yet completed authentication; minting a refresh family at
   1FA-pass would mean a stolen step-up token could be exchanged
   for a refresh chain via the `/2fa/*/finish-auth` endpoints.
   Instead: the family is created INSIDE `webauthn-auth.service.ts`
   `finishAuth` and `totp.service.ts` `verify` once the 2FA ceremony
   completes. This matches Plan 02's existing implementation
   (verified in `webauthn-auth.service.ts:finishAuth` calls
   `sessions.createOnLogin`).

6. **`sessionStorage` for the step-up hand-off (web).** Alternatives
   considered: in-memory React context (lost on the page navigation),
   URL query string (leaks the token to logs / referer / browser
   history), `localStorage` (persistent — wrong durability for a
   120s-TTL token). `sessionStorage` is the closest match: scoped to
   the tab, cleared on tab close, not sent to the server, not in
   history. Plan 10 may revisit (e.g. switching to a `Map<string, ...>`
   in a singleton singleton service if a tab refresh between /login
   and /login/2fa is a UX concern).

7. **Zod union is non-discriminated (`z.union`), not `z.discriminatedUnion`.**
   `z.discriminatedUnion("kind", [...])` requires every shape to
   carry the discriminator — but the 1FA-only branch deliberately
   has NO `kind` field (decision 1). `z.union` parses each shape in
   order; we put the explicit-discriminator shape FIRST so 1FA
   bodies never accidentally match a future step-up extension.

---

## Anti-enumeration verification approach

The plan's must-have section asks for "byte-equal envelope across
both 2FA-enrolled and 2FA-free wrong-credentials paths". The
verification approach used here:

**Code-level proof (load-bearing):**
- `LoginService.login` runs the constant-time compare BEFORE any
  database read into `webauthn_credentials` / `totp_credentials`.
- The wrong-creds path returns `null` directly, identical for both
  user types (specs 1, 1', 1'').
- The controller's wrong-creds path is a single throw site:
  ```ts
  throw new HttpException(
    { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
    HttpStatus.UNAUTHORIZED,
  );
  ```
  No per-user branching → the response body is byte-equal regardless
  of the user's 2FA enrollment.
- `dummyHash()` substitution (existing Phase-02 behaviour) handles
  the unknown-email case.

**Test-level proof (regression-guard):**
- Spec (1) and (1') in `login-2fa-branch.spec.ts` both assert
  `result === null` for wrong creds against the two user kinds.
  Combined with the controller's single throw site, the response
  body is identical at the HTTP layer.
- A future hardening pass could add a controller-level integration
  test (NestJS testing harness) that asserts byte-equality of the
  serialised JSON envelope. Deferred to Plan 12 (real e2e).

**Timing-level proof:**
- The Phase-02 timing floor (`constantTimeEqual32` always runs;
  `dummyHash()` substitutes for missing user) is unchanged. The
  2FA-presence query runs ONLY after the compare passes, so a
  successful-1FA path reads the 2FA tables exactly once — and a
  failed-1FA path NEVER reads them. Wall-time of wrong-creds is
  byte-identical across user kinds (within DB jitter).

---

## Inter-wave gap: `/login/2fa` until Plan 10

Plan 10 (web /settings/security + the new `/login/2fa` page) ships
the consumer of the step-up sessionStorage hand-off. Until Plan 10
lands, a 2FA-enrolled user attempting the web login flow will:
1. Successfully complete the 1FA leg.
2. Get redirected to `/login/2fa` (which doesn't exist yet → 404).

This is **acceptable for the inter-wave window** because:
- No test users have 2FA enrolled in any deployed environment yet
  (Plan 02-12 E2E suite runs entirely as 2FA-free).
- The API path is regression-tested by the new
  `login-2fa-branch.spec.ts` (server-side) — Plan 10 will add the
  Cypress end-to-end coverage for the web path.
- A user who accidentally lands here can refresh, navigate manually
  to `/login`, and try again — they're not stuck behind anything
  destructive (no session was created on the 2FA-required branch).

Plan 10's first commit should ship `/login/2fa/page.tsx` reading
`sessionStorage.getItem("sv:step-up")` and dispatching to either
the WebAuthn or TOTP ceremony based on `twoFa` availability.

---

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 — Blocking] Module cycle AuthModule ↔ TwoFaModule.**

- **Found during:** Task 1 build verification.
- **Issue:** `LoginService` (in AuthModule) needed to inject
  `MethodsService` + `StepUpJwtService` (both exported by
  TwoFaModule). TwoFaModule already imported AuthModule for
  `JwtService`. The plan's pseudocode glossed over this — it just
  says "inject the helpers". NestJS would have thrown
  `UndefinedModuleException` at boot otherwise.
- **Fix:** `forwardRef(() => TwoFaModule)` on `AuthModule.imports`,
  `forwardRef(() => AuthModule)` on `TwoFaModule.imports`,
  `@Inject(forwardRef(() => ...))` on the two new constructor
  params of `LoginService`. Standard NestJS idiom (link in the
  jsdoc).
- **Files modified:** `apps/api/src/auth/auth.module.ts`,
  `apps/api/src/twofa/twofa.module.ts`,
  `apps/api/src/auth/login/login.service.ts`.
- **Commit:** rolled into T1 (`73cef47`).

**2. [Rule 1 — Bug] TS narrowing on the discriminated union (web).**

- **Found during:** Task 2 build verification.
- **Issue:** `if ("kind" in loginRes)` doesn't narrow a Zod-derived
  `z.union(...)` because the 1FA-only branch has no `kind` field
  AT ALL — TypeScript can't use the existence check as a
  discriminant. The compiler reported `Property 'accessToken' does
  not exist on the union`.
- **Fix:** Two `as`-casts — `(loginRes as { kind?: unknown }).kind`
  for the early-return check, and
  `Exclude<typeof loginRes, { kind: "2fa-required" }>` to narrow
  the post-early-return branch to the session shape. Verified
  type-correct via `pnpm --filter @simplevault/web build`.
- **Files modified:** `apps/web/src/app/login/page.tsx`.
- **Commit:** rolled into T2 (`713a5fb`).

**3. [Rule 2 — Defence-in-depth] Audit event renaming +
   dual-emit pattern.**

- **Found during:** Task 1 implementation.
- **Issue:** Truth 8's must-have says "audit row records whether
  the response was step-up or full session". The plan's pseudocode
  showed `auth.login.step_up_issued` for the step-up branch but
  said nothing about the existing `auth.login.ok` event.
- **Fix:** Both events now carry a `data.kind` string: the
  step-up branch emits `auth.login.step_up_issued` with
  `data: {kind: "step-up"}`; the session branch emits the existing
  `auth.login.ok` with `data: {familyId, kind: "session"}`. Two
  orthogonal forensic axes (action name AND data.kind) for the
  Phase 10 operator dashboard.
- **Files modified:** `apps/api/src/common/audit-events.ts`,
  `apps/api/src/auth/login/login.service.ts`.
- **Commit:** rolled into T1 (`73cef47`).

### No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

### Pre-existing lint issues (not introduced by this plan)

The `pnpm --filter @simplevault/api lint` run reports 8 errors at
HEAD — but they were ALL present at the parent commit
(`66e66a8`):
- 2 errors on `userHasSharedVaultDependency` stub
  (`_userId` unused, `require-await` because the stub is
  `async () => false`).
- 2 errors on `Number(...)` "no-op type conversions" inside
  `MethodsService.countByKind` (which is the relocation of the
  same `Number()` calls that previously existed at lines 137-138
  of `methods.service.ts` — moved by my refactor, count
  unchanged).
- 4 parsing errors on test files (the 4 vitest specs aren't in
  the lint tsconfig project — pre-existing config gap from Plan
  04 / 06 / 07).
- The lint error in `apps/web/next-env.d.ts` is on an
  auto-generated Next.js file (no commit to revert).

Verification: `git stash && pnpm --filter @simplevault/api lint`
at parent reports the same 8-error count at the same approximate
locations. No NEW lint errors introduced by Plan 03-08.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm --filter @simplevault/api build` | GREEN |
| `pnpm --filter @simplevault/api test` (vitest, all specs) | GREEN — 32/32 (8 new in `login-2fa-branch.spec.ts` + 24 prior across `jwt-epoch` / `2fa-removal` / `2fa-required-guard`) |
| `pnpm --filter @simplevault/shared build` | GREEN |
| `pnpm --filter @simplevault/web build` | GREEN (Next.js production build, type-check clean) |
| Phase-02 E2E regression (no-2FA path) | UNTESTED LOCALLY (no E2E harness in this plan; Plan 12's Cypress run is the verification step). The unit-test layer asserts that the 1FA-only response shape is byte-identical to the Phase-02 body (spec (2) above), which is the necessary precondition. |
| Step-up token rejected by `/me` | OK at the JWT layer — spec (5) asserts `JwtService.verifyAccessToken` throws on a step-up token. The production guard adds a pre-decode `purpose !== undefined` rejection on top (Plan 02-T1, exercised by `2fa-required-guard.spec.ts`). |
| Anti-enumeration (byte-equal wrong-creds envelope across 2FA-enrolled vs 2FA-free) | OK — specs (1) + (1') both return null; controller has a single throw site with no per-user branching. |

---

## Hand-offs

**Plan 03-09 (throttler ordering):**
- `/auth/login` continues to need `@Public()` (it must be
  reachable without an access token). Already on the INDEX
  Key Link 10 enumerated allow-list. The 2FA-required body now
  also exits without a refresh cookie — the existing throttler
  (login-ip + login-email keying) remains correct on this path.

**Plan 03-10 (web /settings/security + /login/2fa):**
- `/login/2fa/page.tsx` reads
  `sessionStorage.getItem("sv:step-up")` parses
  `{token, twoFa: {webauthnAvailable, totpAvailable}}`.
- Dispatches to the WebAuthn ceremony (`POST /2fa/webauthn/begin-auth`)
  if `twoFa.webauthnAvailable`, otherwise the TOTP form (POST
  `/2fa/totp/verify`) if `twoFa.totpAvailable`. UI presents passkey
  as primary CTA per Phase 03 INDEX Key Link 12.
- After successful 2FA, the relevant `/finish-auth` / `/verify`
  endpoint mints the access token + refresh cookie (Phase-02
  parity), and the page redirects to `/me`.
- Step-up token has 120s TTL — the page should display a "code
  expires in N seconds" countdown so the user knows when to
  restart from /login.

**Plan 03-12 (Cypress E2E):**
- New spec: 2FA-enrolled login → /login/2fa → WebAuthn or TOTP →
  /me. Cypress's virtual-authenticator API drives WebAuthn; TOTP
  uses the deterministic test vectors from
  `packages/crypto/test/totp.test.ts`.
- Regression spec: 2FA-free login still hits the legacy /me
  redirect (Phase-02 21/21 must remain green).
- Anti-enumeration spec: wrong-creds against 2FA-enrolled vs
  2FA-free returns identical 401 envelopes (assert byte-equal
  response.text) — the test that the unit specs can't run because
  they don't go through the controller.

---

## Files

**Created:**
- `apps/api/test/login-2fa-branch.spec.ts` (~340 lines, 8 specs)

**Modified:**
- `apps/api/src/auth/login/login.service.ts` (branch on 2FA + audit dual-emit)
- `apps/api/src/auth/login/login.controller.ts` (`result.kind` switch; skip Set-Cookie on 2fa-required)
- `apps/api/src/auth/login/login.dto.ts` (LoginStepUpResponseBody)
- `apps/api/src/auth/auth.module.ts` (forwardRef → TwoFaModule)
- `apps/api/src/twofa/twofa.module.ts` (forwardRef → AuthModule)
- `apps/api/src/twofa/methods/methods.service.ts` (countByKind primitive; countActive derived)
- `apps/api/src/common/audit-events.ts` (LoginStepUpIssued)
- `packages/shared/src/zod/index.ts` (LoginStepUpResponseSchema)
- `apps/web/src/lib/api/auth-client.ts` (LoginResponseSchema → z.union; new types)
- `apps/web/src/app/login/page.tsx` (branch on `kind === "2fa-required"`; sessionStorage hand-off)

---

## Next plans unblocked

- **Plan 03-09** (throttler ordering — already independent of Plan 08;
  this plan adds no new ceilings).
- **Plan 03-10** (web /settings/security + /login/2fa) — consumes
  the step-up sessionStorage hand-off.
- **Plan 03-12** (E2E) — new specs for both branches + the
  anti-enumeration byte-equality assertion.
