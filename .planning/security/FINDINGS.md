# SimpleVault — Security Findings Tracker

All findings reported by security auditor agents (manual or automated). Tracked from open → fixed → verified.

**Severity scale:** Critical / High / Medium / Low / Info (mapped to CVSS v3.1 base score where applicable).

**Gate rule:** No Critical or High finding may remain `OPEN` when a phase is marked complete. Medium/Low can be deferred with explicit operator sign-off and a follow-up phase commitment.

---

## Schema (per finding)

```
### FINDING-XXXX — short title

- **Severity:** Critical | High | Medium | Low | Info
- **CVSS:** (if applicable)
- **Reporter:** [agent-name] OR operator OR external
- **Date opened:** YYYY-MM-DD
- **Phase:** XX
- **Affected:** files / endpoints / flows
- **Description:** what is wrong
- **Reproduction:** steps / PoC
- **Recommendation:** how to fix
- **Status:** OPEN | IN-PROGRESS | FIXED-PENDING-VERIFICATION | VERIFIED-CLOSED | WONTFIX-WITH-RATIONALE
- **Resolved-by-commit:** sha (when fixed)
- **Verified-by:** [agent-name] on YYYY-MM-DD
```

---

## Open findings

### FINDING-0001 — next@15.1.0 RCE via React-flight protocol (GHSA-9qr9-h5gf-34mp)

- **Severity:** Critical
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/web/package.json` (`next@15.1.0`)
- **Description:** Known critical RCE in Next.js < 15.5.15 via React-flight protocol.
- **Recommendation:** Bump `next` to `^15.5.15` (or latest stable 15.x). Re-run `pnpm install` and verify `apps/web` builds + middleware/CSP still works.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 59c2e19
- **Verified-by:** dependency-supply-chain-auditor on 2026-04-29 (lockfile resolves next@15.5.15)

### FINDING-0002 — next@15.1.0 middleware auth bypass (GHSA-f82v-jwr5-mffw)

- **Severity:** Critical
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/web/package.json` (`next@15.1.0`)
- **Description:** Auth-bypass in Next.js middleware. SimpleVault uses middleware for security headers + (future) auth gating, so this is a direct hit on a load-bearing layer.
- **Recommendation:** Bump `next` to `^15.5.15`. Same upgrade as FINDING-0001.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 59c2e19
- **Verified-by:** dependency-supply-chain-auditor on 2026-04-29 (lockfile resolves next@15.5.15)

### FINDING-0003 — drizzle-orm@0.38.4 SQL injection via identifier (GHSA-gpj5-g38j-94v9)

- **Severity:** High
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `packages/db/package.json`, `apps/api/package.json` (`drizzle-orm@0.38.4`); also `drizzle-kit@0.30.6`
- **Description:** SQL-injection-via-identifier in drizzle-orm — direct hit on the data layer of a vault product. Only `users` stub schema today, but every later schema runs through this.
- **Recommendation:** Bump `drizzle-orm` to `^0.45.2` (and `drizzle-kit` to a matching stable version). Re-generate migration with new drizzle-kit and re-verify against PG 18.3 (Plan 08 verification path).
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 8a31481
- **Verified-by:** dependency-supply-chain-auditor on 2026-04-29 (drizzle-orm@0.45.2, drizzle-kit@0.31.10, PG 18.3 e2e re-verified)

### FINDING-0004 — multer@2.0.2 DoS CVEs via @nestjs/platform-express@10.4.22 (3× High)

- **Severity:** High
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/api/package.json` (`@nestjs/platform-express@10.4.22` → transitive `multer@2.0.2`)
- **Description:** Three High DoS CVEs in `multer@2.0.2`, fixed in `multer >= 2.1.1`.
- **Recommendation:** Either upgrade `@nestjs/*` from 10.4.x to `^11` (preferred, broader hardening) or pin `multer >= 2.1.1` via `pnpm.overrides` in root package.json as a stop-gap.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 71c6399 (pnpm.overrides path; full Nest 11 upgrade slated for Phase 02)
- **Verified-by:** dependency-supply-chain-auditor on 2026-04-29 (multer@2.1.1 single resolution; tracked tech-debt: remove override after Nest 11 lands)

### FINDING-0005 — postgres service in docker-compose missing cap_drop: [ALL]

- **Severity:** High
- **Reporter:** infra-deployment-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `docker-compose.yml` (postgres service)
- **Description:** Defense-in-depth gap: postgres container retains the full default Linux capability set. Other services in this compose drop ALL caps; postgres + redis are the exceptions.
- **Recommendation:** Add `cap_drop: [ALL]` and only add back what postgres needs (`SETUID`, `SETGID`, `DAC_READ_SEARCH` for the official image initdb path). Test with `docker compose up -d` that postgres still starts and is healthy.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 579ea8d
- **Verified-by:** infra-deployment-auditor on 2026-04-29 (cap_drop:[ALL] + minimal cap_add; postgres healthy)

### FINDING-0006 — redis service in docker-compose missing cap_drop: [ALL]

- **Severity:** High
- **Reporter:** infra-deployment-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `docker-compose.yml` (redis service)
- **Description:** Same defense-in-depth gap as FINDING-0005, on the redis service.
- **Recommendation:** Add `cap_drop: [ALL]`. Redis (alpine) typically needs no caps added back.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 579ea8d (cap_drop ALL applied; SETUID/SETGID added back — entrypoint needs them to drop to the redis user, otherwise the container restart-loops)
- **Verified-by:** infra-deployment-auditor on 2026-04-29 (redis healthy, minimal caps acceptable)

### FINDING-0007 — apps/api missing `dev` script (Truth 4 gap)

- **Severity:** Low
- **Reporter:** gsd-verifier
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/api/package.json`
- **Description:** Truth 4 of 01-INDEX.md states "`pnpm dev` starts both web (`:3000`) and api (`:3001`) concurrently." `apps/api` declares `start:dev` only — `turbo run dev` silently skips api. The `docker compose up -d` path (operator's actual goal) is fully met, so this is a literal-wording gap, not a functional gap.
- **Recommendation:** Add `"dev": "nest start --watch"` to `apps/api/package.json` scripts. One-line change.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** 31574f8
- **Verified-by:** gsd-verifier on 2026-04-29 (Truth 4 passes; `turbo run dev --dry=json` schedules both api and web)

### FINDING-0008 — container scan workflow path-filtered

- **Severity:** Info
- **Reporter:** gsd-verifier
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `.github/workflows/container-scan.yml`
- **Description:** Workflow only triggers on changes to Dockerfiles, lockfile, or package.json — code-only PRs do not run Trivy. Intentional cost optimization, but creates a window where new `RUN`/dependency-pulled-via-CI changes could introduce image-level issues silently.
- **Recommendation:** Add a weekly cron `schedule:` trigger to container-scan.yml so all merged code is scanned at least every 7 days regardless of which paths changed. Non-blocking.
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** bac1fa3
- **Verified-by:** gsd-verifier on 2026-04-29 (weekly cron present; informational finding)

### FINDING-0009 — lodash@4.17.21 prototype-pollution residual (GHSA-r5fr-rjxr-66jc) [opened+closed same gate cycle]

- **Severity:** High
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-29 (re-run; was carried-residual on 2026-04-28 because no upstream patch existed at that time)
- **Phase:** 01
- **Affected:** transitive of `@nestjs/config@3.3.0` → `lodash@4.17.21`
- **Description:** Prototype-pollution in lodash < 4.18. On 2026-04-28 no fix existed upstream and the finding was accepted as residual. Between then and 2026-04-29 lodash published 4.18.0 and 4.18.1, making it patchable.
- **Recommendation:** Pin via `pnpm.overrides` `lodash@<4.18.0 -> >=4.18.1`. Tech debt: remove override when @nestjs/config picks up lodash@^4.18 natively (likely with NestJS 11 upgrade in Phase 02).
- **Status:** VERIFIED-CLOSED
- **Resolved-by-commit:** ac55411
- **Verified-by:** dependency-supply-chain-auditor verdict (lockfile resolves lodash@4.18.1; `pnpm audit --prod --audit-level=high` shows 0 high)

### FINDING-0010 — Error envelope `requestId` breaks byte-equal response invariant on /auth/login + /invite/redeem

- **Severity:** High
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/common/filters/all-exceptions.filter.ts:14-16,58`; consumed by `apps/web/cypress/e2e/auth-sad.cy.ts:64,133`
- **Description:** `AllExceptionsFilter.catch()` reads `req.id` (auto-populated per request by `nestjs-pino` / `pino-http`) and embeds it as `error.requestId` in every error response body. Two consecutive `/auth/login` failure responses (or two `/invite/redeem` failure responses) therefore produce JSON bodies that differ by the per-request id even when status, code, and message are identical. The Phase-02 anti-enumeration invariant (truth #6) calls for byte-equal failure responses across miss types; the Cypress sad-path spec asserts `JSON.stringify(resA.body) === JSON.stringify(resB.body)`. The differing bytes are not themselves a miss-type oracle (an attacker cannot infer wrong-email vs. wrong-secret-key from a request id), but the auditor mandate (".planning/security/AGENTS.md") explicitly classifies any drift from byte-equality as HIGH and blocking for Phase 02.
- **Recommendation:** Move `requestId` out of the JSON body into a response header (`X-Request-Id`), generated in a global Express middleware and consumed by Pino + filter. Update web `AuthClientError` to read it from headers. Body becomes strictly `{error:{code, message}}` for all failure responses on `/auth/login` and `/invite/redeem`. Re-run the Cypress sad-path spec to confirm byte-equality.
- **Status:** VERIFIED-CLOSED
- **Verified-by:** auth-flow-auditor on 2026-05-02 (re-run section "RE-RUN 2026-05-02 — FINDING-0010 closure verification" in `.planning/security/audit-reports/2026-05-02-auth-flow-auditor-phase02.md`; body now strictly `{error:{code,message}}`, requestId moved to `X-Request-Id` header, pino-http counter is server-controlled — no inbound-header trust vector)

### FINDING-0011 — POST /invite/redeem leaks invite-bound email on success

- **Severity:** Medium
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/invite/invite.service.ts:64-69`; `apps/api/src/invite/invite.dto.ts` (`InviteRedeemResponse.email`)
- **Description:** A successful `POST /invite/redeem` returns the invite-bound `email` in the response body. An attacker who obtains a leaked invite code through any side channel (operator distribution channel breach, screenshot leak, OOB intercept) can probe the endpoint to recover the *target user's* email — useful for downstream phishing / social engineering / attribution. The legitimate user already knows their own email out-of-band; the endpoint does not need to teach it back.
- **Recommendation:** Drop `email` from the redeem response. Preferred: require the redeemer to submit `{code, email}` and verify both match before returning success — turns the invite into a two-factor binding (code + email). Anti-enumeration is preserved by collapsing every miss to the canonical `AUTH_INVITE_INVALID` 400 (already done). Alternative: leave the wizard to ask for the email at signup time and let the unique-email index handle dupes.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0012 — POST /auth/logout returns 200 with body, web client expects 204

- **Severity:** Low
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/auth/logout/logout.controller.ts:17,54`; `apps/web/src/lib/api/auth-client.ts:178-180,297-304`
- **Description:** Server logout uses `@HttpCode(HttpStatus.OK)` and returns `{ ok: true }`. Web client `request()` short-circuits to `undefined` only on 204; the comment in `auth-client.ts:298` ("Server returns 204 No Content") is stale. The schema `z.unknown()` accepts the 200 body so behaviour is correct; defence-in-depth (local wipe on API failure in `auth-context.tsx:79-89`) holds. Inconsistency, not a security issue.
- **Recommendation:** Change server to `@HttpCode(204)` and `return undefined`, OR update the web comment + drop the 204 special case. Pick one consistent contract.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0013 — useAutoRefresh dead-string clauses for AUTH_REFRESH_REUSED / AUTH_INVALID_CREDENTIALS

- **Severity:** Low
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/web/src/lib/auth/use-auto-refresh.ts:65-71`
- **Description:** The auto-refresh hook compares `e.code` against literal strings `"AUTH_REFRESH_REUSED"` and `"AUTH_INVALID_CREDENTIALS"`. The shared error-code constants are `AUTH_REFRESH_REUSE_DETECTED` (value `"E1005"`) and `AUTH_INVALID_CREDENTIALS` (value `"E1001"`); the server emits the *values* `"E1005"` / `"E1001"`, not the constant names. The fallback clauses `e.status === 401`, `e.code === "E1005"`, and `e.code === "E1001"` already cover every real path, so behaviour is correct, but two of the five OR clauses are dead code that will silently rot if either constant name changes.
- **Recommendation:** Import `ErrorCodes` from `@simplevault/shared/errors` and compare against the canonical *values* (`ErrorCodes.AUTH_REFRESH_REUSE_DETECTED`, `ErrorCodes.AUTH_INVALID_CREDENTIALS`). Drop the literal-name strings.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0014 — `/auth/refresh` and `/auth/logout` accept arbitrary bodies (no `.strict()` empty-body schema)

- **Severity:** Low
- **Reporter:** input-validation-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:**
  - `apps/api/src/auth/refresh/refresh.controller.ts:24-45`
  - `apps/api/src/auth/logout/logout.controller.ts:19-25`
- **Description:** Both controllers ignore the request body entirely (refresh token comes from the `__Host-refresh` cookie). No Zod schema rejects unknown bodies, so a client can POST arbitrary JSON up to the global Express body-parser limit. Not exploitable today (body is unread) but a future contributor could add fields without realising the contract was unset; defence-in-depth gap.
- **Recommendation:** Add `z.object({}).strict()` parsing in both controllers; reject 400 with `VALIDATION_FAILED` on any non-empty body. Trivial change.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0015 — Express body-parser limit not explicitly configured in `main.ts`

- **Severity:** Low
- **Reporter:** input-validation-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/main.ts:10-66`
- **Description:** No explicit `app.useBodyParser('json', { limit: '...' })` or `app.use(json({ limit }))`. Nest 11 + body-parser default JSON limit is 100 KiB — comfortably above legitimate Phase 02 payloads (~3 KiB signup envelope) and below DoS-relevant sizes, so the current default is fine, but the cap should be set explicitly so a future endpoint refactor doesn't silently inherit it.
- **Recommendation:** In `bootstrap()`, set `app.useBodyParser('json', { limit: '64kb' })`. Larger payload endpoints in Phase 04 (vault items) opt in per-route.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0016 — Argon2 iteration upper bound (64) is generous vs. recommended ceiling (10)

- **Severity:** Low
- **Reporter:** input-validation-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/auth/signup/signup.dto.ts:59`
- **Description:** Phase-02 audit mandate sets KDF parameter bounds at `time ∈ [2, 10]`, `memory ∈ [19456, 1 048 576]`. Current Zod cap on `iterations` is 64 (lower-bounded server-side at ≥ 2 by `crypto.service.validateArgon2ParamsAboveFloor`). Because the verifier comparison is a byte-compare (no per-request server Argon2), a high `iterations` is self-DoS only — the *client* re-runs Argon2 with stored params on every login. Tightening the cap aligns the implementation with the spec and prevents a malicious wizard from saving a value the user can't unwrap on a low-end device.
- **Recommendation:** Tighten the Zod ceiling to `iterations ≤ 10`. Memory upper bound is already correct.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0017 — `users.email` / `invite_codes.email` and `LoginSchema.email` lack a length cap

- **Severity:** Medium
- **Reporter:** input-validation-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:**
  - `packages/db/src/schema/users.ts:35`
  - `packages/db/src/schema/invite_codes.ts:35`
  - `apps/api/src/auth/login/login.dto.ts:23` (`z.string().email()` lacks `.max(254)`)
- **Description:** Both columns are `text` (PG unbounded). The login DTO validates `z.string().email()` with no `.max(N)`, so a multi-megabyte string passes the (regex-lenient) `email()` parser and reaches the `lower(email)` index lookup. Bounded today by the 100 KiB body-parser default (FINDING-0015) but defence-in-depth gap on the storage tier — every comparison and index update pays per-byte cost.
- **Recommendation:** Add `.max(254)` (RFC 5321 ceiling) to the Zod email field on `LoginSchema`. Migrate `email` columns to `varchar(254)` or add a CHECK constraint via Drizzle migration. Apply the same cap to the CLI `invite create` email validator.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0018 — Web `/login` form does not validate email with a Zod schema before submit

- **Severity:** Medium
- **Reporter:** input-validation-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/web/src/app/login/page.tsx:88-106`
- **Description:** The form trims + lowercases the email but does not run a Zod schema (no react-hook-form + zod-resolver pattern; validation is hand-coded to non-empty checks). On a typo, the client wastes a server round-trip *and* a multi-second client-side Argon2id derivation before the server rejects the malformed email. UX-degrading and abuse-amplifying — every retry burns Argon2 watt-hours on the user's device.
- **Recommendation:** Either share the server's `LoginSchema` from `packages/shared/src/zod/index.ts` or co-locate a parallel client Zod schema in `apps/web/src/lib/api/auth-client.ts` and validate at submit. Same pattern for `/signup` invite-code step (already does a regex test — good — but no shared schema).
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0019 — `SERVER_ARGON_SALT` dev fallback silently generates a random in-memory salt

- **Severity:** Low
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/crypto/crypto.service.ts:78-89`
- **Description:** When `SERVER_ARGON_SALT` is unset, `CryptoService.onModuleInit` falls back to a fresh `randomBytes(16)` generated in memory and only emits a `logger.warn`. Intentional dev convenience, but in production it is an availability foot-gun: a forgotten env var on a redeploy means the new salt no longer matches the per-user `argon2_secret_key_hash` stored at signup → every existing user gets a uniform 401 "Invalid credentials" with no diagnostic. Operator may misdiagnose as "users forgot password" rather than "salt drift". Not a confidentiality issue (the salt is operator-public-by-convention), but a reliability/correctness issue for SimpleVault's self-hosted target audience.
- **Recommendation:** Make `SERVER_ARGON_SALT` REQUIRED at boot in non-dev mode. Either (a) hard-fail when `NODE_ENV === "production"` and the env is missing, with a clear "must be set + must match value at first signup" message, or (b) document a one-time bootstrap so the salt is generated and persisted to a host file the first time the API starts (mirror `SERVER_INVITE_SECRET` treatment). Cross-link to `docs/operator/DOKPLOY-DEPLOY.md` Phase-02 env-var matrix.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0020 — Audit log emits `inviteId` on failure paths (informational; document as expected)

- **Severity:** Info
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/auth/signup/signup.service.ts:43-44, 173-179`; `apps/api/src/invite/invite.service.ts:72-79`
- **Description:** Failure-path audit events for `auth.signup.fail` and `invite.redeem.fail` carry the `inviteId` UUID in the `data` field. The invite UUID is not itself a secret — it's the public id returned by `POST /invite/redeem` — but logging it on every failure ties an audit-fail entry to a known invite, which Phase 10's hash-chain will surface in the operator dashboard. By design (the planner wants reuse-detect / scrape-detect signal) but worth flagging so future auditors don't mistake it for a leak.
- **Recommendation:** No code change. Document this in `docs/operator/SECURITY-NOTES.md` "Audit log invariants" section as expected behavior, and confirm in the Phase 10 plan that `inviteId` in audit data is OK to store in the chain.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0021 — `/me` throttler keys by IP, not user-id (APP_GUARD ordering vs JwtAuthGuard) [REQ-RATELIMIT-006 not in effect]

- **Severity:** Medium
- **Reporter:** rate-limit-dos-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/common/throttler.config.ts:75-89` (`generateKey`); `apps/api/src/app.module.ts:143` (APP_GUARD registration); `apps/api/src/me/me.controller.ts:11,17` (`@UseGuards(JwtAuthGuard)` + `@Throttle({me-user})`)
- **Description:** `SimpleVaultThrottlerGuard` is registered as a **global** `APP_GUARD` while `JwtAuthGuard` is route-scoped via `@UseGuards(JwtAuthGuard)` on `MeController`. NestJS executes global guards BEFORE route-scoped guards, so when the throttler's `generateKey` reads `req.user?.id` for the `me-user` ceiling, the JWT guard has not yet attached the principal — `req.user` is undefined and the code falls through to the IP-keyed default (`return ${name}:${suffix}` where `suffix` is the IP tracker). Net effect: REQ-RATELIMIT-006's user-keying is silently NOT in effect on `/me`; the limit is enforced per-IP instead. Strictly LOOSER than intent (one user behind a NAT shares a budget with neighbours; a stolen JWT used from many IPs gets the full per-IP budget multiple times rather than a single per-user budget). Not a bypass, but the documented behaviour is wrong.
- **Reproduction:** `curl -i -H "Authorization: Bearer <jwt>" /me` 101 times from a single IP using the SAME JWT → expect the 101st request to 429. Then run from a SECOND IP using the same JWT — observe the second IP gets a fresh 100-request budget (would be 0 under correct user-keying because the user already exhausted it).
- **Recommendation:** Either (a) apply `JwtAuthGuard` globally for any route that has a user-keyed throttler (move JWT-guard to APP_GUARD with a path-allow-list for `/auth/*` `/health` `/invite/redeem`) so it runs before throttler; or (b) split `me-user` into a separate guard chain that runs JwtAuthGuard first, then a route-local throttler subclass; or (c) accept the IP-keyed behaviour and update REQ-RATELIMIT-006 + 02-09-SUMMARY to reflect it. Option (a) is the least surprising long-term — global JWT guard + `@Public()` decorator for opt-out is standard NestJS pattern.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 8e3215c (Plan 03-09 T2; supporting decorator in 859c7e4)
- **Fix summary:** Adopted Recommendation (a). `JwtAuthGuard` registered as APP_GUARD before `SimpleVaultThrottlerGuard` in `app.module.ts`; `@Public()` decorator opts out the 10 truly-public routes (`/health`, `/invite/redeem`, `/auth/{signup,login,refresh,logout,params}`, `/2fa/webauthn/{begin,finish}-auth`, `/2fa/totp/verify`). Step-up routes combine `@Public()` with `Require2FAStepUpGuard` for their token-shape mismatch with `JwtAuthGuard`.
- **Verified-by:** _pending live re-run by rate-limit-dos-auditor on Plan 12 / `/gsd:verify-work 3` (101 `/me` from IP-1 then one from IP-2 with the same JWT — second IP must 429)_
- **Blocks-phase:** NO

### FINDING-0022 — `login-email` keying does not bound input length (Redis-key-flooding DoS surface)

- **Severity:** Medium
- **Reporter:** rate-limit-dos-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/common/throttler.config.ts:83-87` (`generateKey` for `login-email`)
- **Description:** When the request hits `/auth/login`, the throttler runs as a guard BEFORE Zod validation (validation is a pipe; guards run before pipes). The throttler reads `req.body.email` directly (post-body-parser, pre-validation) and lower-cases it to form the Redis key `login-email:em:<email>`. There is NO length cap on the email before keying. An attacker can submit POSTs with the body `{"email": "<10KB-of-arbitrary-chars>"}` — each submission writes a unique 10KB Redis key. With Express's default 100KiB body limit, an attacker can spray ~1M unique keys per minute given a single botnet, each consuming Redis memory until TTL expires (1 hour for `login-email`). This is amplified by the `login-ip` arm only kicking in at 5/min/IP, so distributed sources can each get 5 keys/minute "for free". Independent of the actual auth attempt — the keys are written even when login fails immediately on validation. Cross-references FINDING-0017 (no email length cap) and FINDING-0015 (body-parser limit not explicit) — fixing FINDING-0017 partially mitigates this but the throttler reads body before validation runs, so the in-throttler cap is still required.
- **Reproduction:** Loop 5 POSTs to `/auth/login` with bodies of the form `{"email":"<random 4KB string>@x.test","argon2SecretKeyHash":"<64 chars>"}` from a single IP. Inspect Redis: `redis-cli --scan --pattern 'login-email:em:*' | wc -l` returns 5 oversized keys per IP per minute window.
- **Recommendation:** Two-part fix:
  1. In `generateKey`, cap the email substring used for keying: e.g., `tracker = "em:" + sha256(body.email.toLowerCase()).slice(0,16)` — fixed-length, leaks no PII to Redis, prevents key-flooding amplification.
  2. Document at the top of the throttler config that the throttler reads body BEFORE validation, so future ceilings keyed off body fields must also bound their input.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** a4283a0 (Plan 03-09 T3)
- **Fix summary:** Both parts of the recommendation applied. `generateKey` now keys `login-email` via `createHash("sha256").update(email).digest("hex").slice(0,16)` — fixed 16-char tracker. A header comment block on `apps/api/src/common/throttler.config.ts` documents that the throttler runs BEFORE Zod validation pipes, so any future ceiling keyed off `req.body` MUST hash + slice. Defence-in-depth via Plan 01's `varchar(254)` storage cap (FINDING-0017) remains in place.
- **Verified-by:** _pending live re-run by rate-limit-dos-auditor on Plan 12 / `/gsd:verify-work 3` (5 `POST /auth/login` with 4KB random emails; `redis-cli --scan --pattern 'login-email:em:*'` must return 5 keys each shaped `login-email:em:<16-hex>`)_
- **Blocks-phase:** NO

### FINDING-0023 — throttler storage-error catch regex is fragile (silent self-DoS path on non-matching ioredis errors)

- **Severity:** Low
- **Reporter:** rate-limit-dos-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/common/throttler.config.ts:64-72` (`canActivate` error filter)
- **Description:** `SimpleVaultThrottlerGuard.canActivate` only catches errors whose message matches `/Stream isn't writeable|ECONNREFUSED|ENOTFOUND|Connection is closed/i`. Other ioredis error paths — Redis AUTH failures (`NOAUTH`), MOVED/ASK during cluster resharding, command timeouts (`Command timed out`), max-retries-exceeded (`Reached the max retries`), and Lua script-eval errors — would re-throw and surface as a 500 from the route handler (via `AllExceptionsFilter`'s default). On a Redis hiccup that produces a non-matching error string (e.g., a transient AUTH failure during cred rotation), legitimate `/auth/login` requests would 500 — a self-DoS, exactly the failure mode the fail-open path was designed to prevent.
- **Recommendation:** Replace the regex with an allow-list against `err.constructor.name` from ioredis: catch `RedisError`, `ReplyError`, `MaxRetriesPerRequestError`, `AbortError`, plus generic `Error` whose `.code` matches the network errno set (`ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EPIPE`). Or, simpler: catch ALL errors thrown FROM the storage layer (wrap `super.canActivate` and rethrow only auth/permission errors); fail-open on anything else.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0024 — Redis throttler keys lack env/app namespace prefix

- **Severity:** Low
- **Reporter:** rate-limit-dos-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/common/throttler.config.ts:131` (`new ThrottlerStorageRedisService(redis)`); upstream `@nest-lab/throttler-storage-redis@1.2.0` keys as `{<key>:<throttlerName>}:hits`
- **Description:** The throttler keys do not include an env/app namespace. SimpleVault's docker-compose stack runs Redis on a private internal network with no host-port mapping (per Phase-01 hardening), so a single-tenant deployment is the documented model — but if an operator runs a single Redis instance shared across staging+production (a common cost-saving pattern in self-hosted setups), counters collide. A staging-side burst against `/auth/login` would consume the production budget and vice versa.
- **Recommendation:** Either (a) configure ioredis with `keyPrefix: "${APP_ENV}:throttler:"` (note: this only prefixes commands NOT inside Lua `KEYS` — `@nest-lab/throttler-storage-redis` builds key strings inside the Lua script, so `keyPrefix` won't apply; switch to a wrapper Storage adapter); or (b) document in `docs/operator/DOKPLOY-DEPLOY.md` that each environment MUST run its own Redis instance (operationally simplest; matches the existing per-stack compose model). Option (b) is the lowest-effort fix and aligns with the Dokploy-per-env model already documented.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0025 — Node HTTP server slow-loris timeouts not set (relies entirely on Traefik)

- **Severity:** Info
- **Reporter:** rate-limit-dos-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/api/src/main.ts` (no `server.headersTimeout` / `server.requestTimeout` / `server.keepAliveTimeout` calls)
- **Description:** `apps/api/src/main.ts` does not set Node's HTTP server timeouts. Slow-loris-style attacks (drip-feed bytes / never-close request) are mitigated only at the Traefik proxy layer per the Dokploy plan. An operator running api directly for debugging (e.g., port-forwarding past Traefik, or a misconfigured Dokploy that exposes `:3001` directly) would have no slow-loris protection.
- **Recommendation:** Either (a) document the proxy reliance in `docs/operator/SECURITY-NOTES.md` "Production deployment requirements" with a "Do not expose api directly" warning; or (b) set `server.headersTimeout = 60_000; server.requestTimeout = 120_000; server.keepAliveTimeout = 5_000` on the underlying Node `http.Server` after `app.listen` resolves, so even a direct exposure has bounded slow-loris exposure. (b) is a one-line defence-in-depth addition.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0026 — AAD label literals duplicated at signup site (drift risk)

- **Severity:** Medium
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/web/src/lib/crypto/signup-derivations.ts:152, 157, 162, 167`
- **Description:** The four FROZEN per-blob AAD label prefixes (`sv:user-master:v1|`, `sv:user-recovery:v1|`, `sv:user-sign-sk:v1|`, `sv:user-kx-sk:v1|`) are defined as exported constants in `apps/web/src/lib/crypto/aad-labels.ts` whose header explicitly states "Pull from this module — never repeat literals." The login-derivations module (`login-derivations.ts:11-16, 144, 149, 154`) correctly imports `AAD_LABEL_*`. The signup-derivations module instead inlines the four string literals at each `aadFor(...)` call site. Today the bytes are byte-equal between signup and login, but a future single-side rename (e.g. someone bumps the version suffix at the constants file) will silently break every existing wrapped blob (tag-fail on every login unwrap) without any test catching it. Symbol-parity test (`packages/crypto/test/parity.test.ts`) does not cover this app-level duplication.
- **Reproduction:** Edit `aad-labels.ts:14` to `"sv:user-master:v2|"` and run the e2e signup → login flow. Signup succeeds; login at the master-DEK unwrap step fails with AEAD tag mismatch. The test suite passes.
- **Recommendation:** In `signup-derivations.ts` import the four constants from `./aad-labels` and replace each string literal at the four `aadFor(...)` call sites. Add a small unit test that asserts signup's encoded AAD == login's encoded AAD given the same inputs.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0027 — `deriveMasterKek` accepts arbitrary `secretKey` length (defence-in-depth)

- **Severity:** Medium
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `packages/crypto/src/key-hierarchy.ts:111-140`
- **Description:** `deriveMasterKek()` validates `userArgonSalt.length === 16` (line 117-121) but does NOT validate `secretKey.length`. The HKDF step accepts any `Uint8Array` as IKM, so a degraded or malformed client could pass a 0-byte secret_key and silently derive a key whose entropy is whatever the password contributes after Argon2id stretching — collapsing the two-secret model to a one-secret model on the client side without any server-visible signal (server only sees the Argon2id output). The CRYPTO-STACK.md §3 contract specifies `secret_key = 128 bits = 16 bytes`; the validator should pin it. The web flow's `crockfordToBytes` already enforces 16 bytes (`secret-key-format.ts:78-82`), so the practical risk today is low — but this is the canonical defence-in-depth point: the type-system contract should reject malformed inputs at the crypto package boundary, not rely on every caller doing it.
- **Reproduction:** Call `deriveMasterKek({ password: "x", secretKey: new Uint8Array(0), email: "a@b.c", userArgonSalt: new Uint8Array(16) })` — function returns a 32-byte master_KEK with no warning. Same for `Uint8Array(8)`, `Uint8Array(64)`, etc.
- **Recommendation:** Add a length assertion (e.g. `if (input.secretKey.length !== 16) throw new Error("...");`) parallel to the existing `userArgonSalt` check at line 117-121. Add a vitest case under `key-hierarchy.test.ts` that asserts the throw on bad `secretKey` lengths.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0028 — `deriveKey` accepts arbitrary salt length above 16 (defence-in-depth)

- **Severity:** Low
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `packages/crypto/src/argon2id.ts:81-83`
- **Description:** `deriveKey` validates `salt.length >= SALT_BYTES_MIN` (16) but never asserts a maximum. libsodium itself accepts any length ≥16. SimpleVault always passes exactly 16 bytes (XOR-ed argon salt at hierarchy.ts:134-137; the global `serverArgonSalt` is sized at decode-time in crypto.service.ts:79). No correctness issue today, but a future caller mistakenly passing a 64-byte buffer would produce a different KEK than a caller passing the first 16 bytes — silently — and the resulting wrap would fail to unwrap on the other-typed caller.
- **Recommendation:** Tighten to `salt.length === 16` (matches libsodium pwhash SALTBYTES exactly) or document an explicit maximum. Cosmetic.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0029 — `secret_key` lifetime in browser keyStore beyond strict need

- **Severity:** Low
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02
- **Affected:** `apps/web/src/app/login/page.tsx:155`
- **Description:** Login successfully unwraps the DEKs and then stashes the raw 16-B `secret_key` back into `keyStore` (line 155: `keyStore.set("secret_key", secretKey)`). The comment on lines 156-159 says "future operations that need it (e.g. password change, recovery) can read it without a re-prompt." But Phase 02 has no such operation — password-change is Phase 11+ and recovery is Phase 11. The secret_key thus sits in browser RAM for the entire authenticated session purely for forward-compat. CRYPTO-STACK.md §10 "Memory zeroing in JS" notes that JS engines may copy buffers; minimising lifetime matters. The master_DEK is required at every vault-item op (Phase 04+), but secret_key is NOT — it can be discarded once the master_KEK has been derived.
- **Recommendation:** Drop the `keyStore.set("secret_key", secretKey)` line and immediately `secretKey.fill(0)` after unlock completes. When password-change / recovery flows arrive in later phases, they will need to re-prompt the user for the secret_key anyway (or unlock from a fresh prompt) — that is the intended UX for high-impact operations.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0030 — Recovery flow does not validate mnemonic checksum before deriving recovery_KEK (forward-looking)

- **Severity:** Info
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-02
- **Phase:** 02 (audit; mitigation in Phase 11)
- **Affected:** `packages/crypto/src/key-hierarchy.ts:164-169`, `packages/crypto/src/bip39.ts:65-73` (and a future `apps/api/src/auth/recovery/...` Phase-11 module)
- **Description:** `deriveRecoveryKek({mnemonic, userId})` calls `mnemonicToSeed(mnemonic)` directly — it does not first call `validateMnemonic(mnemonic)`. PBKDF2-HMAC-SHA512 will produce 64 bytes for any input string, so a wrong-checksum mnemonic just yields a recovery_KEK that fails AEAD-unwrap of the wrapped master_DEK. That's the right *security* outcome, but the UX latency is suboptimal: the user waits for one PBKDF2 round-trip + AEAD attempt before seeing "wrong phrase", whereas a `validateMnemonic` precheck is ~microseconds. Not a Phase-02 bug — there's no recovery flow yet — but flagged so the Phase-11 author validates checksum first AND surfaces a generic-error UX (don't differentiate "checksum bad" vs "wrong phrase" — both must look identical to defeat enumeration).
- **Recommendation:** When implementing the recovery flow in Phase 11, call `validateMnemonic(mnemonic)` BEFORE `deriveRecoveryKek`.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0031 — `DELETE /sessions/:id` did not bump `users.session_epoch`, contradicting Truth 12

- **Severity:** High
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/auth/sessions/session.service.ts` `revokeOne` (lines 385-412 prior to fix)
- **Description:** `revokeOne` family-revoked the targeted session row but did NOT call `bumpEpoch(userId)`. Truth 12 of `03-INDEX.md` mandates: *"Bumps the targeted user's session_epoch, cutting all access tokens for that user within ≤ next-request latency."* An inline doc-comment claimed single-session-revoke was "intentionally softer" than revoke-all, but that softer behaviour leaves a stolen access token alive for up to `ACCESS_TOKEN_TTL` (default 900 s) after the user explicitly revokes the compromised session — defeating REQ-AUTH-004 and AT-5 leaf A's threat-model transition (MITIGATED-WITHIN-EPOCH-LATENCY).
- **Recommendation:** After the family-revoke UPDATE returns `revokedCount > 0`, call `await this.bumpEpoch(userId)` (mirroring `revokeAllForUser`'s load-bearing UPDATE-then-bump order). Cross-user / not-found / already-revoked paths must continue to return `null` BEFORE any epoch-bump, to preserve the anti-enumeration property. Update the doc-comment.
- **Status:** VERIFIED-CLOSED (2026-05-04)
- **Blocks-phase:** NO (closed)
- **Fix:** `revokeOne` now invokes `bumpEpoch(userId)` after a successful family-revoke (`apps/api/src/auth/sessions/session.service.ts:419`); doc-comment rewritten to explain per-user grain (lines 372-395); ordering is load-bearing (UPDATE refresh rows BEFORE bumpEpoch) and matches `revokeAllForUser`. Anti-enumeration preserved — `null` returns on cross-user / not-found / already-revoked occur BEFORE any epoch-bump. API build green; 32/32 api unit tests pass. Re-verified by auth-flow-auditor 2026-05-04 (re-run section appended to `2026-05-04-auth-flow-auditor-phase03.md`).

### FINDING-0032 — `/2fa/totp/verify` throttler is IP-keyed despite step-up token carrying `sub`

- **Severity:** Medium
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/common/throttler.config.ts` (`twoFaVerifyIp` ceiling), `apps/api/src/twofa/totp/totp.controller.ts` `/verify`
- **Description:** `/2fa/totp/verify` carries a step-up token whose `sub` identifies the user pre-2FA, but the throttler ceiling is keyed by IP. An attacker who controls a botnet (or rotates IPs via a residential proxy) can brute-force a 6-digit TOTP code (10⁶ space, ±1 step drift = 3×10⁶ effective) at 30/min/IP without ever tripping a per-user limit. Cross-references FINDING-0021/0022's user-keying intent.
- **Recommendation:** Add a `twoFaVerifyUser` ceiling (e.g. 10/min keyed off `req.stepUp.sub`) alongside the existing IP-keyed ceiling, and document the dual-key strategy in `throttler.config.ts`. Defer if explicit operator decision is to keep step-up brute-force pressure entirely IP-shaped.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0033 — `Require2FAStepUpGuard` does not validate `epoch` claim against `users.session_epoch`

- **Severity:** Low
- **Reporter:** auth-flow-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/auth/jwt/step-up-jwt.service.ts` (verify path), `Require2FAStepUpGuard`
- **Description:** Step-up JWTs carry an `epoch` claim mirrored from the user's `session_epoch` at issuance, but the step-up verify path does not re-check that claim against the current `users.session_epoch`. A user who triggers `revoke-all` between 1FA pass and 2FA completion would have their access tokens invalidated but their step-up token would still be honoured for the remaining TTL (≤120 s). Low because the step-up token has a tiny TTL and only mints `/2fa/*` flows, but the claim is already on the wire — checking it costs one cache-hit and closes the consistency gap.
- **Recommendation:** Add `epoch === currentEpoch(sub)` to `StepUpJwtService.verify` using the same `SessionEpochCache.get(userId)` primitive `JwtAuthGuard` uses.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0040 — Client trusts server-supplied `encryptedSecretAad` at TOTP unwrap

- **Severity:** Low
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/web/src/lib/api/twofa-client.ts` (TOTP unwrap path), `apps/api/src/twofa/step-up/step-up-material.controller.ts`
- **Description:** The TOTP unwrap flow accepts `encryptedSecretAad` from the server response and passes it directly to AEAD decryption rather than re-deriving it locally from `"sv:user-totp:v1|" + sha256(lower(email))`. AEAD failure on AAD mismatch is the right *security* outcome, but trusting server-supplied AAD lets a malicious server probe whether a different AAD scheme would unwrap (a defence-in-depth concern; mirrors Phase 02 FINDING-0026 drift-risk).
- **Recommendation:** Recompute AAD client-side from `email` (already in the user profile) at unwrap time; ignore `encryptedSecretAad` from the server response, OR assert it equals the locally-recomputed value before invoking AEAD.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0041 — `master_kek` appears in pino redaction list (expected grep noise)

- **Severity:** Info
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/app.module.ts:91` (pino redaction wildcards)
- **Description:** Server-side grep for `master_kek` finds a pino redaction wildcard (`*.master_kek`). This is the correct defence-in-depth posture (redact even though the field should never appear in any structured log), and is expected noise for the "browser-only secret" gate. Documented here so future grepers don't flag it as a regression.
- **Recommendation:** None — informational.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0042 — WebAuthn challenge entropy via WebCrypto in @simplewebauthn v11 — pin Node ≥20

- **Severity:** Info
- **Reporter:** crypto-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/package.json` engines field (currently unset), `@simplewebauthn/server@11.0.0`
- **Description:** `@simplewebauthn/server@11` allocates challenges via `WebCrypto.getRandomValues` (CSPRNG-equivalent to `crypto.randomBytes`). WebCrypto is globally available on Node ≥20; on earlier engines the import path differs. SimpleVault's CI Dockerfile pins `node:20-alpine` so this is fine today, but the `engines` field in `apps/api/package.json` is unset — a future contributor running `pnpm dev` on an older Node would silently get worse behaviour.
- **Recommendation:** Add `"engines": { "node": ">=20" }` to `apps/api/package.json`.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0050 — WebAuthn finish-auth status drift: 400 vs 401 on adjacent fail paths

- **Severity:** Info
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/twofa/webauthn/webauthn-auth.service.ts` (`CHALLENGE_INVALID` 400 vs `VERIFICATION_FAILED` 401)
- **Description:** Two adjacent fail modes of `/2fa/webauthn/finish-auth` return different HTTP statuses (400 challenge-invalid, 401 verification-failed). An attacker probing with mismatched challenge IDs can distinguish "your challenge expired" from "your assertion didn't verify" — a small enumeration oracle on whether a particular user has rotated through a recent challenge.
- **Recommendation:** Collapse to a single 401 `WEBAUTHN_VERIFICATION_FAILED` for any non-success path on the assertion side, mirroring `/2fa/totp/verify`'s uniform 401 stance.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0051 — `ParseUUIDPipe` 400 vs 404 distinguishes malformed from cross-user IDs

- **Severity:** Info
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/sessions/sessions.controller.ts`, `apps/api/src/twofa/methods/methods.controller.ts` (DELETE routes)
- **Description:** `DELETE /sessions/:id` and `DELETE /2fa/methods/:id` are decorated with `ParseUUIDPipe` which returns 400 for non-UUID path params, while cross-user-but-valid-UUID lookups return 404. An attacker crafting non-UUID probes can distinguish "malformed input" from "valid input but not yours". Tiny information leak; documented for completeness.
- **Recommendation:** Consider returning 404 for both paths (custom pipe that throws `NotFoundException` on parse error), OR document the leak as accepted (it's a generic Nest pattern across the codebase).
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0052 — No startup warn when `EXPOSE_TEST_ROUTES=1 && NODE_ENV=production`

- **Severity:** Low
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/app.module.ts:162-164`, `apps/api/src/main.ts`
- **Description:** The `EXPOSE_TEST_ROUTES=1` flag conditionally registers the `/vault/_2fa-guard-probe` and test-helpers routes. The flag is correctly absent from production Dockerfile, but no runtime guard warns/exits if an operator accidentally sets it on a prod build — the only safety check is the runbook's grep advisory.
- **Recommendation:** Add a boot-time assertion: `if (process.env.EXPOSE_TEST_ROUTES === "1" && process.env.NODE_ENV === "production") throw new Error(...)`. Cheap, fail-fast, no false-positives.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0053 — WebAuthn counter-regression doesn't escalate to logger.warn

- **Severity:** Info
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/twofa/webauthn/webauthn-auth.service.ts:222-225`
- **Description:** Counter-regression rejection emits an audit event with `reason: "counter_regression"` (correct) but at the default audit-log level. Counter regression is a strong clone-detection signal — an authenticator's monotonic counter going backwards is the textbook indicator of a cloned credential. Operators monitoring the API logs for clone-attempt patterns benefit from a dedicated `logger.warn` line in addition to the structured audit row.
- **Recommendation:** Add `this.logger.warn({ evt: "webauthn.counter_regression", userId, credentialId })` next to the existing audit emit. Defer if log-noise is a concern — the audit row already captures it.
- **Status:** OPEN
- **Blocks-phase:** NO

### FINDING-0034 — Stale JSDoc on `bumpEpoch` after FINDING-0031 fix

- **Severity:** Info
- **Reporter:** auth-flow-auditor (re-run)
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/auth/sessions/session.service.ts` `bumpEpoch` JSDoc (was lines 252-258)
- **Description:** Surfaced during FINDING-0031 re-verification. The JSDoc on `bumpEpoch` claimed *"single-session revoke does NOT call this"* — accurate before the 0031 fix, stale after. Risk is doc drift: a future maintainer could "restore" the old behaviour believing the comment.
- **Recommendation:** Rewrite JSDoc to describe the per-user grain and reference Truth 12 + the FINDING-0031 fold-in.
- **Status:** VERIFIED-CLOSED (2026-05-04)
- **Blocks-phase:** NO
- **Fix:** JSDoc rewritten in same closure cycle as 0031 (`session.service.ts:252-260`). References Truth 12 + FINDING-0031.

### FINDING-0054 — Pino redact list lacks names for new Phase-03 sensitive fields

- **Severity:** Info
- **Reporter:** owasp-top10-auditor
- **Date opened:** 2026-05-04
- **Phase:** 03
- **Affected:** `apps/api/src/app.module.ts` (pino redact configuration)
- **Description:** Pino's redact list doesn't explicitly name the new Phase-03 fields: `wrappedSecret`, `encryptedSecretAad`, `issuanceNonce`, `stepUpToken`, `candidateStep`. The wildcard `*.password` / `*.master_kek` / etc. patterns don't match these names. Defence-in-depth is partial: the structured audit emitter already strips them, but a stray `req.body` log (e.g. on a thrown exception that pino auto-serialises) could expose them.
- **Recommendation:** Add the five field names to the redact array. Cosmetic but cheap.
- **Status:** OPEN
- **Blocks-phase:** NO

## Closed findings

_(All FINDING-0001..0009 are VERIFIED-CLOSED above; kept inline for traceability rather than moved out, since they're the entire Phase 01 set. Future phases will move closed findings into this section.)_
