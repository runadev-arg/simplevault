# Rate-limit / DoS auditor — Phase 02 (auth + crypto)

- **Auditor:** rate-limit-dos-auditor
- **Date:** 2026-05-02
- **Scope:** Phase 02 (Plans 02-07..02-12) — `@nestjs/throttler@6.5` + `@nest-lab/throttler-storage-redis@1.2`. Read-only audit.
- **Verdict:** **PASS-WITH-CONCERNS** — no Critical or High issues block phase merge. Two MEDIUM issues, two LOW, one INFO (plus a body-parser cross-ref to FINDING-0015 already filed by input-validation-auditor). The `/me` user-keying issue (FINDING-0021) is the only one that materially affects a documented requirement (REQ-RATELIMIT-006); flagged MEDIUM (not High) because its observed effect is "throttle becomes IP-keyed instead of user-keyed" — strictly looser, not bypassable, and behind shared NATs only marginal.

---

## Ceiling matrix — REQ vs implementation

| REQ | Spec (REQUIREMENTS.md) | Implementation (`throttler.config.ts`) | Status |
|---|---|---|---|
| REQ-RATELIMIT-001 | global 1000/IP/15min | `default` 1000/IP/15min, `GLOBAL_RATE_LIMIT` env-tunable | OK |
| REQ-RATELIMIT-002 (IP arm) | login 5/IP/15min | `login-ip` 5/IP/**1min** (env `LOGIN_IP_RATE_LIMIT`) — TIGHTER than spec window; planner-documented deviation per 02-09-SUMMARY rule-1 | OK (intentionally tightened) |
| REQ-RATELIMIT-002 (email arm) | login 10/email/15min | `login-email` 10/email/**1h** (env `LOGIN_EMAIL_RATE_LIMIT`) — LONGER window than spec; planner-documented as anti-credential-stuffing across IPs | OK (intentionally widened, security-positive) |
| REQ-RATELIMIT-003 | signup 3/IP/h | `signup-ip` 3/IP/h | OK |
| REQ-RATELIMIT-004 | recovery 3/email/h + 5/IP/h | NOT IMPLEMENTED | Out of scope (Phase 03 — recovery flow) |
| REQ-RATELIMIT-005 | vault invite gen 10/vault/day | NOT IMPLEMENTED | Out of scope (Phase 04/07 — shared vaults) |
| REQ-RATELIMIT-006 | per-user general API 300/user/15min | `me-user` 100/user/min — but **APP_GUARD ordering means user-id is not yet on req when the throttler runs**, so it falls back to IP keying. See FINDING-0021. | FINDING (MEDIUM) |
| REQ-RATELIMIT-007 | redis-backed @nestjs/throttler v6 | `@nestjs/throttler@6.5` + `@nest-lab/throttler-storage-redis@1.2` over ioredis | OK |
| (Plan-only) refresh | — | `refresh-ip` 60/IP/min | OK — appropriate for token rotation: a typical session does ~60 refreshes per minute only under attack; legitimate auto-refresh runs ≈once per access-token TTL (15min) |
| (Plan-only) logout | — | `logout-ip` 60/IP/min | OK |
| (Plan-only) /auth/params | — | `auth-params-ip` 100/IP/min | OK — public endpoint, trivial cost |
| (Plan-only) /invite/redeem | — | `invite-redeem-ip` 30/IP/h | OK — pre-signup gate |

All 9 named ceilings present. No silent omissions for Phase-02 scope. REQ-RATELIMIT-004/005 are correctly deferred to later phases (per ROADMAP §Phase-03 + §Phase-07 mapping).

---

## Item-by-item scrutiny (auditor checklist)

### 1. All ceilings present (✓)
9 ceilings declared (`default`, `signup-ip`, `login-ip`, `login-email`, `refresh-ip`, `logout-ip`, `auth-params-ip`, `invite-redeem-ip`, `me-user`). All wired via `@Throttle({...})` decorators. Cross-checked at `apps/api/src/auth/login/login.controller.ts:43,63-66`, `…/signup/signup.controller.ts:17`, `…/refresh/refresh.controller.ts:23`, `…/logout/logout.controller.ts:18`, `apps/api/src/me/me.controller.ts:17`, `apps/api/src/invite/invite.controller.ts:17`.

### 2. Compound login limit (✓ — both enforced)
`apps/api/src/auth/login/login.controller.ts:63-66` declares BOTH `login-ip` and `login-email` in the same `@Throttle({...})` map. Per `@nestjs/throttler` v6 semantics, each named entry produces an independent counter — the request is denied if EITHER ceiling is exceeded. This correctly blocks credential-stuffing across IPs (the email arm) and brute-force from one IP (the IP arm).

### 3. Email-keyed limit & enumeration (✓ but see 3a)
`generateKey()` in `throttler.config.ts:83-87` lower-cases the email before hashing. The 429 body returned via `AllExceptionsFilter` is `{error:{code:"E1010",message:"...",requestId}}` — uniform regardless of email validity. Status code + headers (including `Retry-After`) are byte-equal regardless of whether the email exists in `users`. **Anti-enumeration intact** — but see FINDING-0022 (unbounded email length keying).

#### 3a. Cross-check with auth-flow-auditor
Recommend the auth-flow-auditor confirm: a 429 from the email arm and a 429 from the IP arm produce byte-equal responses (currently both flow through `super.throwThrottlingException`). Out of scope for this audit but flagged for the next gate.

### 4. Refresh rate limit 60/IP/min (✓)
60/IP/min is comfortably above the legitimate ceiling. With a 15-minute access-token TTL (`ACCESS_TOKEN_TTL=900`), a single client refreshes ≈4×/h under normal use. 60/min accommodates token-rotation storms (multi-tab + tab-restoration scenarios) without risking self-DoS. Not too low; not too high.

### 5. Failure mode (✓ for the catch path; PARTIAL for the regex — FINDING-0023)
`SimpleVaultThrottlerGuard.canActivate` (`throttler.config.ts:60-73`) catches errors matching `/Stream isn't writeable|ECONNREFUSED|ENOTFOUND|Connection is closed/i` and returns `true` (fail-open) with a warn-log. ioredis is configured `lazyConnect: true, maxRetriesPerRequest: 1, enableOfflineQueue: false` — so a Redis blip causes one fast reject, the guard fails open, and ioredis auto-reconnects in the background. The next request after recovery succeeds via the same Redis client. **Reattachment is automatic — confirmed.** However, the regex is fragile (FINDING-0023).

### 6. Storage namespace (FINDING-0024)
`@nest-lab/throttler-storage-redis@1.2` writes keys as `{${key}:${throttlerName}}:hits` — **no app/env prefix**. If the same Redis is shared across staging and production, counters collide. SimpleVault docker-compose runs Redis on a private internal network with no host port (per FINDING-0006-related hardening), so the typical operator deployment is single-tenant — but the assumption should be documented and the prefix made explicit. LOW (not Medium) because the dev compose stack is single-tenant by design and Plan 02-12's Dokploy guide treats each environment as its own stack.

### 7. Skip lists (✓)
`skipIf` matches `req.url === "/health"` (strict equality, no startswith). `/auth/*`, `/me`, `/invite/*` are NOT skipped. Health endpoint exemption is correct for Dokploy/k8s probes. INFO-grade nit: a future `/api/health` (when path-routed through Traefik) would not match — left as a tracking note for Phase 04+.

### 8. /me throttle key (FINDING-0021 — MEDIUM)
**Functional gap.** `SimpleVaultThrottlerGuard` is registered as `APP_GUARD` (global). `JwtAuthGuard` is route-scoped via `@UseGuards(JwtAuthGuard)` on `MeController`. Per NestJS execution order, **global guards run before route-scoped guards** — so when the throttler's `generateKey` reads `req.user?.id`, the JWT guard hasn't run yet and `req.user` is undefined. The branch at `throttler.config.ts:81-82` falls through; the key becomes `me-user:<IP-suffix>`. Net effect: REQ-RATELIMIT-006 is enforced by IP, not user. Strictly looser than intent (a single user behind a NAT shares the per-IP budget; an attacker using one stolen JWT from many IPs gets the full budget per IP rather than a single per-user budget). MEDIUM — not bypassable, but the documented per-user keying is not in effect.

### 9. Retry-After header (✓)
`SimpleVaultThrottlerGuard.throwThrottlingException` (`throttler.config.ts:91-101`) sets `Retry-After: <ttl-seconds>` (delta-seconds form, not HTTP-date — RFC 9110 §10.2.3-compliant) on every 429. Cypress E2E spec at `apps/web/cypress/e2e/auth-sad.cy.ts:202` asserts presence on the 429 case. Min value `Math.max(1, …)` avoids the 0-second edge case.

### 10. Burst tolerance (✓)
The Lua script in `throttler-storage-redis.service.js:33-50` increments first, then compares `totalHits > limit`. So the (limit+1)-th request is denied — off-by-one is on the SAFE side (one extra request allowed beyond limit by some throttler implementations is the more common bug; this one denies exactly the request that would exceed).

### 11. Body-parser size (already tracked: FINDING-0015 by input-validation-auditor)
`apps/api/src/main.ts` does NOT explicitly call `app.use(express.json({ limit: ... }))` or `bodyParser.json({ limit })`. NestJS `@nestjs/platform-express` defaults the json body limit to **100 KiB** (express's own default), well under the 1 MiB threshold called out in the auditor mandate. No DoS surface here today. Already filed as FINDING-0015 by input-validation-auditor; no duplicate raised.

### 12. Slow-loris / connection limits (FINDING-0025 — INFO)
NestJS / Express has no built-in slow-loris defence. `apps/api/src/main.ts` does NOT set `server.headersTimeout`, `server.requestTimeout`, or `server.keepAliveTimeout`. The plan documents reliance on Traefik (Dokploy) for proxy-layer timeouts. Recommendation: document this reliance explicitly in `docs/operator/SECURITY-NOTES.md` so an operator running api directly (e.g., debugging) knows the protection isn't there at the Node layer.

### 13. No in-memory limiter remnants (✓)
`grep -rn 'FixedWindowRateLimiter|clientIpKey|rate-limit\.(ts|js)' apps/` returned ZERO matches. Plan 02-09's deletion is clean. No config drift.

---

## Findings

Two MEDIUM, two LOW, one INFO (plus one cross-ref to FINDING-0015 already filed by input-validation-auditor). None Critical or High → **does not block phase merge**.

| ID | Severity | Title |
|---|---|---|
| FINDING-0021 | MEDIUM | `/me` throttler keys by IP, not user-id (APP_GUARD vs route guard ordering) |
| FINDING-0022 | MEDIUM | `login-email` keying does not bound input length — Redis-key-flooding DoS surface |
| FINDING-0023 | LOW | Throttler storage-error catch regex is fragile (specific strings only) |
| FINDING-0024 | LOW | Redis throttler keys lack env/app namespace prefix |
| FINDING-0025 | INFO | Slow-loris timeouts not set on Node HTTP server (relies on Traefik) |
| (cross-ref FINDING-0015) | LOW | Express body-parser limit — already filed by input-validation-auditor |

Full entries appended to `.planning/security/FINDINGS.md`.

---

## Verification done

- Read all 12 phase-02 plan summaries via `02-09-SUMMARY.md` and `02-12-SUMMARY.md`.
- Read all 6 controllers using `@Throttle(...)` plus the central `throttler.config.ts` and `app.module.ts` wiring.
- Read `@nest-lab/throttler-storage-redis@1.2.0` source to verify Lua semantics, key format, and prefix behaviour.
- Read `JwtAuthGuard` to confirm guard ordering implication for `me-user` keying (FINDING-0021).
- Read `AllExceptionsFilter` to confirm 429 maps to `E1010 AUTH_RATE_LIMITED` uniformly.
- Read `apps/web/cypress/e2e/auth-sad.cy.ts` lines 171-206 to confirm the 12-burst → 429 + `Retry-After` E2E assertion exists.
- `grep` for in-memory limiter remnants — clean.
- Cross-referenced REQ-RATELIMIT-001..007 vs implementation row-by-row.

Read-only — no code modified.

---

## Verdict reasoning

The phase ships a Redis-backed, multi-replica-safe, env-tunable throttler covering every Phase-02-relevant ceiling, fails open under Redis outage with explicit logging, sets `Retry-After` correctly, and has an E2E assertion for the burst → 429 path. The deviations (per-minute windows on the IP arm of login, longer email window) are planner-documented and are net-positive for security. The `/me` user-keying gap (FINDING-0021) is the highest-impact issue but it produces a STRICTLY LOOSER rate limit on `/me` (IP-keyed instead of user-keyed) — that's a deviation from REQ-RATELIMIT-006's intent, not a bypass or escalation, hence MEDIUM.

**Verdict: PASS-WITH-CONCERNS.** Track FINDING-0021 + FINDING-0022 as Phase-13 hardening work.
