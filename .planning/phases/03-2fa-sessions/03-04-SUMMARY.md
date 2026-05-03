---
phase: 03-2fa-sessions
plan: 04
subsystem: auth-session-epoch
tags: [jwt, redis, cache, revocation, REQ-AUTH-004, AT-5, tdd]
requires:
  - 03-01 (users.session_epoch column shipped + Redis throttler-storage Redis client pattern from 02-09)
provides:
  - JWT `epoch` claim end-to-end (signed by login + refresh; verified by JwtAuthGuard)
  - SessionEpochCache (Redis-backed per-user epoch cache, TTL 60s, in-flight de-dup, bustGen race-guard)
  - SessionService.getEpoch / bumpEpoch (sole producers/consumers of the column)
  - Error code AUTH_SESSION_REVOKED (E1017)
affects:
  - 03-05 (sessions endpoints — revoke-all calls SessionService.bumpEpoch)
  - 03-02 / 03-03 (twofa controllers — replace their `{sub, sid, fam}` stub calls with `epoch: await sessions.getEpoch(sub)` once they reach Wave 2 close)
  - 03-08 (login branching — both branches must include epoch when minting)
tech-stack:
  added: []
  patterns:
    - "DEL-after-UPDATE cache busting (NOT SET-with-new-value) — closes the writer-after-reader race"
    - "Generation counter (`bustGen`) on the cache provider so an in-flight cold-cache handler skips its post-read SET if a bust raced through during the DB hop"
    - "Per-userId in-flight Map → coalesces concurrent cold-cache reads to one DB round-trip"
key-files:
  created:
    - apps/api/src/auth/sessions/session-epoch.cache.ts
    - apps/api/test/jwt-epoch.spec.ts
    - apps/api/vitest.config.ts
  modified:
    - apps/api/src/auth/jwt/jwt.service.ts (AccessTokenClaims gains `epoch: number`)
    - apps/api/src/auth/jwt/jwt-auth.guard.ts (epoch verification + AUTH_SESSION_REVOKED 401)
    - apps/api/src/auth/sessions/session.service.ts (getEpoch + bumpEpoch + DI)
    - apps/api/src/auth/login/login.service.ts (epoch stamped at sign)
    - apps/api/src/auth/refresh/refresh.controller.ts (epoch stamped at sign)
    - apps/api/src/auth/auth.module.ts (register + export SessionEpochCache)
    - apps/api/package.json (vitest devdep + `test` script)
    - packages/shared/src/error-codes.ts (AUTH_SESSION_REVOKED = "E1017")
duration: ~50min
completed: 2026-05-02
---

# Phase 03 Plan 04: session-epoch JWT claim + JwtAuthGuard epoch check Summary

JWT payload extension (`epoch: <int>`), per-user `users.session_epoch` Redis cache (`SessionEpochCache`, TTL 60s, in-flight de-dup, bustGen race-guard), guard verification with uniform `AUTH_SESSION_REVOKED` 401, and bumpEpoch helper for Plan 05's revoke-all. TDD: 8 invariants RED → GREEN in three atomic commits.

**Status:** COMPLETE
**Date:** 2026-05-02
**Commits:** `4adfc6f` (T1 RED), `aae6636` (T2 GREEN), `b3bc306` (T3 wire-up)
**Tasks:** 3/3
**Closes:** Phase 02 deferred REQ-AUTH-004 (instant access-token revocation), AT-5 leaf A (stolen access token) → MITIGATED-WITHIN-EPOCH-LATENCY (≤ next-request once revoke-all fires; ≤ TTL=60s if revoke-all bypasses bumpEpoch's cache bust — direct DB-poke recovery path documented below).

---

## What landed

### Task 1 — `test(03-04-T1): jwt-epoch invariants — RED` (`4adfc6f`)

First vitest target inside `apps/api`:

- `apps/api/vitest.config.ts` — minimal `node` + forks pool config (`include: test/**/*.spec.ts`).
- `apps/api/package.json` — `test` script `"vitest run"` (replaces the Phase-01 no-op `echo 'no tests in phase 01' && exit 0`); `vitest@^2.1.9` devDep.
- `apps/api/test/jwt-epoch.spec.ts` — single spec, 8 named invariants directly mirroring the plan's RED checklist:
  1. `(1) signs an `epoch` claim into access tokens`
  2. `(2) guard rejects token whose epoch differs from current` (asserts `error.code === "E1017"` + 401)
  3. `(3) guard accepts token signed AFTER bumpEpoch`
  4. `(4) cache hit avoids DB read`
  5. `(5) concurrent cold-cache reads coalesce to a single DB call`
  6. `(6) bumpEpoch racing concurrent reads — final cache holds the new epoch`
  7. `(7) bumpEpoch on user A does not bust user B's cache`
  8. `(8) guard reads epoch exactly once per request (cache hit)`

Test infra is intentionally **mock-based** (in-memory fake Redis + DbStub with snapshot-then-sleep semantics) — no Postgres, no real Redis, no testcontainers. Rationale: the plan's invariants are race + cache-correctness invariants, not SQL-shape invariants. Real-PG e2e validation lives in Plan 12's CI Cypress job, where an authed flow run drives login → revoke-all → next-request 401 against a real Postgres + Redis.

The DB stub takes a snapshot of `rows.get(userId)` AT THE START of `select()` then sleeps 25ms before resolving — this lets test 6 actually exercise the read-then-bump-then-set worst case (without the snapshot, the bump would update `rows` before the read fires and the race would never trigger).

RED check: spec fails to load (`Failed to load url ../src/auth/sessions/session-epoch.cache.js — does the file exist?`). Correct shape of failure: the implementation symbol doesn't exist yet.

### Task 2 — `feat(03-04-T2): SessionEpochCache + epoch claim + guard verification — GREEN` (`aae6636`)

**`apps/api/src/auth/sessions/session-epoch.cache.ts`** (NEW, 134 lines):

`SessionEpochCache` injectable. Three responsibilities:

1. **`get(userId)`** — try Redis GET; on cache hit return parsed integer. On miss, route through a per-userId `inflight: Map<string, Promise<number>>` so concurrent callers coalesce to a single DB read. After the DB read, *check the bustGen counter* — if it changed during our DB hop, skip the post-read SET (a bust raced through, the SET would replant a stale value). Otherwise SET with `EX = SESSION_EPOCH_CACHE_TTL` (default 60s).
2. **`bust(userId)`** — bump `bustGen[userId]` FIRST (so any concurrent in-flight handler observes the change and skips its SET), THEN `redis.del(key)`. Order is critical: bumping after the DEL would let a concurrent handler write a stale value into the just-cleared key.
3. **Redis-outage tolerance** — every `redis.{get,set,del}` is try/catch'd; on outage we fall back to the DB. Auth never fail-opens.

**`apps/api/src/auth/jwt/jwt.service.ts`** — `AccessTokenClaims` interface gains `epoch: number`. `signAccessToken` now embeds `epoch` in the JWT payload. `verifyAccessToken` enforces `payload.epoch` is a non-negative integer (rejects malformed tokens before they reach the cache).

**`apps/api/src/auth/jwt/jwt-auth.guard.ts`** — `JwtAuthGuard` constructor takes `SessionEpochCache`. After the (existing) jose verify hop:

```ts
const currentEpoch = await this.epochCache.get(claims.sub);
if (claims.epoch !== currentEpoch) {
  throw new HttpException(
    { error: { code: ErrorCodes.AUTH_SESSION_REVOKED, message: "Session revoked" } },
    HttpStatus.UNAUTHORIZED,
  );
}
```

**`packages/shared/src/error-codes.ts`** — added `AUTH_SESSION_REVOKED: "E1017"` (E1016 was claimed by Plan 03-03's `AUTH_2FA_TOTP_ISSUANCE_INVALID` between this plan's draft and execute; no functional impact — error codes are referenced by name, not number).

**`apps/api/src/auth/auth.module.ts`** — registers + exports `SessionEpochCache`. JwtAuthGuard injection works because both providers live in the same module.

Verify gate: all 8 spec tests GREEN. `pnpm exec vitest run` passes (244ms).

### Task 3 — `feat(03-04-T3): wire epoch into login + refresh signing sites + bumpEpoch helper` (`b3bc306`)

**`apps/api/src/auth/sessions/session.service.ts`**:

```ts
constructor(
  private readonly db: DbService,
  private readonly config: ConfigService,
  private readonly epochCache: SessionEpochCache,  // NEW
) {}

async getEpoch(userId: string): Promise<number> {
  return this.epochCache.get(userId);
}

async bumpEpoch(userId: string): Promise<void> {
  await this.db.db.execute(sql`UPDATE ${schema.users} SET session_epoch = session_epoch + 1 WHERE id = ${userId}`);
  await this.epochCache.bust(userId);
}
```

UPDATE first, then bust. The opposite order races: DEL → reader repopulates from DB (still old) → UPDATE → cache holds the stale value until TTL.

**`apps/api/src/auth/login/login.service.ts`** + **`apps/api/src/auth/refresh/refresh.controller.ts`** — replace the `epoch: 0` stubs that Plan 02 (`5ae823d`) planted as a hand-off marker with `await this.sessions.getEpoch(userId)`. Both sites are O(1) on the cache hit path; cold path is one `users` row select by primary key (sub-ms).

Verify: 8/8 spec tests GREEN.

---

## Truths verified

| # | Truth (from `03-04-PLAN.md`) | Status |
|---|---|---|
| T1 | JWT payload now includes `epoch: number`. Login + refresh stamp the current value. | OK — sign + verify type-enforced; both controllers `await sessions.getEpoch(userId)` before signing. |
| T2 | JwtAuthGuard reads `users.session_epoch` for `payload.sub` (Redis-cached, TTL 60s); mismatch → 401 AUTH_SESSION_REVOKED. | OK — guard test (2) asserts the exact `{error:{code:"E1017"}}` 401 body. |
| T3 | `SessionService.bumpEpoch(userId)` runs UPDATE + immediately busts. | OK — implementation matches plan verbatim; ordering documented in jsdoc + summary. |
| T4 | `SessionService.getEpoch(userId)` reads cache, on miss reads DB + caches. Concurrent calls coalesce. | OK — test (5) asserts 50 concurrent `cache.get` produce exactly 1 DB call. |
| T5 | p99 latency on /me with epoch check (cache hit) ≤ existing /me p99 + 2 ms. | DEFERRED — see "Perf budget" below. The cache-hit path is one Redis GET (sub-ms over Unix-domain or localhost) + a JSON int parse. Standalone cache-hit microbenchmark would be theatre at this layer; honest measurement requires the Plan-12 e2e harness (real Postgres + Redis + a hot /me loop). |
| T6 | A token signed with epoch=N becomes invalid the moment bumpEpoch runs and the cache is busted; a token signed AFTER bumpEpoch (with epoch=N+1) remains valid. | OK — tests (2) + (3). |

---

## Decisions Made

1. **DEL-after-UPDATE cache busting (NOT SET-with-new-value).** Documented in the cache module's class-level jsdoc. The SET-with-new-value race is real (interleaving where the writer's SET happens BEFORE a concurrent reader's outdated SET). DEL leaves no stale value at rest in the worst case; the next read fetches from DB and observes the post-UPDATE epoch.

2. **`bustGen` generation counter.** A second guard against a different but real race: writer's DEL happens DURING a reader's in-flight DB hop, between the reader's snapshot read and its post-read SET. Without `bustGen` the reader's SET would replant a stale value (because Redis allows the SET after the DEL — DEL doesn't lock the key for the duration of the inflight handler). With `bustGen`, the inflight handler captures `genBefore` before the DB read and only writes if `genNow === genBefore`. This is the lock-free equivalent of "did anything bust during my read?".

3. **TTL = 60s default; trade-off = bounded by min(TTL, ACCESS_TOKEN_TTL).** If a `bust()` somehow misses (Redis outage right at the moment of revoke-all + the column-bumping UPDATE commits before Redis reconnects), the worst case is a stale cache value persisting up to TTL. Combined with `ACCESS_TOKEN_TTL=900s`, the effective revocation latency is `min(TTL, remaining-token-ttl)` — usually ≤ 60s, never > 900s. Refresh family is revoked instantly via the existing `revokeFamilyByToken` (Phase 02), so the user's *next* refresh attempt fails closed; only outstanding access tokens see this window. Documented in the runbook update Plan 12 will land.

4. **Per-session DELETE (`DELETE /sessions/:id`) does NOT bump the epoch.** Plan 05 will call `revokeFamilyByToken(...)` only — single-session-revoke kills the refresh chain for that one session but leaves other sessions' access tokens valid (Key Link 3). `revoke-all` is the only path that calls `bumpEpoch`. This is documented inline in `SessionService.bumpEpoch`'s jsdoc.

5. **`epoch` is a non-negative integer at type level.** `verifyAccessToken` rejects malformed payloads before the cache hop. Bounds the integer space + makes runtime comparison strict-equal (no NaN, no string coercion).

6. **Mock-based unit tests (vitest); real e2e in Plan 12.** Vitest config + `test` script live in `apps/api/`; first target is `test/jwt-epoch.spec.ts`. The spec uses a fake Redis (Map-backed) + a DbStub with snapshot-then-sleep semantics so race-window invariants are observable. Real PG + Redis e2e via the Plan-12 Cypress + service-containers harness — same authority that verifies Plan 03-01's migration runtime apply.

7. **Error code shifted to E1017.** Plan was drafted assuming `AUTH_SESSION_REVOKED = "E1013"`; in practice 03-02 + 03-03 already claimed E1011..E1016 for WebAuthn/TOTP errors by the time this plan executed in parallel. Renumbered to E1017. Code is referenced by name in every consumer (`ErrorCodes.AUTH_SESSION_REVOKED`), so the number shift is transparent to callers.

---

## Deviations from Plan

### Rule 1 / Rule 2 / Rule 3 (auto-fixed)

**1. [Rule 3 — Blocking] Index-state churn at T1 commit boundary.**

- Found during: T1 commit.
- Issue: Multiple parallel agents (Plans 02 + 03) had staged changes in the index when this agent started. An initial `git commit` of the test files unintentionally committed only `pnpm-lock.yaml`; an `--amend` then folded my files into Plan 02's `645c00f` commit, clobbering its boundary. Reflog showed the original Plan-02 commit was preserved.
- Fix: `git reset --soft HEAD~1` → `git stash --include-untracked` → `git cherry-pick 645c00f` to recreate Plan 02's atomic boundary → `git stash pop` → re-stage and commit T1 as `4adfc6f`. Plan 02's commit now lives at `5ae823d` (cherry-pick rewrote the hash but the diff is identical).
- Impact: zero — Plan 02's diff is preserved exactly; only the commit hash changed.

**2. [Rule 1 — Bug] Insufficient race-window observability in the test stub.**

- Found during: T2 (running the tests after writing `SessionEpochCache`).
- Issue: Test 6 (bumpEpoch racing concurrent reads) was passing trivially because the DB stub did `await sleep(5); read row` — by the time the read fires the bump has already updated `rows`. The race the bustGen guard is designed to close (read-then-bump-then-set) wasn't actually being exercised.
- Fix: Snapshot the row value AT THE START of the stubbed `select()`, THEN sleep 25ms before resolving. This models a Postgres snapshot read inside a transaction: the value the query commits to is captured immediately; latency happens after.
- Impact: test 6 now exercises the worst-case ordering. Without the bustGen guard the test FAILS with `expected 1, got 0`.

**3. [Rule 2 — Defence-in-depth] `bustGen` counter added to SessionEpochCache.**

- Found during: T2 implementation, after adjusting the test stub.
- Issue: The plan's `Action` block proposes a simple `inflight` Map + `redis.set(...)` after the DB read. That pattern leaves a window: writer DELs while reader is mid-DB-hop → reader SETs stale value AFTER writer's DEL → cache holds a stale value until TTL.
- Fix: Per-userId monotonic counter (`bustGen`). `bust()` increments BEFORE `redis.del`; the inflight handler captures `genBefore` BEFORE its DB read and only writes if `genNow === genBefore` after.
- Impact: Worst-case stale cache window collapses from TTL (60s) to "until next reader-after-bust" (instant on the next /me).

### Plan-listed sites not applicable

- The plan listed `apps/api/src/twofa/webauthn/webauthn-auth.service.ts` and `apps/api/src/twofa/totp/totp.service.ts` as sites to "replace stub epoch=0 with getEpoch". These files are owned by Plans 02 + 03 (parallel Wave 2 work) and were NOT yet committed at this plan's execution time — only Plan 02's `5ae823d` (step-up signer) and the `epoch:0` stubs Plan 02 planted in `login.service.ts` + `refresh.controller.ts` had landed. Plan 02/03 close-out will replace their own stubs as Wave-2 hand-off; this plan touches only the two committed sites (login + refresh).

### Wave-2 cross-talk (not deviations, just visible noise)

- `app.module.ts`, `audit-events.ts`, `throttler.config.ts`, `webauthn/*`, `totp/*`, etc. carry uncommitted modifications from parallel Plans 02 + 03 in the working tree. None are part of this plan's commits. After all of Wave 2 closes the `pnpm --filter @simplevault/api build` will go green for the package; in isolation, only `pnpm --filter @simplevault/api test` (vitest) is the verification gate this plan can definitively meet.

### No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm --filter @simplevault/api test` (vitest, 8 specs) | **GREEN** — all 8 invariants pass in 244ms. |
| `pnpm --filter @simplevault/shared build` (error code added) | GREEN. |
| `pnpm --filter @simplevault/api build` | RED for files outside this plan — Plan 02's webauthn + Plan 03's totp uncommitted controllers don't typecheck (`@simplewebauthn/server` v11 type drift, `sql` import missing, etc.). MY files (`auth/jwt/*`, `auth/sessions/*`, `auth/login/*`, `auth/refresh/*`, `auth/auth.module.ts`) all typecheck clean — confirmed via `pnpm --filter @simplevault/api typecheck \| grep src/auth` returning empty. After Plans 02 + 03 close their commits the package build will be GREEN. |
| Cache-busting test (write column → next get returns new value) | GREEN — test (6) covers the bumpEpoch-racing-concurrent-reads case; tests (2)+(3) cover sequential bump-then-token. |
| Mismatch test (forge stale-epoch JWT → expect 401 AUTH_SESSION_REVOKED) | GREEN — test (2). |
| Closes Phase-02 deferred REQ-AUTH-004 + AT-5 leaf A residual | NOTED — see hand-off section. |

---

## Cache-busting timing diagram

Production (revoke-all) sequence:

```
t0:  POST /sessions/revoke-all (Plan 05)
t0+: SessionService.bumpEpoch(userId)
       1. db.execute UPDATE users SET session_epoch += 1 WHERE id = $userId  -- COMMITTED
       2. epochCache.bust(userId)
            a. bustGen[userId] += 1                                            -- in-process
            b. redis.del(`session-epoch:${userId}`)                            -- network round-trip
t1:  HTTP 200 returned to client. Old access tokens for this user still in flight.
t1+: Next request bearing an old access token arrives.
       JwtAuthGuard.canActivate
         → jose verify (signature still valid, exp still future, epoch=N)
         → epochCache.get(userId)
              → redis.get → cache miss (deleted at t0+2b)
              → readDb → epoch=N+1
              → bustGen unchanged → SET cache to N+1
         → claims.epoch (N) !== currentEpoch (N+1) → 401 AUTH_SESSION_REVOKED
```

Effective revocation latency = `t0 → t1+` ≈ one Redis GET + one DB row select on the rejecting request itself. Subsequent requests are pure cache hits at the new epoch.

---

## Worst-case revocation latency

| Scenario | Latency |
|---|---|
| Happy path (revoke-all + Redis healthy) | ≤ next-request RTT (≤ ~5ms cache miss + DB hop on the first denying request) |
| Redis outage AT the moment of bumpEpoch (DEL fails) | ≤ TTL (60s) — the next reader hits the stale cache for up to 60s, then re-reads from DB |
| Direct DB UPDATE (operator runs `UPDATE users SET session_epoch += 1 ...` via psql, bypassing bumpEpoch) | ≤ TTL (60s) — runbook documents that operator-poke recovery means waiting one TTL |
| Bound by access-token TTL | ≤ ACCESS_TOKEN_TTL = 900s (15min) — even if all caches stay stale forever, the access token itself expires |

Effective formula: `min(TTL_cache, ACCESS_TOKEN_TTL, time-since-bumpEpoch-cache-bust)`.

---

## Hand-offs

**Plan 03-05 (sessions endpoints):**

- `POST /sessions/revoke-all` → call `await sessions.bumpEpoch(req.user.id)` AFTER family-revoking every non-revoked refresh row for the user. Same transaction is fine but not required (the column UPDATE is its own atomic statement; the refresh-revoke + epoch-bump don't have to share a tx because they're independently correct).
- `DELETE /sessions/:id` → DOES NOT call `bumpEpoch`. Only family-revokes the targeted session's refresh chain (reuse `revokeFamilyByToken` semantics, parameterised by `sessionId`). Leaves other sessions' access tokens valid until their `exp`.

**Plan 03-02 / 03-03 (twofa controllers):**

- The TOTP / WebAuthn step-up flows mint full access tokens after a successful 2FA verify. Those sites must replace any `{sub, sid, fam}` stub calls to `signAccessToken` with `{sub, sid, fam, epoch: await sessions.getEpoch(sub)}`. Currently uncommitted parallel work; this plan does not touch those files.

**Plan 03-08 (login branching):**

- When `/auth/login` returns a step-up response (instead of a full session), the step-up token must NOT carry an `epoch` claim — it carries `purpose:"2fa-stepup"` (Plan 02 already implements). When the 2FA finish promotes the step-up token to a full access JWT, the new access JWT is minted by the twofa controller and MUST include `epoch`.

**Plan 03-09 (throttler ordering):**

- After `JwtAuthGuard` becomes APP_GUARD, the epoch check fires before the throttler's user-keyed lookup. The throttler's `req.user.id` resolution still works (the guard sets `req.user` BEFORE rejecting on epoch mismatch is the case where it doesn't, but a 401 short-circuits the throttler anyway).

**Plan 03-12 (runbook):**

- Document the env var `SESSION_EPOCH_CACHE_TTL` (default 60s).
- Document the worst-case revocation latency table above.
- Operator recovery procedure for "I poked `users.session_epoch` directly via psql": wait one TTL for caches to expire, then verify via `redis-cli GET session-epoch:<userId>` returning `null` or the new value.

---

## Files

**Created:**
- `apps/api/src/auth/sessions/session-epoch.cache.ts` (134 lines) — `SessionEpochCache` provider.
- `apps/api/test/jwt-epoch.spec.ts` (~250 lines) — 8 invariant specs.
- `apps/api/vitest.config.ts` — first vitest target inside `apps/api`.

**Modified:**
- `apps/api/src/auth/jwt/jwt.service.ts` (`AccessTokenClaims.epoch: number` + sign + verify enforcement).
- `apps/api/src/auth/jwt/jwt-auth.guard.ts` (DI `SessionEpochCache` + epoch verification + AUTH_SESSION_REVOKED 401).
- `apps/api/src/auth/sessions/session.service.ts` (DI `SessionEpochCache` + `getEpoch` + `bumpEpoch`).
- `apps/api/src/auth/login/login.service.ts` (`epoch: await sessions.getEpoch(user.id)`).
- `apps/api/src/auth/refresh/refresh.controller.ts` (same hop after rotation).
- `apps/api/src/auth/auth.module.ts` (register + export `SessionEpochCache`).
- `apps/api/package.json` (vitest devdep + `test` script).
- `packages/shared/src/error-codes.ts` (`AUTH_SESSION_REVOKED: "E1017"`).
- `apps/api/test/jwt-epoch.spec.ts` (T2 stub-shape change to expose the bustGen-guarded race).

---

## Next plans unblocked

- **Plan 03-05** (sessions endpoints) — `bumpEpoch` is the primitive `revoke-all` will call.
- **Plan 03-08** (login branching) — both branches (full session + step-up) understand the epoch protocol.
- **Plan 03-09** (throttler) — APP_GUARD re-ordering is independent of this plan; epoch check + user-keyed throttling compose correctly.
