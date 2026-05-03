---
phase: 03-2fa-sessions
plan: 05
subsystem: sessions-api
tags: [sessions, revoke-all, anti-enumeration, epoch, audit, throttler]
requires:
  - 03-01 (user_sessions schema + users.session_epoch column)
  - 03-04 (SessionService.bumpEpoch + SessionEpochCache primitives)
provides:
  - GET /sessions (Truth 11)
  - DELETE /sessions/:id (Truth 12)
  - POST /sessions/revoke-all (Truth 13)
  - SessionService.listForUser / revokeOne / revokeAllForUser
  - Audit actions auth.session.revoked + auth.session.revoke_all
  - Throttler ceilings sessions-list-user / sessions-revoke-user / sessions-revoke-all-user
affects:
  - 03-09 (when APP_GUARD reorder lands, the three new ceilings become user-keyed for real)
  - 03-11 (web /settings/sessions UI consumes these endpoints)
  - 03-12 (E2E specs around session-list + revoke + epoch-killing-old-token)
tech-stack:
  added: []
  patterns:
    - "DISTINCT ON (family_id) ORDER BY family_id, created_at DESC — collapse rotation chain to one representative row per session family for the UI"
    - "Anti-enumeration on every cross-user lookup: 404 (NOT 403). Same response shape regardless of 'doesn't exist' vs 'exists but not yours'"
    - "revoke-all = UPDATE refresh-rows THEN bumpEpoch (order load-bearing — reverse order would let a fresh /auth/refresh mint a new access token under the new epoch)"
    - "Strict-allowlist Zod re-parse on the response body (defence-in-depth against future ORM-hydration leaks)"
key-files:
  created:
    - apps/api/src/sessions/sessions.module.ts
    - apps/api/src/sessions/sessions.controller.ts
    - apps/api/src/sessions/sessions.service.ts
  modified:
    - apps/api/src/auth/sessions/session.service.ts (+listForUser, +revokeOne, +revokeAllForUser)
    - apps/api/src/app.module.ts (register SessionsModule)
    - apps/api/src/common/throttler.config.ts (3 new ceilings + userKeyed expansion)
    - apps/api/src/common/audit-events.ts (SessionRevoked + SessionRevokeAll)
    - packages/shared/src/zod/index.ts (SessionListItemSchema + SessionListResponseSchema)
duration: ~25min (recovery agent — siblings had pre-staged the impl files)
completed: 2026-05-02
---

# Phase 03 Plan 05: /sessions API (list / revoke-one / revoke-all) Summary

User-facing session management API: list active sessions, log out one device, log out everywhere. The third endpoint closes Phase-02's deferred AT-5 leaf A residual (stolen access token) by calling `SessionService.bumpEpoch` after the family-revoke — outstanding access tokens for the user fail closed within ≤ next-request latency on the cache-bust path or ≤ TTL (60s) on the worst-case Redis-outage path (Plan 04 latency table).

**Status:** COMPLETE (recovery agent)
**Date:** 2026-05-02
**Commits:** `edb35e8` (T1 list + revoke-one), `760ca16` (T2 revoke-all + bumpEpoch + audit events extension)
**Tasks:** 2/2

---

## What landed

### Task 1 — `feat(03-05-T1): GET /sessions + DELETE /sessions/:id + sessions module` (`edb35e8`)

NEW top-level module `apps/api/src/sessions/` — distinct from `auth/sessions/SessionService` (the refresh-rotation primitive). The new module is the user-facing controller surface; heavy lifting (DB queries, epoch bumps) is delegated to `SessionService` to keep the rotation primitive as the single owner of `user_sessions` writes.

**`SessionService.listForUser(userId, currentSessionId)`**: returns one row per active session FAMILY (rotation chain collapsed). Drizzle doesn't expose `DISTINCT ON` natively, so the implementation drops to raw `sql\`...\`` for `SELECT DISTINCT ON (family_id) ... ORDER BY family_id, created_at DESC`. Marks the family containing `currentSessionId` (the sid claim from the caller's JWT) as `current: true` — note: the representative row for that family may have a DIFFERENT id than `currentSessionId` (after rotation). One small extra query maps `currentSessionId → family_id` so the marker lands on the family, not the literal row.

`ipHashB64Prefix` = first 6 chars of `base64(ip_hash)` (36 bits) — UX context only (per Truth 11), not authn. Anything more leaks the full hash to JS where an XSS could exfiltrate it.

**`SessionService.revokeOne(userId, sessionId)`**: family-revoke gated on `WHERE id=$sessionId AND user_id=$userId`. Cross-user / non-existent / already-revoked all collapse to `null` → controller maps to uniform 404 (NEVER 403 — anti-enumeration per Truth 12). Returns `{familyId, revokedCount}` on success for the audit-log payload. Does NOT bump the epoch (single-session-revoke is intentionally softer than revoke-all per Plan 04 Key Link 3).

**`SessionsController`**: `GET /sessions` parses the response through `SessionListResponseSchema.parse(...)` before returning (defence-in-depth against future ORM-hydration leaks). `DELETE /sessions/:id` validates `:id` via `ParseUUIDPipe({version:"4"})`, returns 204 on success — same shape for "I revoked my current session" and "I revoked a sibling session", so the response itself doesn't leak which row was hit.

Throttler ceilings: `sessions-list-user` (60/min) + `sessions-revoke-user` (30/min). Both user-keyed via `req.user.id`. Until Plan 09's APP_GUARD reorder lands, the throttler runs BEFORE `JwtAuthGuard` → `req.user.id` is `undefined` and `generateKey` falls back to IP-keying. That is tolerable for the Plan-05↔Plan-09 lag because the absolute IP-keyed ceilings are still tight (60/30 per minute is sub-abuse for any plausible IP); the user-keying just becomes effective once Plan 09 reorders the guards. Documented inline in `throttler.config.ts`.

Audit event: `auth.session.revoked` (with `data: {familyId, revokedRows}`). Cross-user / not-found paths emit NO audit row — emitting one would make the audit log itself an enumeration oracle (a row attempt on a probed sessionId would log a different shape than a real cross-user probe). Standard pino request-log line still fires.

### Task 2 — `feat(03-05-T2): POST /sessions/revoke-all + bumpEpoch wiring + revoke-all audit` (`760ca16`)

**`SessionService.revokeAllForUser(userId)`**: `UPDATE user_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL RETURNING id` then `await this.bumpEpoch(userId)`. Order is load-bearing: bump-then-revoke would briefly let a fresh `POST /auth/refresh` (with the still-valid refresh cookie) mint a NEW access token under the NEW epoch, defeating the revoke. Refresh-rows-first slams that window shut. Returns `{revokedCount}`.

**`SessionsController.revokeAll`**: `POST /sessions/revoke-all` returns 200 `{revokedCount}` AND clears the `__Host-refresh` cookie via `Set-Cookie ... Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict` — mirrors `LogoutController`'s clear semantics. The user is logging themselves out from this device too; they will need to re-login.

Audit event: `auth.session.revoke_all` with `targetId = userId` and `data: {revokedCount}`. Always emitted (even when revokedCount === 0) — the user explicitly invoked the endpoint, the audit row records the intent.

Throttler ceiling `sessions-revoke-all-user` (5/min, env `SESSIONS_REVOKE_ALL_RATE_LIMIT`). Same Plan-09 caveat as T1's two ceilings.

Closes Phase-02 AT-5 leaf A residual: after `revoke-all` fires, every outstanding access token for the user fails closed on its next request (cache-bust path) or ≤ TTL=60s (Redis-outage path). The refresh family is dead at the same instant.

---

## Truths verified

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T11 | `GET /sessions` returns `{id, createdAt, lastUsedAt, current, userAgentFamily, ipHashB64Prefix}[]` for the caller; ordering: current first then createdAt asc | OK — controller implementation + Zod parse + sort discipline. |
| T12 | `DELETE /sessions/:id` family-revokes on success; 404 (NOT 403) on cross-user — anti-enumeration | OK — `revokeOne` returns `null` on cross-user, controller maps to uniform 404. No audit row on the not-found path. |
| T13 | `POST /sessions/revoke-all` family-revokes EVERY non-revoked row AND calls `bumpEpoch`; returns `{revokedCount}`; current access token invalidated as soon as next request lands | OK — `revokeAllForUser` UPDATE-rows-then-bumpEpoch order; cookie cleared at controller level. |

---

## Decisions Made

1. **Module separation: `apps/api/src/sessions/` (NEW) vs `apps/api/src/auth/sessions/` (existing).** The new module is the user-facing CRUD surface; the existing `auth/sessions/SessionService` remains the refresh-rotation primitive AND the single owner of `user_sessions` writes. Adding new write paths to a different module would split ownership and create the risk of a future maintainer adding a third write path that doesn't respect family-revoke semantics. The new `SessionsService` delegates all DB work down to `SessionService`.
2. **`DISTINCT ON (family_id)` collapse.** A long-lived session that's been refreshed N times has N+1 rows in `user_sessions` (N rotated rows + 1 current). The UI wants ONE entry per device, not the rotation history. `DISTINCT ON (family_id) ORDER BY family_id, created_at DESC` picks the most-recent representative; the sid → family mapping (one extra small query) marks the right family as `current`.
3. **404 (NOT 403) on cross-user revoke (Truth 12).** Anti-enumeration. Mirrored on `DELETE /2fa/methods/:id` (Plan 06).
4. **`ipHashB64Prefix` = first 6 chars of base64(ip_hash).** 6 × 6 = 36 bits — collisions tolerated; this is UX context, not authn. Enough for "I recognise this network" without leaking the full hash to JS.
5. **revoke-one does NOT bump epoch (Truth 12 + Plan 04 Key Link 3).** Killing all of the user's other access tokens because they revoked a single laptop session would be too aggressive. Only revoke-all bumps. Documented in `revokeOne` jsdoc.
6. **revoke-all = UPDATE refresh-rows FIRST, then bumpEpoch.** Documented in `revokeAllForUser` jsdoc. Reverse order opens a brief race window where a fresh `POST /auth/refresh` (still-valid cookie) mints a new access token under the bumped epoch — defeating the revoke.
7. **Audit event consolidation.** Plan 05 owns `SessionRevoked` + `SessionRevokeAll`. Plan 06 owns `TwoFaMethodRemoved` (committed as part of Plan 06's atomic surface, NOT this plan, despite the Plan-05 PLAN file's "consolidated enum extension" wording — recovery agent split the audit-events hunks per their owning plan to keep blame attribution clean).
8. **Cross-user/not-found paths emit NO audit row.** Logging "user X tried to revoke session Y but didn't own it" would make the audit log a side-channel oracle for enumeration. Standard request-log line still fires.
9. **Strict-allowlist Zod parse on response body.** `SessionListResponseSchema.parse(items)` runs server-side before responding. A future ORM-hydration leak (e.g. someone adds `refresh_token_hash` to the SELECT projection) surfaces as a 500, not a silent secret exfil.
10. **`SESSIONS_REVOKE_ALL_RATE_LIMIT` env var added (default 5).** Plan-prescribed; consistent with the other two new ceilings (`SESSIONS_LIST_RATE_LIMIT`, `SESSIONS_REVOKE_RATE_LIMIT`).

---

## Deviations from Plan

### Rule 3 (auto-fixed blocking issues)

**1. [Rule 3 — Wave-3 cross-talk] Recovery agent inherited mixed-state working tree.**

- **Found during:** Recovery start (this agent took over after three sibling agents stalled with interleaved edits across shared files).
- **Issue:** `app.module.ts`, `audit-events.ts`, `throttler.config.ts`, `twofa.module.ts`, `packages/shared/src/zod/index.ts`, `.env.example`, and `apps/api/test/2fa-required-guard.spec.ts` carried hunks belonging to all three Wave-3 plans (05, 06, 07) interleaved. Plain `git add <file>` would have committed Plan 06/07's hunks under Plan 05.
- **Fix:** Hunk-level attribution via hand-written patches applied with `git apply --cached`. Plan 05's bits staged + committed; Plan 06/07's bits left in the working tree for their own commits.
- **Impact:** Two atomic commits with clean blame attribution. Plan 06 + Plan 07 commits will pick up the rest cleanly.

**2. [Rule 3 — Plan-listed audit-action consolidation NOT done.]**

- **Found during:** Recovery triage.
- **Issue:** Plan 05's PLAN said "consolidated audit-action enum extension lands in this commit" (Plans 02/03/06's actions all together). The working-tree state already had Plans 02/03/06's actions committed by their respective plans / siblings. `TwoFaMethodRemoved` (the Plan 06 entry) was unstaged but PRE-EXISTING in the dirty tree.
- **Fix:** Recovery agent reverts the consolidation rule. Each plan owns its own audit-action additions. Plan 05 commits `SessionRevoked` (T1) + `SessionRevokeAll` (T2). Plan 06 commits `TwoFaMethodRemoved`. This is cleaner blame-wise.
- **Impact:** No semantic change — final HEAD audit-events.ts contains the same enum entries; only the commit attribution differs from the original plan.

### Plan-listed sites NOT applicable

- `audit-events.ts` was NOT extended with all 11 2FA actions in this plan (per the PLAN's "consolidated enum extension since it's the smallest module touching it"). Reasoning above.

### No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm --filter @simplevault/api typecheck` (Plan 05 staged tree only — siblings stashed) | GREEN |
| `pnpm --filter @simplevault/api build` (Plan 05 only) | GREEN |
| `pnpm --filter @simplevault/api test` at Plan 05 boundary | jwt-epoch.spec 8/8 GREEN; `2fa-required-guard.spec.ts` RED (require-2fa.guard.ts unstaged at this boundary — Plan 07 GREEN brings it back). Wave-3 cross-talk; documented as Rule 3. |
| Cross-user revoke = 404 (NOT 403) | OK — `SessionService.revokeOne` returns `null` on cross-user, controller maps via `NotFoundException`. |
| revoke-all bumps epoch atomically before returning | OK — `revokeAllForUser` awaits `bumpEpoch` BEFORE return. Plan 04's tests cover the bump-then-cache-bust ordering. |
| Strict-allowlist Zod re-parse on `GET /sessions` | OK — `SessionListResponseSchema.parse(items)` in controller. |

---

## Hand-offs

**Plan 06 (2FA methods API):**
- Audit-action `TwoFaMethodRemoved` already in the working tree (uncommitted at the Plan-05 boundary); Plan 06 will commit it as its own atomic.
- Plan 06's removal-guard 409 path uses the `userHasSharedVaultDependency` stub seam — independent of Plan 05.

**Plan 07 (Require2FAGuard + probe route):**
- The guard count query lives in `apps/api/src/twofa/require-2fa.guard.ts` (not committed at Plan-05 boundary). Plan 07 commits it.
- Plan 05 doesn't touch the guard at all — separate concern.

**Plan 09 (throttler ordering fix):**
- After `JwtAuthGuard` becomes `APP_GUARD`, the three new user-keyed ceilings (`sessions-list-user`, `sessions-revoke-user`, `sessions-revoke-all-user`) start keying off `req.user.id` for real (currently fall back to IP — see `throttler.config.ts` comment block).

**Plan 11 (web /settings/sessions):**
- Consumes `GET /sessions` and `POST /sessions/revoke-all`. The shape match is enforced by `@simplevault/shared/zod`'s `SessionListItemSchema` + `SessionListResponseSchema` exported types.

**Plan 12 (E2E + runbook):**
- E2E spec `sessions.cy.ts` should cover: log in twice → list shows 2 → revoke other → list shows 1 → cross-user delete = 404 → revoke-all → next /me = 401 with code E1017.
- Runbook update: document the new `SESSIONS_REVOKE_ALL_RATE_LIMIT` env var (default 5), document that revoke-all forcibly clears the local refresh cookie, document the latency table reference (Plan 04 SUMMARY's "worst-case revocation latency" already covers it).

---

## Files

**Created:**
- `apps/api/src/sessions/sessions.module.ts` (25 lines)
- `apps/api/src/sessions/sessions.controller.ts` (~125 lines)
- `apps/api/src/sessions/sessions.service.ts` (~95 lines)

**Modified:**
- `apps/api/src/auth/sessions/session.service.ts` (+131 lines T1 + ~36 lines T2 = listForUser + revokeOne + revokeAllForUser)
- `apps/api/src/app.module.ts` (register SessionsModule)
- `apps/api/src/common/throttler.config.ts` (3 new ceilings + userKeyed expansion)
- `apps/api/src/common/audit-events.ts` (SessionRevoked + SessionRevokeAll)
- `packages/shared/src/zod/index.ts` (SessionListItemSchema + SessionListResponseSchema)

---

## Next plans unblocked

- **Plan 06** (2FA methods API) — independent, no shared seam beyond audit-events.ts file.
- **Plan 07** (Require2FAGuard + probe) — independent.
- **Plan 11** (web /settings/sessions) — needs API endpoints; now available.
