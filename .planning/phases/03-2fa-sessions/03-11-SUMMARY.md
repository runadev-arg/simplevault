---
phase: 03-2fa-sessions
plan: 11
subsystem: web-sessions
tags: [web, sessions, revoke, ui, settings, truth-11, truth-12, truth-13]
requires:
  - 03-05 (sessions API: GET /sessions, DELETE /sessions/:id, POST /sessions/revoke-all)
  - 02-11 (web auth-context, accessTokenStore, keyStore.wipe pattern)
provides:
  - "Web /settings/sessions surface (Truths 11–13)"
  - "apps/web/src/lib/api/sessions-client.ts typed wrappers"
affects:
  - 03-12 (Cypress E2E: add a sessions revoke spec covering single + revoke-all + cross-tab epoch invalidation)
tech-stack:
  added: []
  patterns:
    - "Reuses the shared `request` helper from auth-client.ts (exported in this commit; previously file-private). twofa-client.ts (Plan 10) reuses it too — single source for fetch + Zod + error envelope plumbing."
    - "Intl.RelativeTimeFormat for the relative-time labels — avoids the date-fns dep (~40 KB) for one use site."
    - "Confirm-then-execute UX for revoke-all (matches the Phase-02 logout pattern). Defence-in-depth wipe-on-API-failure mirrors auth-context.tsx."
key-files:
  created:
    - apps/web/src/app/(authed)/settings/sessions/page.tsx
    - apps/web/src/app/(authed)/settings/sessions/session-list.tsx
    - apps/web/src/app/(authed)/settings/sessions/revoke-button.tsx
    - apps/web/src/app/(authed)/settings/sessions/revoke-all-button.tsx
    - apps/web/src/lib/api/sessions-client.ts
  modified:
    - apps/web/src/lib/api/auth-client.ts (export `request` helper for sibling clients)
duration: ~25min
completed: 2026-05-04
---

# Phase 03 Plan 11: Web /settings/sessions

`/settings/sessions` lists every active session for the caller, pins the
"this device" row at the top with a green emerald accent, supports
per-row "Sign out" via DELETE /sessions/:id, and ships a confirm-then-
execute "Sign out everywhere except this device" CTA that bumps the
user's session_epoch server-side and wipes local state before bouncing
to /login.

**Status:** COMPLETE
**Date:** 2026-05-04
**Commits:** `7affc1e` (T1), `2bf83f4` (T2)
**Tasks:** 2/2

---

## What landed

### Task 1 — `feat(03-11-T1): /settings/sessions page + list + per-row revoke` (`7affc1e`)

**`apps/web/src/lib/api/sessions-client.ts` (new)** — typed wrappers for
`GET /sessions`, `DELETE /sessions/:id`, `POST /sessions/revoke-all`.
Imports the shared `SessionListResponseSchema` from `@simplevault/shared/zod`
so the wire shape stays in lock-step with the server controller. Reuses
the shared `request` helper from `auth-client.ts` (exported in this
commit) — fetch + Zod validation + error envelope handling stays
single-source.

**`apps/web/src/app/(authed)/settings/sessions/page.tsx` (new)** — the
route entry point. Renders `<SessionList />` (T1) and `<RevokeAllButton />`
(T2). Uses the existing (authed) layout's JWT-bootstrap guard, so the
page only renders for an authenticated caller.

**`apps/web/src/app/(authed)/settings/sessions/session-list.tsx` (new)**
— fetches `GET /sessions` on mount. Sorts the `current` row to the top,
renders a distinct emerald-accented panel for that row (no revoke
button), and a zinc panel for siblings. Empty state when only the
current session is active. Uses `Intl.RelativeTimeFormat` for the
"created/last used" timestamps — avoids the `date-fns` dep (~40 KB
uncompressed) for a single use site.

**`apps/web/src/app/(authed)/settings/sessions/revoke-button.tsx` (new)**
— per-row "Sign out" button. On 404 (cross-user / unknown id), surfaces
a generic "couldn't revoke this session" — preserves the server-side
anti-enumeration property (Truth 12: never confirm whether the id
actually existed for someone else's user).

### Task 2 — `feat(03-11-T2): revoke-all button with full local wipe + redirect` (`2bf83f4`)

**`apps/web/src/app/(authed)/settings/sessions/revoke-all-button.tsx` (new)**
— "Sign out everywhere except this device" CTA. Confirm-then-execute
pattern: clicking surfaces a rose-accented warning panel + Confirm /
Cancel buttons. On confirm:

  1. POST `/sessions/revoke-all` (server bumps `users.session_epoch`,
     family-revokes every active session row for the caller, clears the
     `__Host-refresh` cookie).
  2. `keyStore.wipe()` — zero-overwrites every Uint8Array (master_DEK,
     signing_sk, kx_sk, etc.) and clears the Map.
  3. `accessTokenStore.wipe()` — clears the in-memory JWT.
  4. `window.location.assign("/login")` — hard navigate so the next
     request from the new page can't accidentally find a stale token in
     a closure or React-state branch.

Defence-in-depth wipe-on-API-failure mirrors the existing logout
pattern (`auth-context.tsx` Phase 02-11): a transient 5xx still wipes
locally + bounces. The user is never left "still signed in" with stale
secrets in memory.

---

## Truths verified

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T11 | `/settings/sessions` lists active sessions via GET /sessions; current pinned + visually distinct, ipHashB64Prefix shown for "recognise the network", relative createdAt + lastUsedAt | OK — current row sorted first; emerald-accent panel for current vs zinc for siblings; `fp: <6 chars>` rendered before timestamps |
| T12 | Revoke-button on non-current rows hits DELETE /sessions/:id; on success row disappears | OK — onRevoked callback re-runs `listSessions()`; 404 surfaces a generic message |
| T13 | "Sign out everywhere except this device" CTA: POST /sessions/revoke-all → wipe local key-store + accessTokenStore + redirect to /login | OK — confirm-then-execute; defence-in-depth wipe on API failure |

---

## Decisions made

1. **Exported the shared `request` helper from `auth-client.ts`** rather
   than duplicating it in each new client. Plan 10 (twofa-client.ts) and
   this plan (sessions-client.ts) both consume it. Single source for
   fetch + Zod + error envelope plumbing. Tiny one-line export change in
   `auth-client.ts`; behaviour unchanged for existing callers.

2. **`Intl.RelativeTimeFormat` over `date-fns`.** The standard browser
   built-in produces locale-aware relative times ("2 hours ago", "in 3
   days") — exactly what the plan needed. `date-fns` is ~40 KB; the
   browser API is free.

3. **Sort `current` row to top in the client.** The server returns rows
   in some order (the controller's `.list` doesn't impose one for the
   caller's row). Client sorting keeps the pinning resilient if the
   server impl changes — the API contract guarantees `current: true`
   for the caller's row but doesn't promise it appears first.

4. **404 surfaces as "Couldn't revoke this session"** (not "session
   does not exist"). Anti-enumeration: the user MUST NOT be able to
   distinguish "the id was never theirs" from "the row was already
   revoked". The server-side 404-not-403 already enforces this on the
   wire; the UI mirrors it.

5. **Cross-tab implication documented inline in the file.** Revoke-all
   bumps the user's session_epoch, so other open tabs of the same user
   lose their access token within ≤60s (Plan 04 SessionEpochCache TTL)
   and the auto-refresh hook on those tabs bounces them to /login.
   Operator behaviour, not a defect — documented for Phase 12 Cypress
   to assert.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm typecheck` (apps/web) | GREEN |
| `pnpm build` (apps/web) | GREEN — `/settings/sessions` First-Load JS = 127 kB |
| Existing 4 api specs | GREEN (no API changes) |
| Live e2e | NOT RUN — Plan 12 ships the Cypress spec for revoke / revoke-all / cross-tab epoch invalidation |

---

## Hand-offs

**Plan 03-12 (E2E Cypress):** add a `sessions.cy.ts` spec covering:
  - log in twice from two distinct cookie jars (simulating two devices);
  - on the first jar, navigate to `/settings/sessions` — assert two rows
    with the current one labelled "This device";
  - revoke the other row → assert list updates + the second jar's `/me`
    returns 401 within ≤60s (epoch cache TTL);
  - sign out everywhere except this device → assert keyStore is wiped +
    redirected to `/login` + the second jar's `/me` returns 401;
  - re-login from this device, confirm only one session row.

**Plan 13 (hardening pass):** consider switching to a stale-while-
revalidate pattern for `GET /sessions` (e.g. SWR or TanStack Query) so
the list updates without a full re-fetch on every revoke. Not needed
for ≤50-user scale; revisit only if the page feels sluggish at use.

---

## Files

**Created:**
- `apps/web/src/app/(authed)/settings/sessions/page.tsx`
- `apps/web/src/app/(authed)/settings/sessions/session-list.tsx`
- `apps/web/src/app/(authed)/settings/sessions/revoke-button.tsx`
- `apps/web/src/app/(authed)/settings/sessions/revoke-all-button.tsx`
- `apps/web/src/lib/api/sessions-client.ts`

**Modified:**
- `apps/web/src/lib/api/auth-client.ts` (export `request` helper)
- `apps/web/src/app/(authed)/settings/sessions/page.tsx` (T2 wires `<RevokeAllButton />`)
