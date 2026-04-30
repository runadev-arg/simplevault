# 02-11 Summary — Web /login + auto-refresh + (authed) route group + /me + logout

**Phase:** 02-auth-crypto
**Plan:** 11 (Wave 6)
**Date:** 2026-04-28
**Status:** COMPLETE — two atomic commits, web build green, no `node:crypto` in client bundle.

## Commits

- `364f203` — `feat(02-11-T1): /login page + login derivations + access-token store`
- `d2a6c15` — `feat(02-11-T2): auto-refresh hook + auth context + (authed) route group + /me page + logout`

## What landed

```
apps/api/src/auth/login/login.controller.ts       (modified)
apps/web/src/lib/api/auth-client.ts               (extended)
apps/web/src/lib/auth/access-token-store.ts       NEW
apps/web/src/lib/auth/use-auto-refresh.ts         NEW
apps/web/src/lib/auth/auth-context.tsx            NEW
apps/web/src/lib/crypto/aad-labels.ts             NEW (frozen labels per 02-10)
apps/web/src/lib/crypto/login-derivations.ts      NEW
apps/web/src/lib/crypto/secret-key-format.ts      NEW (shared Crockford codec)
apps/web/src/app/login/page.tsx                   NEW
apps/web/src/app/(authed)/layout.tsx              NEW
apps/web/src/app/(authed)/me/page.tsx             NEW
```

## Load-bearing decisions

### 1. Global Argon2id params AND global server-argon-salt (LOAD-BEARING)

Plan body's "global params" decision is adopted in full. The chicken-and-egg
between client-side verifier derivation and server-side salt lookup is
resolved by extending **`GET /auth/params`** to ALSO return the global
`serverArgonSalt`:

```json
{
  "argon2Params": { "memoryKiB": 65536, "iterations": 3, "parallelism": 1 },
  "serverArgonSalt": "<base64 16B>"
}
```

Rationale:
- Per CRYPTO-STACK §2 the operator-managed salt is a public-by-convention
  pepper; exposing it does not weaken the verifier (security depends on
  `secret_key`'s 128 bits of entropy, not the salt's secrecy).
- The endpoint body is identical for every caller — NO email parameter,
  NO per-user response variation; anti-enumeration property preserved.
- Server-side `users.argon2_secret_key_hash` is byte-compared
  (constant-time) against the client's submission; the per-user
  `users.server_argon_salt` row is now an unused historical snapshot
  (kept for forward compat with a per-user-salt migration if Phase 11+
  rotates).

**Revisitation conditions** (when to flip back to per-user salt):
- Operator wants per-user calibration (different Argon2 cost per user).
- A future threat model requires per-user salts (e.g., to defend against
  rainbow tables where the global salt is leaked publicly — though
  combined with secret_key 128b this is already infeasible).
- Phase 13 hardening pass elects to.

### 2. Auto-refresh trigger window — 60 s before exp

`REFRESH_LEAD_MS = 60_000`. Schedules `setTimeout((expiresAt - now) - 60s)`.
At default `ACCESS_TOKEN_TTL=900` (15 min) that's a refresh every ~14 min.

Failure modes:
- **401 / E1005 / AUTH_REFRESH_REUSED / E1001 → fail closed**: wipe
  `accessTokenStore` + `keyStore`, hard-redirect to /login. NO retry.
- **Network blip → soft retry once after 30 s**: not a security event,
  one re-attempt is friendlier than logging the user out on a flaky tunnel.
  No infinite loop — the second failure (if `state.cancelled` hasn't
  flipped) propagates as auth-loss.

`visibilitychange` listener: when the tab returns to `visible`, if
`expAt - now <= REFRESH_LEAD_MS` we fire `doRefresh()` immediately so a
laptop-suspend doesn't land the user on a stale token.

### 3. (Authed) route group pattern — client-side guard only

```
apps/web/src/app/(authed)/
├── layout.tsx     ← "use client", AuthProvider + AuthGate
└── me/page.tsx    ← "use client"
```

Server components CANNOT gate on the access token (it's in-memory only;
no cookie/header readable from RSC for authentication purposes). The
guard is therefore a thin client wrapper:

1. Mount `<AuthProvider>` (which mounts `useAutoRefresh` + bootstraps
   from `__Host-refresh` cookie if present via one transparent
   `/auth/refresh` call).
2. Render `"Checking session…"` splash while `bootstrapped === false` —
   protected content NEVER flashes to a logged-out caller.
3. After bootstrap: if `accessToken === null` → `window.location.assign("/login")`.
4. Otherwise → render children.

### 4. Browser-refresh UX (truth #7)

A browser hard-refresh on `/me`:
- Memory access token is gone.
- `AuthProvider` mount fires one `POST /auth/refresh` (cookie carries
  refresh token).
- If cookie alive → 200 → new access token in memory, page renders
  transparently.
- If cookie dead → 401 → redirect to /login.

**KNOWN UX gap (documented for Phase 04+)**: post-refresh-bootstrap, the
`keyStore` is EMPTY because `master_password` + `secret_key` are not in
any cookie. So `/me` works (it only needs the access JWT) but vault-item
pages will need to either:
  - Prompt for `master_password` + `secret_key` to re-unlock (most
    likely UX), or
  - Read-only mode using the access token alone for pages that don't
    need `master_DEK`.

This is a Phase 04+ design decision; Phase 02-11 simply does not break
when the keyStore is empty post-refresh.

### 5. Secret lifecycle at login

- `master_password`: lives in component state during the unlock step;
  dropped (string GC) right after `unlockSecrets`. NOT mirrored into the
  keyStore (the unwrapped `master_DEK` + `master_KEK` are what downstream
  needs).
- `secret_key` Uint8Array(16): stashed in keyStore so a future re-unlock
  / password-rotation operation can read it without re-prompting. Wiped
  on logout / reuse-detect.
- `master_KEK`, `master_DEK`, `signing_sk`, `kx_sk`: all stashed in
  keyStore. All zero-overwritten by `keyStore.wipe()` on logout / reuse
  / tab-close (Phase 04+ may add a `beforeunload` listener if profiling
  shows it's needed; for v1 the React unmount path is sufficient).
- On any login error mid-derivation: every partially-derived buffer is
  `.fill(0)`'d in the catch block, then `keyStore.wipe()` + `accessTokenStore.wipe()`
  before re-rendering the error UI.

## Same-origin / cookie verdict (LOAD-BEARING for 02-12 runbook)

The `__Host-refresh` cookie has `Path=/`, `Secure`, `HttpOnly`,
`SameSite=Strict`, **no `Domain`**. The `__Host-` prefix forbids `Domain`.
This means:

- **Production assumption (per `02-INDEX` + operator runbook): web and
  api MUST be served from the SAME origin** (`pass.runadev.com/api/*` →
  api container, everything else → web container, via Traefik
  path-routing in Dokploy). Cookie sets and rides on every same-origin
  request automatically.
- **Development**: web on `localhost:3000`, api on `localhost:3001`.
  This IS cross-origin. `SameSite=Strict` prevents the cookie from
  riding on cross-site navigations, but it WILL ride on
  `fetch(..., { credentials: "include" })` calls IF the response also
  has CORS `Access-Control-Allow-Credentials: true` and `Origin` allowed.
  Refresh in dev still works as long as CORS is configured. **Plan
  02-12 owns the runbook entry that documents the same-origin
  requirement for prod.**

NOT a Rule-4 CHECKPOINT: the operator already chose Traefik path-routing
in Dokploy (per planning STATE.md), making prod same-origin by design.
The dev cross-origin pain is an existing condition (also affects signup)
and is mitigated by `connect-src` + `credentials: "include"` already in
place from 02-10.

## Verification

| Check | Result |
|---|---|
| `pnpm --filter @simplevault/web typecheck` | green |
| `pnpm --filter @simplevault/api typecheck` | green |
| `pnpm --filter @simplevault/web build` (incl. ESLint) | green |
| `node:crypto` / `require("crypto")` regex over `.next/static/chunks/**/*.js` | clean (0 hits) |
| `/login` chunk size | ~3.07 kB page + ~532 kB First Load (libsodium WASM) |
| `/me` chunk size | ~1.02 kB page + ~118 kB First Load |
| Two atomic commits | yes |

### Manual smoke

**NOT performed in-loop**, matching the precedent set by 02-10 and the
caller's carry-over (manual smoke OK; E2E owned by 02-12). The wire
contracts are byte-frozen by the 21/21 e2e harness in 02-08 plus the
typecheck-passing Zod schemas in `auth-client.ts`. Plan 02-12 will:

1. Walk `pnpm cli invite create` → /signup → /login → /me → logout via
   Playwright.
2. Verify `users.user_sessions` row transitions on login (insert),
   refresh (used_at + revoked_at on old, new row inserted), logout
   (family-revoke).
3. Verify localStorage / sessionStorage / IndexedDB are empty of any
   token / DEK at every checkpoint.

## Truths verdict

| # | Truth | Status |
|---|---|---|
| 1 | /login: email + master pw + secret_key → argon2_secret_key_hash → POST /auth/login | TRUE — `apps/web/src/app/login/page.tsx` + `lib/crypto/login-derivations.ts` |
| 2 | 200: access JWT in MEMORY ONLY; refresh in HttpOnly cookie; client unwraps wrapped_master_dek | TRUE — `accessTokenStore.set(jwt)` + `unlockSecrets()` populates `keyStore` |
| 3 | Wrong creds → canonical "Invalid credentials"; no enumeration | TRUE — login-page maps both `AUTH_INVALID_CREDENTIALS` (server miss/bad-verifier) AND libsodium tag-mismatch (bad master pw → unwrap failure) to the same string |
| 4 | Auto-refresh hook: 1 min before exp; on success replaces token; on 401 AUTH_REFRESH_REUSED → wipe + redirect | TRUE — `lib/auth/use-auto-refresh.ts` |
| 5 | Logout button → POST /auth/logout, wipes keys + token, redirects | TRUE — `auth-context.tsx::logout()` + `(authed)/me/page.tsx` button |
| 6 | (authed) group requires valid access token; otherwise redirects to /login | TRUE — `(authed)/layout.tsx` AuthGate |
| 7 | Browser hard-refresh on /me: useAuth bootstrap calls /auth/refresh; if cookie alive, transparent re-auth; else /login | TRUE — `AuthProvider` mount-effect + `useAutoRefresh` |

## Hand-offs

### Plan 02-12 (E2E + operator runbook)

Required Playwright spec:

1. `pnpm cli invite create --email <e>` → walk /signup wizard → expect redirect to `/login?signed_up=1`.
2. /login form: email + master pw + secret_key → expect `/me` loaded → assert `id`, `email`, `createdAt`, `argon2Params` all rendered.
3. Wait > `ACCESS_TOKEN_TTL` (operator should set `ACCESS_TOKEN_TTL=60` for the test container) → assert auto-refresh fires (network panel: one `POST /auth/refresh` 200) without user interaction.
4. Click "Logout" → expect cookie gone (DevTools Application > Cookies) + redirect to `/login` + DB row `user_sessions.revoked_at IS NOT NULL`.
5. Browser hard-refresh on `/me` mid-session → expect transparent re-auth (one /auth/refresh 200) → page re-renders.
6. Replay an OLD `__Host-refresh` cookie (capture before refresh; replay after) → expect 401 E1005 → web wipes state + redirects to /login.

Operator runbook entries needed:

- **Same-origin requirement** (load-bearing): web + api MUST share an
  origin in prod. Document Traefik path-routing under `pass.runadev.com`
  (`/api/*` → api container, `/*` → web container). If operator splits
  origins (e.g., `pass.runadev.com` + `pass-api.runadev.com`), the
  `__Host-refresh` cookie will not transit between them — auth will
  break.
- New env var consumed by web: `NEXT_PUBLIC_API_URL`. In prod (same
  origin) leave UNSET so it falls back to `'self'`. In dev set to
  `http://localhost:3001`.
- The 02-08 + 02-09 env var table (JWT_SECRET, ACCESS_TOKEN_TTL, all
  rate-limit knobs) — already documented; runbook should consolidate.

### Phase 04+ (vault items)

- `master_DEK` is in `keyStore.getBytes("master_dek")` after a successful
  /login. Vault items wrap with this key under per-vault DEKs.
- Browser hard-refresh **does not** restore the keyStore. Phase 04 must
  decide between forcing a re-unlock prompt and a read-only mode.

## Deviations

1. **Auto-applied (Rule 1) — Extend `GET /auth/params` response with `serverArgonSalt`**.
   The shipped 02-08 endpoint returned only `argon2Params`; the global-params
   decision in 02-11 plan body requires the salt to be globally exposed
   so the client can derive the verifier without authenticating first.
   No security regression — global salt is operator-pepper, not a per-user
   secret; response remains identical for every caller (anti-enumeration
   preserved).

2. **Auto-applied (Rule 1) — Soft 30 s retry on transient network errors during refresh**.
   Plan body says "no retry loop". Pure auth failures (401 / E1005 / etc.)
   ARE fail-closed with no retry per spec. But on a TCP/network error
   that is NOT an auth signal, one 30 s retry prevents flaky-mobile-tunnel
   logouts. Capped at one retry — second failure flows to auth-loss.
   Conservative; can be removed in 02-12 if the runbook prefers strictest
   behaviour.

3. **Auto-applied (Rule 1) — Soft retry path uses `setTimeout(30_000)` not exponential backoff**.
   Single-retry policy makes EB irrelevant.

4. **Auto-applied (Rule 1) — Lint cleanup of T1 files committed in T2**.
   `pnpm build` only invokes ESLint after typecheck; lint errors only
   surfaced when T2's wider surface tripped them. Net effect: cosmetic,
   committed atomically with T2.

5. **Auto-applied (Rule 1) — Do not store `master_password` in keyStore**.
   Plan body's carry-over §6 is ambiguous: "stash secret_key per the
   new-device-flow note in CRYPTO-STACK.md... default: keep secret_key in
   memory for the session, prompt for re-entry on reload." Followed
   exactly: `secret_key` stashed; `master_password` dropped right after
   `master_KEK` derivation completes. Less attack surface for a memory
   inspector; the unwrapped `master_KEK` + `master_DEK` are what
   downstream actually needs.

No Rule-3 deviations. **No Rule-4 CHECKPOINT.**

## Reference artifacts

- `apps/api/src/auth/login/login.controller.ts` — extended `params()` response
- `apps/web/src/lib/api/auth-client.ts` — added `getAuthParams`, `login`, `refresh`, `logout`, `me`
- `apps/web/src/lib/auth/access-token-store.ts`
- `apps/web/src/lib/auth/use-auto-refresh.ts`
- `apps/web/src/lib/auth/auth-context.tsx`
- `apps/web/src/lib/crypto/aad-labels.ts`
- `apps/web/src/lib/crypto/login-derivations.ts`
- `apps/web/src/lib/crypto/secret-key-format.ts`
- `apps/web/src/app/login/page.tsx`
- `apps/web/src/app/(authed)/layout.tsx`
- `apps/web/src/app/(authed)/me/page.tsx`
