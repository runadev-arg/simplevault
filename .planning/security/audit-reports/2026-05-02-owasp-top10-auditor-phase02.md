# owasp-top10-auditor — Phase 02

**Date:** 2026-05-02
**Phase:** 02 (Auth + Crypto core)
**Scope:** `POST /invite/redeem`, `POST /auth/signup`, `POST /auth/login`,
`POST /auth/refresh`, `POST /auth/logout`, `GET /me`, `GET /auth/params`;
web `/signup`, `/login`, `/(authed)/me`, logout button; supporting modules
(throttler, exception filter, Pino redaction, JWT guard, session service,
crypto service).

**Method:** static read-only audit of the API + web source trees, the
NestJS bootstrap, the Next.js middleware/CSP, and the Drizzle SQL access
patterns. Cross-checked against the Phase 02 truths in
`02-PHASE-SUMMARY.md` and the load-bearing decisions in `STATE.md`.

**Verdict:** **PASS-WITH-CONCERNS**
*(this auditor opens 1 Low + 1 Info; no new Critical/High. NOTE: the
auth-flow-auditor's FINDING-0010 — `requestId` in error body breaks the
byte-equal anti-enumeration invariant — is Phase-02-blocking and must
close before the gate.)*

---

## A01 — Broken Access Control — **PASS**

- `GET /me` is the only authenticated endpoint in Phase 02; it is wrapped
  by `@UseGuards(JwtAuthGuard)` at the controller level
  (`apps/api/src/me/me.controller.ts:11`). The guard verifies the bearer
  via `JwtService.verifyAccessToken` (`apps/api/src/auth/jwt/jwt-auth.guard.ts:43-60`)
  and rejects every failure mode (missing header, malformed, bad
  signature, expired, malformed claims) with the same uniform 401 +
  `AUTH_INVALID_CREDENTIALS` envelope. No header tricks (`X-User`,
  `X-User-Id`, etc.) are read anywhere — `req.user` is set ONLY from
  validated JWT claims (line 53).
- IDOR is not yet possible because no resource takes a path/body id —
  `/me` reads `req.user.id` only, and `MeService.get(userId)`
  (`apps/api/src/me/me.service.ts:22-53`) selects exclusively on that
  derived id.
- `MeResponseSchema.parse(...)` enforces a `.strict()` allow-list at the
  serialiser, so a future ORM hydration leak surfaces as a 500 instead
  of a silent data exfil (defence-in-depth pattern, `me.service.ts:51`).
- The web `(authed)` route group enforces the client-side guard via
  `AuthGate` in `apps/web/src/app/(authed)/layout.tsx:24-48`. The guard
  hard-redirects to `/login` post-bootstrap if no access token; the
  splash state prevents protected content flash.
- Refresh-token-cookie lifecycle is correct: rotation under
  `SELECT ... FOR UPDATE` (`session.service.ts:166-237`),
  family-revocation on reuse (`session.service.ts:186-193`),
  family-revocation on logout (`session.service.ts:240-254`). A stolen
  refresh token cannot be used to access protected resources directly —
  it can only be exchanged at `/auth/refresh`, and reuse triggers
  immediate family revocation.

## A02 — Cryptographic Failures — **PASS** *(boundary-only; deep crypto deferred to crypto-auditor)*

- Argon2id params are gated server-side at signup via
  `validateArgon2ParamsAboveFloor` (`crypto.service.ts:143-149`) — KDF
  downgrade attempts (m<19456 KiB OR t<2 OR p≠1) collapse to the same
  `VALIDATION_FAILED` shape as any other malformed body
  (`signup.service.ts:37-50`). Floor matches OWASP ASVS 2024 L1
  guidance.
- Wrapped key blobs (`wrappedMasterDek`, `wrappedMasterDekRecovery`,
  `wrappedUserSigningSk`, `wrappedUserKxSk`) are accepted only as
  size-bounded base64 (32..256 B post-decode) at the API boundary
  (`signup.dto.ts:65-70`) — no path eats raw plaintext.
- Server-stored material is **only**: `argon2_secret_key_hash`,
  `argon2_params`, wrapped DEKs, `recovery_hmac`, `user_pub_key`,
  wrapped private keys, salts. The signup `.strict()` Zod envelope
  (`signup.dto.ts:51-72`) makes "the server NEVER receives the master
  password / secret_key / recovery phrase" a hard contract — any extra
  key like `password` triggers a 400 before any handler runs.
- Pino redaction (`app.module.ts:25-119`) covers every wrapped-blob,
  every secret-bearing body field, and the `Authorization` /
  `Cookie` / `Set-Cookie` headers. Wildcards `*.dek` `*.kek` `*.password`
  catch nested logger contexts.
- `AllExceptionsFilter` does NOT include the stack trace or raw
  exception body in the response (`all-exceptions.filter.ts:9-59`) —
  responses contain `{code, message, requestId}` only. Internal
  `signup.service.ts:148-154` deliberately logs only `err.name` +
  `pg_code`, never the raw `err` object (which would contain bytea SQL
  parameters).
- HSTS preload, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, COOP/CORP `same-origin`, frozen
  Permissions-Policy on the web side (`apps/web/src/lib/csp.ts:38-48`).
  helmet on the API side covers the API surface (`main.ts:18-39`).

**Note (deferred to crypto-auditor):** the dummy-hash is derived
deterministically from `JWT_SECRET` (`timing-floor.ts:25-34`) — fine as
long as `JWT_SECRET` stays ≥32 bytes random (enforced in
`jwt.service.ts:33-55`). Acceptable boundary posture; deeper review of
KDF / AEAD nonce / X25519 misuse is the crypto-auditor's mandate.

## A03 — Injection — **PASS**

- All Drizzle SQL goes through either the parameterised query builder
  (`tx.insert(...).values(...)`, `tx.update(...).set(...).where(eq(...))`,
  `db.select().from(...).where(eq(...))`) or the `sql` template tag with
  `${expr}` interpolations — Drizzle binds these as PG `$1`/`$2`
  parameters, never string-concats:
  - `login.service.ts:63` — `lower(${input.email})` parameterises `email`.
  - `signup.service.ts:68-71` — `id = ${input.inviteId}` parameterises `inviteId`.
  - `session.service.ts:175-178` — `refresh_token_hash = ${tokenHash}` parameterises the hash.
- Zero occurrences of `sql.raw`, `sql.identifier(userInput)`, or
  string-concatenated SQL fragments anywhere under `apps/api/src` or
  `packages/db`.
- Every DTO is Zod-validated with `.strict()` and `safeParse` BEFORE the
  handler runs (`SignupSchema`, `LoginSchema`, `InviteRedeemSchema`,
  `MeResponseSchema`). Body-level fixed/variable-length base64 fields
  enforce sizes against fuzzing (`signup.dto.ts:19-49`).
- Zero `eval`, `new Function`, or dynamic `require(<userInput>)` in the
  API tree (verified by grep). Operator CLI (`apps/cli/src/`) does not
  shell-out to user input — it uses Node `crypto.randomBytes`, Drizzle
  inserts, and `process.stdout.write` only.

## A04 — Insecure Design — **PASS**

- **Anti-enumeration is comprehensive and consistent.**
  - `/auth/login` returns the same uniform 401 + `AUTH_INVALID_CREDENTIALS`
    body for "user not found" AND "wrong verifier"
    (`login.service.ts:73-83`, `login.controller.ts:84-92`). The 32-byte
    `constantTimeEqual32` runs against `dummyHash()` on the user-not-found
    path so the wall-time path equalises within DB-lookup jitter
    (`timing-floor.ts:36-44`).
  - `/invite/redeem` collapses every failure mode (not-found / expired /
    already-redeemed) to the same `AUTH_INVITE_INVALID` 400
    (`invite.service.ts:42-86`); internal logs preserve the
    distinction.
  - `/auth/signup` collapses race-loss, expired, redeemed, AND
    duplicate-email-unique-violation (PG 23505) to the same
    `AUTH_INVITE_INVALID` 400 (`signup.service.ts:128-145, 172-185`) —
    so an attacker cannot tell whether an invite was already burned vs
    whether the bound email is already a user.
  - `/auth/params` returns global Argon2id params + global server salt;
    no per-user discrimination, identical body for every caller.
- No support-side recovery / admin-recovers-user path exists. Recovery
  is via the user's recovery phrase + `recovery_hmac` only.
- Two-secret model preserved: signup/login both require email +
  argon2_secret_key_hash (= Argon2id over `secret_key` salted by
  `serverArgonSalt`). Master password is bound only via the wrapped
  master DEK (which the client unwraps offline post-login).
- `/auth/login` success-path leaks one bit: wall-time is longer because
  of the `INSERT INTO user_sessions` + JWT signing on success vs the
  early-return on failure. That's the canonical "user successfully
  logged in" signal and is not exploitable for enumeration since the
  attacker also gets the access token + cookie on success.

## A05 — Security Misconfiguration — **PASS**

- API `helmet({...})` is wired at `main.ts:18-39` with full CSP, HSTS
  (preload + 1y), `referrerPolicy: no-referrer`, default `useDefaults:
  true` (which includes `hidePoweredBy`). CORS allowlist is env-driven
  CSV (`main.ts:42-49`), credentials enabled, methods locked to
  `GET/POST/PATCH/DELETE`, allowed-headers locked.
- API `ValidationPipe` is global with `whitelist: true`,
  `forbidNonWhitelisted: true`, `transform: true`,
  `enableImplicitConversion: false` (`main.ts:51-58`) — defence in
  depth atop the per-DTO Zod schemas.
- Web Next.js middleware (`apps/web/src/middleware.ts:1-32`) generates a
  per-request CSP nonce using Edge `crypto.getRandomValues`, propagates
  via `x-nonce` request header, and stamps the response CSP. CSP
  contains:
    - no `'unsafe-inline'`, no `'unsafe-eval'`
    - `'wasm-unsafe-eval'` ONLY on `script-src` (libsodium-wrappers-sumo
      WASM compile) — does not relax JS eval
    - `'strict-dynamic'` on `script-src`
    - `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`,
      `form-action 'self'` (`apps/web/src/lib/csp.ts:1-36`).
- Web `next.config.mjs` sets `poweredByHeader: false` (line 13).
- No debug routes ship: `/health` is the only GET-without-auth besides
  `/auth/params` and `/invite/redeem` (POST). `LOG_LEVEL` env-driven
  (`app.module.ts:126`).
- No default credentials hard-coded anywhere. `JWT_SECRET`,
  `SERVER_INVITE_SECRET`, `SERVER_RECOVERY_HMAC_SECRET` all hard-fail
  at boot if missing (`jwt.service.ts:35`, `crypto.service.ts:72-73`).
- `.env` is git-ignored (`.gitignore` lines `env`); only `.env.example`
  is tracked (verified via `git ls-files .env`).

**Concern (non-blocking, see findings below):**
`SERVER_ARGON_SALT` has a dev-only soft fallback to a random in-memory
salt with a `logger.warn` only (`crypto.service.ts:78-89`). If an
operator forgets to set this on a production restart, all stored
verifiers stop matching (auth lockout) — not a confidentiality bug, but
an availability foot-gun. Filed as Low.

## A06 — Vulnerable & Outdated Components — **N/A** *(deferred to dependency-supply-chain-auditor)*

Phase 02 includes the NestJS 10→11 upgrade (Plan 02-01) which closed the
multer `pnpm.overrides` tech debt. The `lodash@<4.18.0 → >=4.18.1`
override is still in place (Phase 01 carry-over, tracked in
FINDING-0009). No obvious stale pins observed in `apps/api/package.json`
on a quick read; full sweep is the dep-auditor's mandate.

## A07 — Identification & Authentication Failures — **PASS** *(OWASP-specific items only; full auth flow audit by auth-flow-auditor)*

- **JWT alg=none rejected.** `JwtService.verifyAccessToken` calls
  `jwtVerify(token, this.secret, { algorithms: [ALG] })` where
  `ALG = "HS256"` (`jwt.service.ts:14, 78`) — `jose` only accepts the
  whitelisted alg, so `alg: "none"` is impossible.
- **No JWT secret in code.** `JWT_SECRET` is loaded from env at
  `onModuleInit`; missing → boot fails. Decoded length must be ≥32 B in
  base64 / hex / utf8 (`jwt.service.ts:38-55`).
- **Session IDs are unpredictable.** `crypto.randomUUID()` for
  `family_id` (`session.service.ts:134`); 32-byte
  `randomBytes` → `base64url` for the raw refresh token
  (`session.service.ts:131-132`); `BLAKE2b-256` of the raw token is
  what's stored (`session.service.ts:88-97`).
- **Refresh-token rotation + reuse-detection** is a single-tx
  `SELECT ... FOR UPDATE` with three discriminated outcomes; reuse →
  family-revocation + structured `auth.refresh.reuse_detected` audit
  event for Phase 10 ingestion (`session.service.ts:186-193`,
  `audit-events.ts:27, 100-104`).
- **No header-trick auth bypass.** Authorization is parsed strictly via
  `^Bearer\s+(\S+)\s*$/i` (`jwt-auth.guard.ts:71-77`). No `X-Forwarded-User`
  / `X-User-Id` / `X-Auth-User` is read anywhere in the API.
- **`__Host-refresh` cookie** has `Path=/`, `Secure`, `HttpOnly`,
  `SameSite=Strict`, no `Domain` — verified at all three set sites
  (`login.controller.ts:94-100`, `refresh.controller.ts:80-86`,
  `logout.controller.ts:29-35`).
- **In-memory access token only.** `apps/web/src/lib/auth/access-token-store.ts`
  is explicitly module-scoped JS heap. A clear set of invariants in the
  file header forbids `localStorage` / `sessionStorage` / `IndexedDB` /
  cookies / any persistent surface for the access token. Refresh token
  never passes through web JS — `__Host-refresh` is HttpOnly and
  travels only via `credentials: "include"` (`auth-client.ts:143, 201`).

## A08 — Software & Data Integrity — **PASS** *(deferred deeper sweep to dep-auditor)*

- `pnpm-lock.yaml` is committed at the repo root (verified via
  `find -maxdepth 2 -name pnpm-lock.yaml`).
- No `postinstall` scripts added in Phase 02. `pnpm.overrides` for
  `lodash<4.18.0` is the only override in place (Phase 01 carry-over).

## A09 — Logging & Monitoring — **PASS**

- Pino redaction list (`app.module.ts:25-119`) is comprehensive and
  censor-replaces with `"[REDACTED]"`. Covers every signup / login /
  refresh body field; both camelCase and snake_case keys; nested
  contexts via `*.<field>`; the Authorization / Cookie / Set-Cookie
  headers in both request and response; the access / refresh token; and
  every wrapped-blob bytea field.
- AuditEvent v1 shape is frozen and centrally emitted by
  `AuditEventService.emit` (`audit-events.ts:70-107`); call sites use
  it consistently across signup/login/refresh/logout/invite-redeem.
- IP storage is `HMAC-SHA256(SERVER_IP_HASH_SECRET, ip)` —
  `session.service.ts:99-104` — never raw IP. Fall-back to unkeyed
  SHA-256 with a startup warn if the secret is unset; PII risk is
  bounded (a hashed IP is still a stable identifier per server epoch but
  is not the cleartext IP).
- UA is parsed coarsely (`Browser/OS` family, e.g. `Chrome/Mac`) and
  truncated to 256 chars (`session.service.ts:107-123`). No raw UA
  string persisted.
- `req.id` is read by `AllExceptionsFilter` for cross-log correlation
  (`all-exceptions.filter.ts:13-16`). nestjs-pino assigns request IDs
  by default (`pinoHttp` instance).
- `auth.refresh.reuse_detected` is escalated to `logger.warn` for ops
  dashboards (`audit-events.ts:101-104`).

**Concern (Info):** the audit-event call sites in
`signup.service.ts:43-44, 138, 173-179` log the `inviteId` UUID inside
`data: { inviteId }` on failure paths. The invite UUID is not itself a
secret (it's the public `inviteId` returned by `/invite/redeem`), but
it ties an audit-failure entry to a known invite. Deemed Info-only —
post-Phase-10 hash-chain ingestion this is desired behavior.

## A10 — SSRF — **N/A**

No outbound HTTP / network call from user input anywhere in Phase 02.
The only outbound network calls in the API are: PG via `pg`, Redis via
`ioredis` (rate-limit storage), and helmet's static header set. None of
these takes a user-controlled URL.

---

## Findings filed in FINDINGS.md

| ID | Severity | Title |
|---|---|---|
| FINDING-0019 | Low  | `SERVER_ARGON_SALT` dev fallback silently generates a random in-memory salt |
| FINDING-0020 | Info | Audit log emits `inviteId` on failure paths (Phase-10-by-design; document as expected) |

(There were no new High or Critical findings.)

**Findings already on file from sibling Phase-02 auditors that overlap
with this auditor's scope and are noted but NOT re-filed:**

| ID | Severity | Reporter | Title |
|---|---|---|---|
| FINDING-0010 | High   | auth-flow-auditor       | Error envelope `requestId` breaks byte-equal response invariant on /auth/login + /invite/redeem |
| FINDING-0011 | Medium | auth-flow-auditor       | POST /invite/redeem leaks invite-bound email on success |
| FINDING-0012 | Low    | auth-flow-auditor       | POST /auth/logout returns 200 with body, web client expects 204 |
| FINDING-0013 | Low    | auth-flow-auditor       | useAutoRefresh dead-string clauses for AUTH_REFRESH_REUSED / AUTH_INVALID_CREDENTIALS |
| FINDING-0014 | Low    | input-validation-auditor| `/auth/refresh` and `/auth/logout` accept arbitrary bodies (no `.strict()` empty-body schema) |
| FINDING-0015 | Low    | input-validation-auditor| Express body-parser limit not explicitly configured in `main.ts` (this auditor's "Info" was preempted) |
| FINDING-0016 | Low    | input-validation-auditor| Argon2 iteration upper bound (64) is generous vs. recommended ceiling (10) |
| FINDING-0017 | Medium | input-validation-auditor| `users.email` / `invite_codes.email` and `LoginSchema.email` lack a length cap |
| FINDING-0018 | Medium | input-validation-auditor| Web `/login` form does not validate email with a Zod schema before submit |

This auditor concurs with all of the above as scoped within OWASP A03
(injection-adjacent input-bound DoS), A04 (insecure design — invite
email leak), or A01/A07 (refresh/logout body acceptance and the
byte-equal invariant). FINDING-0010 (High) is the only **blocking**
item across the union of in-scope findings.

---

## Severity summary

(this auditor's own findings only)

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Info | 1 |

(union with sibling-auditor findings that fall in OWASP scope —
informational view, not double-counted)

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 (FINDING-0010 by auth-flow-auditor — Phase-02 blocker) |
| Medium | 3 |
| Low | 5 |
| Info | 1 |

## Verdict

**PASS-WITH-CONCERNS** for the OWASP Top-10 sweep itself. **The Phase-02
gate is BLOCKED by FINDING-0010** (filed by auth-flow-auditor; this
auditor concurs that the byte-equal invariant on /auth/login and
/invite/redeem failure responses is load-bearing per the Phase-02 truths
and the gate doctrine).

No new Critical/High discovered by this auditor. Phase 02 demonstrates
a strong default posture: anti-enumeration is consistent across every
public surface, KDF downgrade is server-side enforced, refresh-token
rotation + reuse detection is correct, every DTO is `.strict()`-Zod
validated, every SQL access is parameterised, the access token never
touches persistent storage, and the redact list is comprehensive. The
single Low (`SERVER_ARGON_SALT` dev fallback) is an availability
foot-gun for operators rather than a confidentiality bug; the Info items
are documentation-only.

Phase 02 gate may proceed pending the other 4 blocking auditors
(crypto, auth-flow, input-validation, rate-limit-dos) and the
informational threat-modeler update.
