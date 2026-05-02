# auth-flow-auditor — Phase 02

**Date:** 2026-05-02
**Scope:** Phase 02 auth surface — invite redeem, signup, login, refresh, logout, /me
**Method:** static read-only audit of API + web + DB schema + Cypress sad-path spec
**Verdict:** PASS-WITH-CONCERNS

---

## Executive summary

Phase 02 implements the documented auth model with substantial care:

- Two-secret model (master_password + 16-B secret_key) is enforced; the
  server NEVER receives password / secret_key / recovery phrase. SignupDto
  is `.strict()`, Pino redaction is comprehensive (defence in depth).
- Refresh-token rotation uses `SELECT ... FOR UPDATE`, family-id, and
  `used_at` reuse detection. Reuse → entire family revoked + structured
  audit event (`auth.refresh.reuse_detected`). The DB schema, service
  logic, and audit-event chain are all correct.
- `__Host-refresh` cookie issuance is correct: `httpOnly + secure +
  sameSite=strict + path=/` with no `Domain` attribute.
- Access token is in-memory only client-side. Comprehensive grep of
  `apps/web/src` finds zero `localStorage` / `sessionStorage` /
  `IndexedDB` writes for auth state — only documentation strings
  describing the invariant.
- Logout invariants honoured: client wipes locally on API failure
  (try/catch around `apiLogout()` in `auth-context.tsx:81-85`); server
  family-revokes via `revokeFamilyByToken` and idempotently clears the
  cookie.
- JWT params: HS256 + jose, `JWT_SECRET ≥ 32 B` enforced at boot, `kid`
  set, `sub`/`sid`/`fam` claims, `exp` from `ACCESS_TOKEN_TTL` (default
  900 s = 15 min). Constant-time hash compare on login with deterministic
  dummy verifier (`dummyHash()` derived from `JWT_SECRET`).
- Email canonicalisation is consistent: server stores `lower(email)` via
  the unique functional index; AAD binder `SHA256(lower(email))` is
  computed identically on both client paths
  (`signup-derivations.ts:62-64` and `login-derivations.ts:39-41`).
- Rate limits are Redis-backed, named per-route, with `Retry-After` set
  on 429. `/me` is keyed by user-id post-auth.
- `auth-flow-auditor` mandate items 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 all
  PASS.

Three concerns surfaced, the most material being a soft drift from the
strict byte-equal-error-response invariant required by mandate item 1
("Drift = HIGH").

## Findings

### F1. Error envelope `requestId` breaks byte-equality across miss types  — HIGH

**Files:**
- `apps/api/src/common/filters/all-exceptions.filter.ts:14-16, 58`
- `apps/web/cypress/e2e/auth-sad.cy.ts:64, 133`

**Evidence:** `AllExceptionsFilter.catch()` reads `req.id` (populated by
`nestjs-pino` / `pino-http` with a unique value per request) and embeds
it as `error.requestId` in every error response body:

```ts
res.status(status).json({ error: { code, message, requestId } });
```

Two consecutive `/auth/login` calls with different miss types
(unknown-email vs. existing-email-wrong-secret) produce JSON bodies that
differ by exactly that `requestId` byte sequence. The Cypress spec
asserts:

```ts
expect(JSON.stringify(resA.body)).to.equal(JSON.stringify(resB.body));
```

This is byte-inequality even when both responses are functionally
identical (same status, same code, same message). The Phase 02 truth #6
("Login response shape + status + timing IDENTICAL across miss types")
is intent; the implementation drifts because of a per-request id leaking
into the body. By the auditor mandate ("Drift = HIGH") this blocks.

**Subtlety:** the differing bytes are NOT a *miss-type* oracle — an
attacker cannot infer which check failed from `requestId` alone.
However:
1. The Cypress assertion will fail intermittently or always once
   request-id middleware is wired in CI (it is — `nestjs-pino`'s
   `pinoHttp` auto-sets `req.id`).
2. The strict invariant is the mandate; "morally equivalent" isn't
   enough.

**Recommendation:**
- Move `requestId` from response body into a dedicated response header
  (e.g. `X-Request-Id`). Keep the body strictly `{error:{code,message}}`.
- Update web `AuthClientError` to read `requestId` from headers.
- Update Cypress assertion if the byte-equality test is to keep its
  meaning.

**Severity rationale:** Mandate-defined ("Drift = HIGH"). No CVSS
attached because the drift does not by itself create an enumeration
oracle; it is a hardening invariant violation that breaks the test
asserting it.

### F2. `POST /invite/redeem` discloses the bound email on success  — MEDIUM

**Files:**
- `apps/api/src/invite/invite.service.ts:64-69`
- `apps/api/src/invite/invite.dto.ts` (`InviteRedeemResponse.email`)

**Evidence:** A successful redeem returns the invite-bound email in the
response body. An attacker who obtained a leaked invite code (operator
distribution channel breach, screenshot, OOB intercept) can probe the
endpoint to discover the *target user's* email — useful for downstream
phishing, social-engineering, or attribution.

```ts
return {
  inviteId: row.id,
  email: row.email,            // <- leaks PII to whoever holds the code
  argon2Params: params,
  serverArgonSalt: serverArgonSalt.toString("base64"),
};
```

The wizard UX uses the email to pre-fill the signup form — but the
operator already shared the email with the recipient out-of-band when
they delivered the code. The endpoint does not need to teach it back.

**Recommendation:** Drop `email` from the response. Either:
- (a) require the redeemer to submit `{code, email}` and verify both
  match before returning success (preferred — turns invite into a
  two-factor binding), or
- (b) leave the wizard to ask the user for their email at signup time
  and let the unique-violation on the lower-email index handle dupes.

Option (a) is anti-enumeration-friendly: still 400 with the canonical
INVITE_INVALID body on any miss.

### F3. `/auth/logout` returns 200 with `{ ok: true }`, web client expects 204  — LOW

**Files:**
- `apps/api/src/auth/logout/logout.controller.ts:17, 54`
- `apps/web/src/lib/api/auth-client.ts:178-180, 297-304`

**Evidence:** Server uses `@HttpCode(HttpStatus.OK)` and returns
`{ ok: true }`. Web client `request()` short-circuits to `undefined`
only on 204. The schema `z.unknown()` happens to accept `{ ok: true }`
so this works, but the comment in `auth-client.ts:298` (`Server returns
204 No Content`) is wrong. Not a security issue — both paths still wipe
the in-memory store via `auth-context.tsx:86-89`. Defence-in-depth
(local wipe on API failure) holds.

**Recommendation:** Either change server to `@HttpCode(204)` and
`return undefined`, or update the web comment + drop the 204 special
case.

### F4. `useAutoRefresh` literal-string check `"AUTH_REFRESH_REUSED"` never matches  — LOW

**Files:** `apps/web/src/lib/auth/use-auto-refresh.ts:65-71`

**Evidence:** The hook treats five conditions as auth failure:

```ts
const isAuthFail =
  e instanceof AuthClientError &&
  (e.status === 401 ||
    e.code === "AUTH_REFRESH_REUSED" ||
    e.code === "AUTH_INVALID_CREDENTIALS" ||
    e.code === "E1005" ||
    e.code === "E1001");
```

The shared error-code constant is `AUTH_REFRESH_REUSE_DETECTED` (value
`"E1005"`) — neither the literal name `"AUTH_REFRESH_REUSED"` nor the
string `"AUTH_INVALID_CREDENTIALS"` is what the server emits (the server
emits the *value* `"E1001"` / `"E1005"`). The fallback `e.status === 401`
+ `e.code === "E1005"` / `"E1001"` already covers every real path, so
behaviour is correct, but two of the five clauses are dead.

**Recommendation:** Remove the dead string clauses; or import the
`ErrorCodes` const from `@simplevault/shared` and compare against the
canonical values.

### F5. `loginEmail` rate-limit keyed by email — minor enumeration knob  — INFO

**Files:** `apps/api/src/common/throttler.config.ts:75-89`

**Evidence:** `SimpleVaultThrottlerGuard.generateKey` keys
`login-email` by `lower(req.body.email)`. An attacker can probe an email
to consume its bucket (5/IP/min already restrains cross-account abuse;
10/email/hour is the second ceiling). Both existing and non-existing
emails consume the same bucket — there is no oracle. Documented for
completeness; no action.

### F6. `req.id` can be `undefined` if pino middleware path is bypassed  — INFO

**Files:** `apps/api/src/common/filters/all-exceptions.filter.ts:13-16`

**Evidence:** Filter falls back to `requestId = "unknown"` if `req.id`
isn't a string/number. With `nestjs-pino` wired in `app.module.ts:124-133`
this should never trigger, but if a future short-circuit handler runs
before the logger middleware, error correlation degrades silently.
Cosmetic. (Resolves itself if F1's recommendation moves requestId to a
header generated in a global middleware.)

## Mandate item-by-item verdict

| # | Item | Verdict | Notes |
|---|---|---|---|
| 1 | Account enumeration via timing — dummy Argon2id + byte-equal responses | **DRIFT** | Timing floor correct (`login.service.ts:74-77`); response body NOT byte-equal due to F1 |
| 2 | Anti-enum on invite redeem & signup | PASS | Redeem failure path collapses to canonical 400; signup duplicate-email and invite-invalid both collapse to AUTH_INVITE_INVALID 400 (`signup.service.ts:131-144`). F2 is a separate PII-disclosure concern, not an enumeration timing issue. |
| 3 | Refresh rotation + family-revoke on reuse | PASS | `session.service.ts:163-237` tx + `FOR UPDATE` + reuse path. Audit event emitted. |
| 4 | `__Host-refresh` cookie attributes | PASS | `httpOnly + secure + sameSite:"strict" + path:"/"`, no `Domain`. (`login.controller.ts:94-100`, `refresh.controller.ts:80-86`) |
| 5 | Access token in-memory only | PASS | Grep verifies no localStorage/sessionStorage/IndexedDB writes for auth state in `apps/web/src`. |
| 6 | Logout invariants — local wipe on API failure | PASS | `auth-context.tsx:79-89` try/catch; server `revokeFamilyByToken` + cookie clear. |
| 7 | JWT params (HS256, ≥32B secret, sub/sid/fam, kid, exp) | PASS | `jwt.service.ts:26-90`. No `aud`/`iss` (acceptable for single-audience API; recommend setting them in Phase 03). |
| 8 | Auto-refresh hook (60s lead, fail-closed on auth, soft retry on net) | PASS | `use-auto-refresh.ts:25-127` with one 30s soft retry. F4 is a string-literal cleanup, behaviour correct. |
| 9 | CSRF posture — `__Host-` cookie + same-origin + SameSite | PASS | SameSite=Strict + `__Host-` + `credentials: "include"` only. State-changing routes other than `/auth/refresh` and `/auth/logout` use Bearer auth (e.g. `/me`), never cookie. |
| 10 | Email canonicalisation (lower+trim, AAD binder = SHA256(lower(email))) | PASS | `LoginSchema` `.email().toLowerCase().trim()` (login.dto.ts:23); AAD `emailHash` calls `email.toLowerCase()` on both signup and login derivations. Server stores via `lower(email)` functional index. |
| 11 | Recovery code rotation deferred to Phase 11 | PASS | No half-implemented rotation flow. `recovery_hmac` is signup-time only. |
| 12 | Pino redaction list comprehensive | PASS | `app.module.ts:25-119` covers headers, cookies, every wrapped-key field, all bytea body keys, access/refresh tokens, plus wildcard `*.dek`/`*.kek`/etc. |

## Confidence + caveats

- Cypress sad-path spec was reviewed but NOT executed. The byte-equality
  assertion (`auth-sad.cy.ts:64,133`) is the one most likely to flake in
  CI given F1 — operator should watch the first CI run on a PR.
- Server-side timing-floor relies on the assumption that DB-lookup
  jitter dominates over the constant-time memcmp. This is true in
  practice (PG round-trip is ms; memcmp on 32B is ns). No instrumentation
  was performed to assert distribution.
- No live runtime check of cookie issuance against a curl probe. Static
  audit only — see `login.controller.ts:94-100` for the literal options.

## Verdict

**PASS-WITH-CONCERNS.**

Phase 02 implementation is materially correct and the load-bearing
invariants (two-secret model never touches the server, refresh rotation
+ family-revoke, `__Host-` cookie hygiene, in-memory access tokens,
logout-always-wipes, JWT shape, Pino redaction) all PASS. The HIGH
F1 (response body drift via `requestId`) is a hardening / test-spec
issue, not an enumeration oracle, but the auditor mandate explicitly
classifies any drift in the byte-equal invariant as HIGH and therefore
blocking for Phase 02 gate sign-off.

**Action required for Phase 02 gate to flip to PASS:**
- Resolve F1 (move `requestId` to header OR drop from error body OR
  freeze it to a constant for unauthenticated 401 responses).
- Resolve F2 (drop `email` from `/invite/redeem` response, prefer
  two-input binding).

F3, F4, F5, F6 are non-blocking cleanups.

---

## RE-RUN 2026-05-02 — FINDING-0010 closure verification

**Scope.** Verify operator's fix for FINDING-0010 (F1 above): `requestId`
moved from JSON error body to `X-Request-Id` response header on
`AllExceptionsFilter`, `ErrorEnvelopeSchema` tightened on the web
client, CORS `exposedHeaders` extended in `apps/api/src/main.ts`.

**Method.** Static read-only re-audit of the three changed files,
cross-checked against `apps/web/cypress/e2e/auth-sad.cy.ts:64,133`,
`apps/api/src/app.module.ts:124-133` (pino-http config), and
`node_modules/.pnpm/pino-http@10.5.0/node_modules/pino-http/logger.js:233-240`
(`reqIdGenFactory` default behaviour).

### Per-check evidence

**1. `AllExceptionsFilter` body shape — PASS.**
`apps/api/src/common/filters/all-exceptions.filter.ts:59` —
`res.status(status).json({ error: { code, message } })`. No `requestId`
key on the body. No other per-request fields. Array `message` is
collapsed via `m.join(", ")` at line 41 (still possible client-input
echo, but only on the validation-failed path, where collapse is constant
across requests with the same input — orthogonal to anti-enumeration on
auth/login + invite/redeem). `X-Request-Id` is set at line 58 via
`res.setHeader`. No remaining body-write path embeds `requestId`.

**2. Web client `auth-client.ts` — PASS.**
`apps/web/src/lib/api/auth-client.ts:78-83` — `ErrorEnvelopeSchema`
matches strictly `{ error: { code, message } }` (no `requestId`).
`request()` reads header at line 157 (`res.headers.get("x-request-id")`,
case-insensitive per `Headers.get` contract). `postJson()` reads header
at line 217 with the same contract. `AuthClientError.requestId` is wired
through both success-shape (lines 160-168) and fallback (lines 170-175)
paths in `request()`, and likewise (lines 220-228, 230-235) in
`postJson()`. Client debugging continues to work via the header.

**3. `main.ts` CORS — PASS.**
`apps/api/src/main.ts:48` — `exposedHeaders: ["X-Request-Id"]`. Browser
JS in cross-origin dev (`apps/web` on :3000 hitting api on :3001) can
read the header via `Headers.get`. Line 47 also lists `X-Request-Id` in
`allowedHeaders`, which permits CORS-preflight tolerance for clients
that send the header inbound — this does NOT cause the server to read
or echo it (see check 6 below).

**4. Anti-enumeration byte-equality — PASS.**
For both Cypress assertions (`auth-sad.cy.ts:64` invite expired vs.
bogus, and `:133` /auth/login unknown-email vs. existing-email-wrong-key):

- `code` already collapses to a single canonical code per failure
  surface (invite → `AUTH_INVITE_INVALID`; login → `AUTH_INVALID_CREDENTIALS`).
- `message` is the canonical static string for each code (no per-request
  data interpolation in the throw sites — verified at
  `invite.service.ts` and `login.service.ts` static thrown messages).
- No other fields are added to the body — the filter writes literally
  `{ error: { code, message } }`.

Body bytes are now identical across miss types. Cypress
`JSON.stringify(resA.body) === JSON.stringify(resB.body)` will hold.

**5. Regression check — PASS.**

| Invariant | Source | Status |
|---|---|---|
| Refresh rotation + family revoke | `session.service.ts` (untouched) | unchanged |
| `__Host-refresh` cookie attributes | `login.controller.ts:94-100`, `refresh.controller.ts:80-86` (untouched) | unchanged |
| Access token in-memory only (no localStorage etc.) | `apps/web/src/lib/auth/*` (untouched) | unchanged |
| Pino redact list | `app.module.ts:108-119` (untouched) | unchanged; `X-Request-Id` value is a counter integer, not a secret, so absence from redact list is fine |
| Constant-time login | `login.service.ts:74-77` (untouched) | unchanged |
| Anti-enum on /invite/redeem failure | `invite.service.ts` (untouched) | unchanged |
| Audit-event chain | `common/audit-events.ts` (untouched; still has `requestId?: string`) | unchanged; audit-event still records the same `req.id` value via internal API |

**6. Subtle correctness — `req.id` provenance — PASS.**
`req.id` is populated by `pino-http`'s `loggingMiddleware` at
`logger.js:141` via `req.id = req.id || genReqId(req, res)`. The
SimpleVault `LoggerModule.forRoot({ pinoHttp: ... })` config in
`app.module.ts:124-133` does NOT supply a custom `genReqId`, so
pino-http's `reqIdGenFactory` default (`logger.js:233-240`) is used:

```js
function reqIdGenFactory (func) {
  if (typeof func === 'function') return func
  const maxInt = 2147483647
  let nextReqId = 0
  return function genReqId (req, res) {
    return req.id || (nextReqId = (nextReqId + 1) & maxInt)
  }
}
```

Two observations:

- The fallback on `req.id ||` checks whether anything has *already* set
  `req.id` on the express request object. Nothing in SimpleVault's
  middleware chain (`grep -rn 'req\.id\s*=' apps/api/src` — only the
  filter reads it; nothing writes) sets `req.id` from the inbound
  `X-Request-Id` header. Express + body-parser + helmet + CORS do not
  populate `req.id` either. Therefore the active branch is the
  monotonic counter `nextReqId = (nextReqId + 1) & maxInt` —
  constant-shape, server-controlled, not derived from any client input.
- Inbound-trust policy: **ignore-and-overwrite (counter only)**. A
  client-supplied `X-Request-Id: <attacker-string>` header is NOT read
  by pino-http or by any middleware, and therefore is NOT echoed back
  in the response header. No log-injection vector. No per-victim
  fingerprinting vector. No content-injection in the response header.

The `X-Request-Id` value emitted is an integer 1..2³¹-1 (per process,
resets on restart). It contains zero user-controlled bytes and no
secrets. Safe to log; safe to expose to the browser via CORS.

**Note (non-finding):** `X-Request-Id` is listed in CORS `allowedHeaders`
at `main.ts:47`, which lets cross-origin clients SEND the header. The
server does not read it (see above). This is dead permission today and
could be removed for tidiness, but it does not enable any attack
because there is no code path that consumes the inbound value. Not
worth a finding.

### Verdict

**VERIFIED-CLOSED.**

The fix is correct, complete, and does not introduce a new vector.
FINDING-0010 is resolved. No new findings during this re-run.

