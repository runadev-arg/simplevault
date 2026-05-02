---
Date: 2026-05-02
Auditor: input-validation-auditor
Scope: Phase 02 — every new endpoint + new web form. Zod posture, .strict(),
       body-size caps, email canonicalization, KDF parameter bounds,
       Drizzle parameterization, web/server schema-drift.
Method: Read-only inspection of:
        - apps/api/src/main.ts (global pipes + body-limit)
        - apps/api/src/invite/{controller,service,dto}.ts
        - apps/api/src/auth/signup/{controller,service,dto}.ts
        - apps/api/src/auth/login/{controller,service,dto}.ts
        - apps/api/src/auth/refresh/refresh.controller.ts
        - apps/api/src/auth/logout/logout.controller.ts
        - apps/api/src/auth/sessions/session.service.ts
        - apps/api/src/me/{controller,service}.ts
        - apps/api/src/crypto/crypto.service.ts
        - apps/api/src/common/filters/all-exceptions.filter.ts
        - packages/shared/src/zod/index.ts
        - packages/db/src/schema/{users,invite_codes,user_sessions}.ts
        - apps/web/src/lib/api/auth-client.ts
        - apps/web/src/app/{signup,login}/** form schemas
Verdict: PASS-WITH-CONCERNS — no Critical/High findings. Validation
         posture across the new endpoints is solid: every controller
         body is parsed via Zod `.strict()`, every bytea field is
         length-checked post-base64-decode, KDF params are bounded both
         by Zod (upper) and by a server-side floor (lower), all SQL is
         parameterised through Drizzle, and the web client mirrors the
         server response shapes. Three Medium and three Low findings
         are raised — none block the gate.
---

# Input-Validation Audit — Phase 02

## Verdict

**PASS-WITH-CONCERNS** — three Medium / three Low findings.
No Critical, no High. None block the Phase 02 merge.

## Per-endpoint table

| Endpoint | Method | DTO file | `.strict()` | Length caps | Notes | Status |
|---|---|---|---|---|---|---|
| `/invite/redeem` | POST | `apps/api/src/invite/invite.dto.ts` | YES | code: 8..64 chars + base32+hyphen regex | All failure modes collapse to uniform `INVITE_INVALID` 400; no enumeration | OK |
| `/auth/signup` | POST | `apps/api/src/auth/signup/signup.dto.ts` | YES (outer + nested `argon2Params`) | UUID inviteId; fixed-32B hashes; fixed-16B salt; variable 32..256B AEAD blobs | Email comes from invite row, never user-controlled at signup | OK |
| `/auth/login` | POST | `apps/api/src/auth/login/login.dto.ts` | YES | email: standard `.email().toLowerCase().trim()`; verifier fixed 32 B | Body shape uniform; constant-time compare path proven | OK |
| `/auth/refresh` | POST | _(no DTO — body unused)_ | n/a | none on body | Cookie token is parsed from header; no schema validates an empty body — see FINDING-0014 | FINDING (Low) |
| `/auth/logout` | POST | _(no DTO — body unused)_ | n/a | none on body | Same as refresh — see FINDING-0014 | FINDING (Low) |
| `/auth/params` | GET | n/a | n/a (no body) | n/a | Returns global params + global salt; constant body for every caller | OK |
| `/me` | GET | n/a (auth-only) | n/a (no body) | n/a | Response shape `MeResponseSchema.parse(...)` enforces strict allow-list before send | OK |

## Findings count by severity

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 3 |
| Info | 0 |

(Auth-flow-auditor's earlier FINDING-0012 in `FINDINGS.md` already captures the logout 200-vs-204 shape drift this auditor independently flagged; no duplicate raised here.)

## Findings (numbered, appended to `.planning/security/FINDINGS.md`)

### FINDING-0014 — `/auth/refresh` and `/auth/logout` accept arbitrary bodies (no `.strict()` empty-body schema)

- **Severity:** Low
- **Affected:**
  - `apps/api/src/auth/refresh/refresh.controller.ts:24-45`
  - `apps/api/src/auth/logout/logout.controller.ts:19-25`
- **Description:** Both endpoints read the refresh token from the
  `__Host-refresh` cookie and ignore the request body. There is no
  `.strict()` Zod schema rejecting unknown keys / non-empty bodies.
  Defence in depth: a misbehaving / abused client could POST large
  JSON bodies to either endpoint up to the global Express JSON body
  limit (~100 KiB default — see FINDING-0015). Not exploitable today
  because nothing reads the body, but a future contributor could add
  body fields without realising the contract was unset.
- **Recommendation:** Add a `z.object({}).strict()` schema and parse
  the body in both controllers; reject 400 on any non-empty body. Or
  document the "ignore body" contract with a `safeParse` against an
  empty schema and bounce non-conforming requests early.
- **Blocks merge:** No.

### FINDING-0015 — Express body-parser limit not explicitly configured in `main.ts`

- **Severity:** Low
- **Affected:** `apps/api/src/main.ts:10-66`
- **Description:** No explicit `app.use(json({ limit: "..." }))` or
  `NestExpressApplication.useBodyParser('json', { limit: "..." })`.
  Nest 11 + body-parser default JSON limit is 100 KiB, which is
  comfortably above the largest legitimate Phase 02 payload (signup
  envelope ~3 KiB) and below DoS-relevant sizes. Not a vulnerability,
  but the operator-visible cap should be set explicitly so a future
  refactor (adding a vault-item upload endpoint, say) doesn't silently
  inherit 100 KiB.
- **Recommendation:** In `main.ts`, set
  `app.useBodyParser('json', { limit: '64kb' })` (or similar small
  cap). Auth flow needs nothing larger; vault-item endpoints in Phase
  04 should opt into a higher cap per-route.
- **Blocks merge:** No.

### FINDING-0016 — Argon2 iteration upper bound (64) is generous vs. recommended ceiling (10)

- **Severity:** Low
- **Affected:** `apps/api/src/auth/signup/signup.dto.ts:59`
- **Description:** Phase 02 audit mandate calls for KDF parameter
  bounds of `time ∈ [2, 10]` and `memory ∈ [19456, 1048576]`. The
  current Zod schema upper-bounds memory at exactly 1 048 576 KiB
  (good) but caps iterations at 64 (vs. spec 10). The lower bound is
  enforced server-side via `crypto.service.validateArgon2ParamsAboveFloor`
  (m ≥ 19456, t ≥ 2). Because the verifier comparison itself is a
  byte-compare (no server-side Argon2 derivation per request), an
  inflated `iterations` is self-DoS only — the *client* burns the
  CPU on every login. Still, lowering the cap aligns the bound with
  the spec and prevents a malicious wizard from saving a value the
  user can't unwrap on a low-end device.
- **Recommendation:** Tighten the Zod ceiling: `iterations` to `≤ 10`,
  add explicit `parallelism: z.literal(1)` already present (good).
  Memory upper bound is already correct.
- **Blocks merge:** No.

### FINDING-0017 — `users.email` / `invite_codes.email` and `LoginSchema.email` lack a length cap

- **Severity:** Medium
- **Affected:**
  - `packages/db/src/schema/users.ts:35`
  - `packages/db/src/schema/invite_codes.ts:35`
- **Description:** Both columns are `text` (PostgreSQL unbounded
  varchar). The login DTO validates `z.string().email()` with no
  `.max(N)`, so a malicious client can submit a multi-megabyte
  string that clears a regex-permissive `email()` parser before the
  `lower(...)` index lookup. PG will store it (no row-level cap), and
  every subsequent login or invite-redeem that hits `lower(email)`
  pays comparison cost on the long string. Not a DoS multiplier on
  its own (still bounded by the global JSON limit), but it is a
  defence-in-depth gap on the storage tier.
- **Recommendation:** Add `.max(254)` to the Zod email field on
  `LoginSchema` (RFC 5321 maximum). Add a CHECK constraint or
  `varchar(254)` to the `email` columns in both schema files; ship
  via a Drizzle migration in a Phase 02 follow-up commit (or carry as
  Phase 03 hardening). Apply the same cap to the CLI `invite create`
  email arg validator.
- **Blocks merge:** No.

### FINDING-0018 — Web `/login` form does not validate email with a Zod schema before submit

- **Severity:** Medium
- **Affected:** `apps/web/src/app/login/page.tsx:88-106`
- **Description:** The form trims + lowercases the email but does not
  apply a Zod schema (no react-hook-form + zod-resolver pattern; the
  validation is hand-coded to check for non-empty strings). The
  server's `LoginSchema` enforces `.email()` and (after FINDING-0017
  applies) `.max(254)`, but the client wastes a network round-trip
  + Argon2 derivation (multi-second on user device) before the
  server rejects an obviously malformed email. UX-degrading and
  abuse-vector-amplifying (every retry re-runs Argon2id locally;
  a typo loop costs the user serious watt-hours).
- **Recommendation:** Either share the server's `LoginSchema` from
  `packages/shared/src/zod/index.ts` or co-locate a parallel client
  Zod schema in `apps/web/src/lib/api/auth-client.ts` and validate at
  submit. Same fix for `/signup` invite-code step (already does a
  regex test — good — but no shared schema).
- **Blocks merge:** No.

_(No FINDING raised here for the logout response-shape drift — auth-flow-auditor's earlier FINDING-0012 in `FINDINGS.md` already covers it.)_

## What was checked and is OK

The following items in the audit mandate were checked and are **green**:

1. **Zod on every DTO**: Every controller method that accepts a body
   parses via `Schema.safeParse(body)` and throws
   `BadRequestException` with the uniform error envelope on failure.
   No class-validator usage anywhere in the new code (the
   `ValidationPipe` in `main.ts` is left in place from Phase 01 but
   does no work because the new controllers type their bodies as
   `unknown` and parse manually).
2. **`.strict()` posture**: `InviteRedeemSchema`, `SignupSchema` (outer
   + inner `argon2Params`), `LoginSchema`, `MeResponseSchema` — all
   chained `.strict()`. Forbidden field names (`password`,
   `secret_key`, `recoveryPhrase`) on the signup envelope are rejected
   by the outer `.strict()` before the controller body runs — REQ-CRYPTO-003
   contract met.
3. **Email canonicalization**: `LoginSchema` does
   `z.string().email().toLowerCase().trim()`. Invite-code emails are
   lowercased by the issuing CLI on insert (per `invite_codes.ts:24`).
   Login service uses `lower(email) = lower(${input.email})` in PG —
   so client+server agree byte-for-byte. No drift observed.
4. **Length caps on bytea fields**: Every base64 field decodes to a
   `Buffer` and is checked exact (`fixedB64(32)` for verifier hashes
   and pubkeys, `fixedB64(16)` for salts) or bounded (`variableB64(32, 256)`
   for AEAD-wrapped private-key blobs). Slots that the server uses
   downstream (insert into `users`) are length-validated at the DTO
   boundary.
5. **10-field signup envelope**: Plan 02-07 spec has 10 fields; DTO
   has exactly 10 (`inviteId`, `argon2SecretKeyHash`, `argon2Params`,
   `userArgonSalt`, `wrappedMasterDek`, `wrappedMasterDekRecovery`,
   `recoveryInnerHash`, `userPubKey`, `wrappedUserSigningSk`,
   `wrappedUserKxSk`). AAD label inputs are FROZEN per
   `02-PHASE-SUMMARY.md §Load-bearing decisions §2` and are NOT
   user-controlled (the per-user binder is a server-derived
   SHA256(lower(email)) — email itself comes from the invite row at
   signup, not the user submission).
6. **Argon2 params lower bound**: The `crypto.service` floor
   (`memoryKiB ≥ 19456 ∧ iterations ≥ 2 ∧ parallelism === 1`) is
   enforced both at boot for the operator-supplied env params and at
   signup for the client-supplied params. KDF-downgrade vector
   closed.
7. **Secret key format**: 16-byte Crockford-base32. Server never
   receives the raw secret key (only the Argon2id verifier
   derivative); web `/login` validates Crockford via
   `crockfordToBytes(secretKeyText)` before deriving the verifier.
8. **Mnemonic on the wire**: Confirmed — only `recoveryInnerHash`
   (the 32-byte SHA-256 of the normalised phrase) crosses the wire
   on signup; no field carries the BIP-39 phrase. The server's
   `outerRecoveryHmac` wraps the inner hash with
   `SERVER_RECOVERY_HMAC_SECRET`. Recovery flow (Phase 02 stops
   here) only stores the HMAC.
9. **Invite-code format**: regex `^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z-]{8,64}$`
   matches Crockford-base32 + hyphens, length-capped 8..64. CLI in
   Plan 06 prints 31-char codes; the regex accepts them.
10. **Drizzle SQL parameterization**: All `sql\`...\`` usages
    (`signup.service.ts:68`, `session.service.ts:175`,
    `login.service.ts:63`) interpolate values via the tagged-template
    binding form (`${input.inviteId}`, `${tokenHash}`,
    `${input.email}`). No raw string concatenation. No SQL injection
    surface.
11. **Refresh-cookie validation**: Cookie value is read by a tiny
    custom parser (`parseCookie` in `refresh.controller.ts:106-117`)
    and passed straight to `SessionService.rotate(rawToken, ...)`.
    `rotate` derives `BLAKE2b-256(rawToken)` and looks it up in
    `user_sessions.refresh_token_hash`. A malformed / oversized token
    simply doesn't match any row → 401 INVALID_CREDENTIALS. No
    parsing or schema-validation needed because the token is
    treated as an opaque byte string.
12. **Error responses**: `AllExceptionsFilter` produces a uniform
    `{ error: { code, message, requestId } }` envelope. ZodError
    messages are NOT echoed verbatim — controllers catch `safeParse`
    failure and throw a generic `VALIDATION_FAILED` 400 with the
    fixed message `"Invalid request body"`. No password / secret-key
    plaintext could reach the response body via this path. (Pino
    redaction is the second line of defence on log lines.)

## Closing note

Phase 02 input validation posture is the strongest of any phase to
date. The findings raised above are tightening recommendations, not
defects — none rise to the threshold that blocks a Phase 02 merge.
Fix FINDING-0017 (email column length cap) early in Phase 03 to
avoid carrying a per-row unbounded text column into the vault-items
schema cascade.
