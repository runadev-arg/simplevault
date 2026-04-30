# Phase 02 — Auth + Crypto core (Implementation summary)

**Status:** IMPLEMENTATION COMPLETE — all 12 plans done; awaiting
`/gsd:verify-work 2` security gate (5 blocking auditors + threat-modeler
informational).

**Date range:** 2026-04-28 → 2026-04-30
**Plans:** 12 plans across 7 waves
**Goal (per 02-INDEX.md):** A user can redeem an operator-issued invite
code, generate a master password + 128-bit secret_key + 24-word BIP-39
recovery phrase **client-side**, sign up, log in from a fresh browser
using all three secrets, and log out — with timing-uniform error handling
and short-lived JWT + rotating refresh tokens.

## Plan map

| Plan | Title | Wave | Status | SUMMARY |
|---|---|---|---|---|
| 01 | NestJS 10 → 11 upgrade + drop multer override | 1 | DONE | [02-01-SUMMARY.md](./02-01-SUMMARY.md) |
| 02 | crypto: Argon2id + AEAD + calibrate (TDD) | 2 | DONE | [02-02-SUMMARY.md](./02-02-SUMMARY.md) |
| 03 | crypto: BIP-39 + key hierarchy + recovery wrap (TDD) | 2 | DONE | [02-03-SUMMARY.md](./02-03-SUMMARY.md) |
| 04 | crypto: X25519 sealed-box + symbol-parity + node barrel tighten (TDD) | 3 | DONE | [02-04-SUMMARY.md](./02-04-SUMMARY.md) |
| 05 | DB schema: users extend + sessions + invite_codes | 2 | DONE | [02-05-SUMMARY.md](./02-05-SUMMARY.md) |
| 06 | Operator CLI: `invite create` + `argon2 calibrate` | 3 | DONE | [02-06-SUMMARY.md](./02-06-SUMMARY.md) |
| 07 | API: POST /invite/redeem + atomic POST /auth/signup | 4 | DONE | [02-07-SUMMARY.md](./02-07-SUMMARY.md) |
| 08 | API: POST /auth/login + /auth/refresh + /auth/logout | 4 | DONE | [02-08-SUMMARY.md](./02-08-SUMMARY.md) |
| 09 | API: GET /me + audit-events + throttler + Pino redaction | 5 | DONE | [02-09-SUMMARY.md](./02-09-SUMMARY.md) |
| 10 | Web /signup multi-step flow + Ed25519 backfill | 6 | DONE | [02-10-SUMMARY.md](./02-10-SUMMARY.md) |
| 11 | Web /login + auto-refresh + (authed) group + /me + logout | 6 | DONE | [02-11-SUMMARY.md](./02-11-SUMMARY.md) |
| 12 | E2E (Cypress) + CI job + operator runbook | 7 | DONE | [02-12-SUMMARY.md](./02-12-SUMMARY.md) |

## Goal-backward truths verdict

(13 truths from 02-INDEX.md "Goal-backward truths" section.)

| # | Truth | Verdict |
|---|---|---|
| 1 | `pnpm cli invite create` writes single-use 7-day-TTL HMAC-bound code; prints to stdout | TRUE — 02-06 |
| 2 | `POST /invite/redeem` returns invite metadata; `redeemed_at` set only after `/auth/signup` succeeds (atomic) | TRUE — 02-07 |
| 3 | `POST /auth/signup` accepts the 10-field envelope; server NEVER sees password / secret_key / recovery phrase | TRUE — 02-07 + 02-10 |
| 4 | Web /signup forces secret_key + recovery-phrase reveal + 4-word challenge confirmation; server-side gate via `recovery_hmac` | TRUE — 02-07 server gate + 02-10 wizard |
| 5 | `POST /auth/login` returns access JWT (15min HS256) + `__Host-refresh` cookie (30d, single-use) | TRUE — 02-08 + 02-11 client |
| 6 | Login response shape + status + timing IDENTICAL across miss types (constant-time Argon2id dummy) | TRUE — 02-08 (timing-floor via dummy Argon2id, NOT setTimeout) + 02-12 byte-equal spec |
| 7 | `POST /auth/refresh` rotates token, single-use; replay revokes family + emits `auth.refresh.reuse_detected` | TRUE — 02-08 + 02-09 audit emit |
| 8 | `POST /auth/logout` revokes family, clears cookie | TRUE — 02-08 + 02-11 client |
| 9 | `GET /me` returns ONLY `{id, email, createdAt, argon2Params}` (locked schema) | TRUE — 02-09 |
| 10 | Login + signup + refresh + invite-redeem rate-limited per REQ-RATELIMIT-002/003 | TRUE — 02-09 (Redis-backed `@nestjs/throttler@6` + 9 named ceilings) |
| 11 | Server stores ONLY: argon2_secret_key_hash + argon2_params + wrapped DEKs + recovery_hmac + public keys + wrapped private keys | TRUE — 02-05 schema (no plaintext columns by construction) |
| 12 | `pnpm test` in `packages/crypto` exercises every primitive; green in node + browser | TRUE — 71 tests (02-02/03/04) |
| 13 | E2E happy + sad path | LANDED — 02-12 specs authored; CI job runs them on every PR. Local-execute gap documented in 02-12-SUMMARY. |

**12/13 truths VERIFIED in code or tests; truth #13 awaits the first CI
run on a PR (this branch is `main` so CI gating is post-merge).**

## Cumulative changes (top-level)

### New packages / modules

- `packages/crypto/` — full real-impl crypto package (Argon2id, AEAD,
  BIP-39, key hierarchy, X25519 sealed-box, calibrate). 71 tests, green
  in node + browser test environments. Conditional exports preserved;
  browser bundle has zero `node:crypto` references (regex-verified).
- `apps/cli/` — new `@simplevault/cli` workspace with binary
  `simplevault-cli`, two subcommands (`invite create`, `argon2
  calibrate`).

### New API surface

- `POST /invite/redeem` — invite-code exchange.
- `POST /auth/signup` — atomic signup (10-field envelope; server-side
  recovery-HMAC gate).
- `POST /auth/login` — uniform-shape, uniform-timing.
- `POST /auth/refresh` — rotation + family-revocation on reuse.
- `POST /auth/logout` — family-revoke + cookie-clear.
- `GET /me` — minimal profile.
- `GET /auth/params` — global Argon2 params + server_argon_salt
  (anti-enum: identical body for every caller).

### New web surface

- `/signup` — 6-step wizard with reducer-enforced advance gates +
  client-side libsodium derivations; in-memory key-store with `wipe()`.
- `/login` — single-step form (email + master pw + secret_key);
  in-memory access-token store + key-store.
- `/(authed)/layout.tsx` — client-side guard with `AuthProvider` +
  `useAutoRefresh` + bootstrap-from-cookie.
- `/(authed)/me/page.tsx` — minimal profile + logout button.
- `/auth/refresh` auto-refresh hook — fires 60 s before exp; soft
  retry once on transient network errors; fail-closed on auth errors.

### Schema additions

- `users` table extended with: `argon2_secret_key_hash`, `argon2_params`,
  `wrapped_master_dek`, `wrapped_master_dek_recovery`, `recovery_hmac`,
  `wrapped_user_signing_sk`, `wrapped_user_kx_sk`, `user_pub_key` +
  `user_kx_pub_key`, `user_argon_salt`.
- `user_sessions` table — `family_id`, `prev_token_id`,
  `refresh_token_hash` (BLAKE2b-256), `used_at`, `revoked_at`,
  `expires_at`, `ip_hash`, `user_agent_family`.
- `invite_codes` table — `code_hash` (HMAC-SHA256), `email`,
  `created_by`, `redeemed_at`, `expires_at`.
- Drizzle migration generated and applied via `apps/api`'s
  `migrate-then-start.sh`.

### NestJS infrastructure

- Upgraded 10.4.x → 11.x; `pnpm.overrides` for `multer<2.1.1` REMOVED.
- `@nestjs/throttler@6.5` + `@nest-lab/throttler-storage-redis@1.2`
  replace the in-memory limiter; 9 named ceilings; fail-open on Redis
  outage with warn-log + `Retry-After`.
- Pino redaction list extended (load-bearing for auth-flow-auditor):
  `secretKey`, `secret_key`, `recoveryPhrase`, `masterPassword`,
  `argon2_secret_key_hash`, `dek`, `kek`, `nonce`, all wrapped key
  fields, `req.headers.authorization`, `res.headers['set-cookie']`,
  `req.body.token`, `req.body.refreshToken`, plus the existing list.

### CI / supply-chain

- New `e2e` job in `.github/workflows/ci.yml` boots postgres + redis
  service containers, runs migrations + Cypress, uploads artifacts on
  failure.

### Operator runbook

- `docs/operator/SECURITY-NOTES.md` — Argon2id calibration section.
- `docs/operator/DOKPLOY-DEPLOY.md` — full Phase-02 env-var matrix,
  same-origin requirement (Traefik path-routing under
  `pass.runadev.com`), pre-cutover checklist, CLI reference.

## Load-bearing decisions (FROZEN — changing requires re-threat-model)

1. **Two-secret model** confirmed (REQ-CRYPTO-003): master_password +
   16-B secret_key. Recovery phrase is a third optional secret used
   only for vault-key recovery, not auth.
2. **AAD per-user binder = SHA256(lower(email))** (decision from 02-10;
   re-derived byte-identically at login in 02-11). Per-blob AAD label
   prefixes are FROZEN: `"sv:user-master:v1|"`, `"sv:user-recovery:v1|"`,
   `"sv:user-sign-sk:v1|"`, `"sv:user-kx-sk:v1|"`.
3. **`__Host-refresh` cookie** with `Path=/`, `Secure`, `HttpOnly`,
   `SameSite=Strict`, no `Domain`. Forces same-origin deployment.
4. **Global Argon2 params + global server_argon_salt** (decision from
   02-11): `GET /auth/params` returns both. `users.server_argon_salt`
   row is now an unused historical snapshot for future per-user-salt
   migration.
5. **Timing-floor** via constant-time dummy Argon2id, NOT setTimeout.
6. **Family-revocation on refresh-token reuse** with structured Pino
   event `auth.refresh.reuse_detected` for Phase-10 audit-chain
   ingestion.
7. **`/me` body shape** locked at `{id, email, createdAt, argon2Params}`
   `.strict()`.
8. **`AuditEvent` v1 shape** FROZEN for Phase 10 hash-chain ingestion.
9. **Operator CLI delivery** out-of-band; SMTP deferred to Phase 07.

## Open items / known limitations / tech debt

- **Web app test infra not landed** — Vitest/RTL deferred (02-10 + 02-12
  context). E2E coverage substitutes for now; if Phase 04+ vault-item
  components benefit from unit tests, that's where to invest.
- **Master-password not re-promptable post-refresh** — browser hard
  refresh restores access JWT but not the unwrapped master_KEK /
  master_DEK. `/me` works (only needs JWT) but Phase 04's vault items
  must decide: re-prompt UI vs read-only mode.
- **`users.server_argon_salt`** is a per-user column that is currently
  ignored at runtime (global salt is authoritative). Decision to keep
  for forward compat; remove in Phase 13 if not needed.
- **JWT `kid` rotation runbook** not yet written. Phase 02 ships
  single-key; rotation is Phase 14.
- **No SMTP integration in v1** — invite codes delivered OOB by the
  operator (Signal / in-person / operator's own email client).
  Phase 07 lifts this.
- **`pnpm.overrides` for `lodash@<4.18.0`** still in place from 01-09.
  Remove when no transitive dep pulls in old lodash; track via Dependabot.
- **Cypress local-run gap** — 02-12 SUMMARY documents that the suite
  was authored but not run end-to-end locally in the implementation
  loop. CI is the verification authority.

## Carry-over hand-offs to Phase 03+

### Phase 03 (WebAuthn + TOTP 2FA)

- Reuse `auth-context.tsx` + `useAutoRefresh` + `(authed)` route group
  patterns; 2FA enrolment + step-up flows hang off `/me` and a new
  `/login/2fa` page.
- `users` table will need a 2FA-enrolment column-set; coordinate with
  `user_sessions` so a session row records "step-up satisfied at T".
- Threat model: STRIDE refresh on the 2FA paths.

### Phase 04 (vault items)

- `master_DEK` is in `keyStore.getBytes("master_dek")` after a
  successful `/login`. Vault items wrap with this key under per-vault
  DEKs.
- Browser hard-refresh **does not** restore the keyStore. Phase 04 must
  decide between re-unlock prompt and read-only mode.

### Phase 07 (sharing + SMTP)

- Invite-code delivery becomes SMTP; the existing `invite_codes.email`
  field is already a binding identifier and will continue to be after
  SMTP lands. Operator override for OOB delivery should remain.

### Phase 10 (audit chain)

- `AuditEvent` v1 shape is FROZEN; Phase 10 wires the HMAC-chained
  append-only log + checkpoint signing per
  `docs/operator/SECURITY-NOTES.md` "Audit checkpoint git repo".
- Pino events emitted in Phase 02 (`auth.signup.ok`, `auth.login.ok`,
  `auth.login.fail`, `auth.logout`, `auth.refresh.ok`,
  `auth.refresh.reuse_detected`, `invite.redeem.ok`,
  `invite.redeem.fail`) are the input stream.

### Phase 13 (hardening)

- Decide: drop `__Host-` cookie if subdomains needed (alice.pass…).
- Decide: per-user Argon2 calibration (currently global).
- Decide: re-key `SERVER_INVITE_SECRET` runbook (out of scope for now).

### Phase 14 (production cutover)

- Pre-cutover checklist in `docs/operator/DOKPLOY-DEPLOY.md` is the
  authority. Operator MUST: generate 6 secrets, run argon2 calibrate
  on the VPS, verify Traefik routes, issue first invite, walk the
  signup, verify auto-refresh + logout.
- Backups (rsync over SSH) wired in Phase 14; SSH target +
  authorized_keys decision still operator-pending.

## Security gate hand-off

`/gsd:verify-work 2` runs the 5 blocking auditors:

| Auditor | Primary input |
|---|---|
| crypto-auditor | `packages/crypto/src/*` + `apps/api/src/crypto/*` + the AAD-label scheme + recovery_hmac flow |
| auth-flow-auditor | `apps/api/src/auth/*` + signup/login/logout/refresh + `/me` + Pino redaction list + Cypress sad-path spec |
| owasp-top10-auditor | route guards on `/me` + `/auth/*` + `/invite/*`; KDF; AEAD; RNG |
| input-validation-auditor | every Zod DTO; `.strict()` posture; no SQL injection (Drizzle parameterised); body size limits |
| rate-limit-dos-auditor | `@nestjs/throttler` config + 9 named ceilings + Cypress rate-limit smoke spec |
| threat-modeler (informational) | Updated Login flow STRIDE + AT-5 + M0 baseline §2 + §10 |

Phase 02 is **closed** when all 5 blocking auditors PASS in
`.planning/security/AUDIT-LOG.md` with no Critical/High open in
`FINDINGS.md`, AND threat-modeler Phase-02 update is committed.
