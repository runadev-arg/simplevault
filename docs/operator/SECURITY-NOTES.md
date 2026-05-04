# Operator security responsibilities

These are things only **YOU** (the operator) can do. SimpleVault's security
posture depends on them. Claude can't generate secrets, can't provision SSH
keys on a remote backup target, and can't pick an SMTP provider for you.

## Secrets you generate and own

| Secret | Where it lives | Disaster impact if lost |
|---|---|---|
| `JWT_SECRET` | Dokploy env (api app) | All sessions invalidate; users must re-login. Annoying, not catastrophic. |
| `SERVER_CHAIN_SECRET` | Dokploy env (api app) | **AUDIT LOG VERIFICATION BREAKS** for every entry written under this secret. Critical. **Always store an offline copy** (encrypted USB / safe / paper in a safe-deposit box). |
| User Recovery Kit (per-user, displayed once at signup) | The user's responsibility — printed/screenshot/saved | If a user loses both their master password AND their Recovery Kit → **permanent data loss for that user**. We cannot recover. This is by design (zero-knowledge). |
| `secret_key` (per-user, 128-bit, two-secret model) | User's password manager / Recovery Kit | Same as above — required on every new device. |

Generate `JWT_SECRET` and `SERVER_CHAIN_SECRET` with:

```bash
openssl rand -base64 48
```

Generate them once, store an **offline** copy, then paste into Dokploy's
encrypted env-var UI. Treat them like cryptographic root material because they
are.

## Off-site backups (Phase 14)

The audit checkpoints + nightly `pg_dump` push to a separate VPS/NAS via
**rsync over SSH** (see `.planning/STATE.md` for the confirmed decision).

You need to provide BEFORE Phase 14:

- **Target host** (e.g. `backup.runadev.com`)
- **Target user** (e.g. `simplevault-backup`)
- **Target path** (e.g. `/var/backups/simplevault/`)
- **A dedicated SSH keypair**:
  - private key → Dokploy secrets (env var or mounted file)
  - public key → `~/.ssh/authorized_keys` of the target user
- **Restrict the key in `authorized_keys`** with a `command="..."` directive,
  e.g.:
  ```
  command="rrsync -wo /var/backups/simplevault/",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... simplevault-backup
  ```
  This limits a compromise of the SimpleVault VPS to **append-only** backup
  writes — an attacker with the SimpleVault private key still cannot rm/mv
  historical backups.

Do **not** rely on the hosting provider's VPS-level snapshots as your only
backup: a filesystem-level corruption can poison both the running data and the
snapshot identically. Logical `pg_dump` archives survive.

## Audit checkpoint git repo (Phase 10+)

A daily Ed25519-signed Merkle root of audit-chain heads will be committed to a
**separate** git repo (private GitHub or self-hosted Gitea). You need to:

1. Create the repo (private; minimum read-access friction).
2. Generate an Ed25519 keypair:
   ```bash
   ssh-keygen -t ed25519 -f audit-signing -C "simplevault-audit"
   ```
3. Add the public key as a **deploy key with write access** on the repo.
4. Store the private key in Dokploy secrets (mounted into the audit-cron
   container in Phase 10).

**Decide repo location BEFORE Phase 10** — changing it later requires
re-bootstrapping the checkpoint chain.

## SMTP (Phase 02+)

Required for: invite emails, login alerts, vault-sharing notifications,
password-reset hand-offs.

Pick one BEFORE Phase 02:

- **Postmark** — high-deliverability, transactional-only, paid
- **Mailgun** — flexible, generous free tier
- **Mailjet** — EU-friendly, GDPR-clear
- **Self-hosted Postfix relay** — maximum sovereignty, more ops surface

Phase 02 will need: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`,
`SMTP_FROM` (and optionally `SMTP_TLS` toggles).

## Operator account 2FA

When you sign up your **own** SimpleVault account on first deploy, enroll
**both** a hardware WebAuthn key **and** a TOTP backup. Don't be the operator
who locked themselves out of the only admin account.

If the operator account should require stricter rules than regular users
(e.g. mandatory hardware key, no TOTP-only fallback), decide before Phase 14 —
it's a roadmap-open question.

## Argon2id calibration (one-time, before production cutover)

**Why:** per-deployment calibration ensures Argon2id wall time stays in
the **500–1000 ms** band on the actual production hardware (per
CRYPTO-STACK.md §2). The Phase-02 default fallback values
(`ARGON2_MEMORY_KIB=65536`, `ARGON2_ITERATIONS=3`, `ARGON2_PARALLELISM=1`)
are conservative — on a small VPS they may run too slowly and degrade
login UX; on a beefy box they may be weaker than the host can afford.
Calibration is per-hardware: if you migrate VPS, **re-run**.

**How:**

1. SSH to the Dokploy host.
2. Exec the CLI inside the api container:
   ```bash
   docker exec -it <api-container> simplevault-cli argon2 calibrate
   ```
   (or, equivalently, `pnpm cli argon2 calibrate` from a dev checkout
   on the same host).
3. The CLI prints a target trio, e.g.:
   ```
   ARGON2_MEMORY_KIB=131072
   ARGON2_ITERATIONS=3
   ARGON2_PARALLELISM=1
   # wall time: ~720ms on this host
   ```
4. Paste those three lines into Dokploy's encrypted env-var UI for the
   `simplevault-api` service. Web does not consume these directly —
   the api returns the active params via `GET /auth/params` which the
   web wizard + login page read at runtime.
5. Redeploy the api service in Dokploy. Existing user records are NOT
   re-derived (they keep the params snapshotted at signup); new
   signups + future password rotations use the new values.

**Lower-bound floor:** values below
`ARGON2_MEMORY_KIB=19456, ARGON2_ITERATIONS=2, ARGON2_PARALLELISM=1`
(OWASP 2024 minimum) mean the host is too underpowered for production —
either pick a bigger VPS or accept a weaker security posture explicitly.

## Periodic operator tasks

- **Weekly** — review `pnpm audit` Dependabot PRs; merge or document a
  defensible defer.
- **Monthly** — backup-restore drill: restore the most recent `pg_dump` into a
  staging compose project and verify a known account's data integrity end-to-end.
- **Quarterly** — rotate `JWT_SECRET` (annoyance: invalidates active sessions).
  **Do not rotate `SERVER_CHAIN_SECRET` casually** — it requires the
  audit-chain re-bootstrap ceremony documented in Phase 10.

## Detection signals (Phase 10+)

Once the audit chain + metrics are live, watch Grafana for:

- `audit_chain_breaks_total > 0` → **DROP EVERYTHING** and investigate. A
  break means either a bug, secret rotation without ceremony, or tampering.
- `twofa_bypass_total > 0` → bug in our 2FA enforcement → patch immediately.
- Sustained 5xx burst on auth endpoints → possible attack; check the rate
  limiter config and the source IPs.

## Phase 03 — 2FA + sessions invariants (load-bearing)

These invariants were established by Phase 03 (`.planning/phases/03-2fa-sessions/`)
and the auditor at every subsequent gate will check them. Don't weaken
without a fresh threat-model pass.

### TOTP secret is browser-only

The plaintext 20-byte TOTP secret NEVER reaches the API. The browser
generates it (`sodium.randombytes_buf(20)` in
`apps/web/src/app/(authed)/settings/security/enroll-totp-flow.tsx`),
wraps it under `master_DEK` with AAD `encodeAad(argon2Params,
"sv:user-totp:v1|" || SHA256(lower(email)))`, and POSTs the wrapped blob
to `/2fa/totp/finish-register`. The server stores it as opaque bytes
(`totp_credentials.wrapped_secret bytea`).

**Server-side verification** (run before every Phase-03+ release):

```bash
grep -rE "master_dek|master_kek|masterDek|masterKek|computeTotpStep|verifyTotpCandidate" \
  apps/api/src/twofa/totp/
```

Expected: zero hits except the load-bearing comment in `totp.service.ts`
documenting the invariant. Any new hit → server has started decrypting
or computing TOTP — STOP and fix.

The same invariant applies to verification:
`POST /2fa/totp/verify` accepts `{credentialId, candidateStep}` where
`candidateStep` is the RFC 6238 step the client locally computed; the
server CAS-locks `last_used_step < candidateStep` to prevent replay but
performs no cryptographic verification of the secret. The security
relies on the client decryption + comparison: an attacker without
`master_DEK` cannot produce a `candidateStep` that matches the user's
authenticator app.

### AAD scheme extension

Phase 02 established the AAD pattern:

```
AAD = encodeAad(argon2Params, label || SHA256(lower(email)))
```

with `label ∈ { "sv:user-master:v1|", "sv:user-recovery:v1|",
"sv:user-sign-sk:v1|", "sv:user-kx-sk:v1|" }`.

Phase 03 extends with `"sv:user-totp:v1|"` (Plan 03-10). Phase 04+
labels follow the same `sv:<scope>:v1|` convention. Bumping `:v1` is a
load-bearing event — every blob wrapped under the old version stays
encrypted with the old AAD; you'd need a re-wrap migration to upgrade.

### Session-epoch column + Redis cache + bust semantics

Phase 03 Plan 04 added `users.session_epoch INT NOT NULL DEFAULT 0`.
Every access JWT carries `epoch: <int>`; `JwtAuthGuard` 401s with
`AUTH_SESSION_REVOKED` if the JWT's epoch differs from the user's
current value. The current value is Redis-cached with TTL
`SESSION_EPOCH_CACHE_TTL` (default 60s) under the key
`session-epoch:<user-id>`.

Bumps happen on:
- `POST /sessions/revoke-all` (the user revokes everything from the
  /settings/sessions page).
- Operator manual intervention (see RUNBOOK.md "Lost 2FA" + "Session
  revocation").

**Critical invariant**: every bump MUST be paired with a Redis DEL of
the cache key (`SessionService.bumpEpoch` does this; the runbook's SQL
procedures explicitly DEL via `redis-cli`). Skipping the DEL means the
worst-case revocation latency stretches to the full TTL.

### WebAuthn RP ID is load-bearing

`WEBAUTHN_RP_ID = pass.runadev.com` (apex) is bound into every passkey
at registration. Changing it is a credential-bricking event — see
RUNBOOK.md "WebAuthn RP-ID change" for the procedure. Decided in INDEX
operator-decision §1; do not silently change.

### `@Public()` route enumeration

Phase 03 Plan 09 promoted `JwtAuthGuard` to a global APP_GUARD running
BEFORE `SimpleVaultThrottlerGuard`. Routes that must be reachable
without an access JWT carry `@Public()` from
`apps/api/src/auth/jwt/public.decorator.ts`. The complete allow-list
(every route NOT on this list MUST require an access JWT):

- `GET /health`
- `POST /invite/redeem`
- `POST /auth/signup`
- `GET /auth/params`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /2fa/webauthn/begin-auth` (step-up token via Require2FAStepUpGuard)
- `POST /2fa/webauthn/finish-auth` (step-up token)
- `POST /2fa/totp/verify` (step-up token)
- `GET /2fa/step-up-material` (step-up token, Plan 03-10)

Adding a new public route in any subsequent phase: justify in the plan
SUMMARY + add to this list.

### 2FA-required guard hand-off seam to Phase 07

`apps/api/src/twofa/methods/methods.service.ts` exposes a mutable
`sharedVaultDependencyCheck` field defaulted to a `() => false` stub.
Phase 03's removal-guard surfaces a 409 `AUTH_2FA_REMOVAL_BLOCKED` when
removing the last 2FA method AND the stub returns true. Phase 07 flips
the stub to `(userId) => vault_members.exists(...)`. Until then the 409
path is exercised only by integration tests via direct stub mutation.

### Audit-action enum extensions (FROZEN for Phase 10)

Phase 03 added the following actions to `AuditAction` (`apps/api/src/common/audit-events.ts`):

- `auth.login.step_up_issued` (Plan 03-08)
- `auth.2fa.webauthn.register.{ok,fail}` (Plan 03-02)
- `auth.2fa.webauthn.auth.{ok,fail}` (Plan 03-02)
- `auth.2fa.totp.register.{ok,fail}` (Plan 03-03)
- `auth.2fa.totp.verify.{ok,fail}` (Plan 03-03)
- `auth.2fa.method.removed` (Plan 03-06)
- `auth.session.revoked` (Plan 03-05)
- `auth.session.revoked_all` (Plan 03-05)

The audit-event schema version stays at `v: 1`. Phase 10's hash-chain
will index these — DO NOT rename or remove without bumping `v`.

### Findings disposition (Phase 02 → Phase 03)

Reference: `.planning/security/FINDINGS.md`.

| Finding | Phase 03 disposition |
|---|---|
| FINDING-0017 (no email length cap) | **FIXED** by Plan 03-01 (`varchar(254)` on `users.email` + `invite_codes.email`; Zod `.max(254)` on every email DTO). |
| FINDING-0021 (`/me` user-keyed throttler keyed by IP because of guard order) | **FIXED-PENDING-VERIFICATION** by Plan 03-09 (JwtAuthGuard moved to APP_GUARD before throttler). Live re-run owed to `/gsd:verify-work 3`. |
| FINDING-0022 (`login-email` Redis-key flooding) | **FIXED-PENDING-VERIFICATION** by Plan 03-09 (key derivation switched to `sha256(email).slice(0,16)` — fixed-length, PII-free). Live re-run owed to `/gsd:verify-work 3`. |
| FINDING-0011 (`/invite/redeem` echoes email) | DEFERRED to Phase 13 (Phase 03 doesn't touch invite flow; revisit when SMTP lands in Phase 07). |

All other Phase-02 OPEN findings (0012..0029 minus the four above) remain
OPEN as tracked tech debt for Phase 13's hardening pass.

---

## CODEOWNERS

`.github/CODEOWNERS` uses `@germankatz` as the sole owner. **Confirm this
matches your actual GitHub username.** If not, edit `CODEOWNERS` and re-push.
This becomes load-bearing once you enable required-reviews branch protection.
