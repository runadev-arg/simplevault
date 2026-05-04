# SimpleVault — Operator Runbook

Day-2 operations guide. Things you'll do **after** the initial deploy is
healthy. For pre-deploy bring-up, see [`DOKPLOY-DEPLOY.md`](./DOKPLOY-DEPLOY.md);
for one-time secrets + backup posture, see
[`SECURITY-NOTES.md`](./SECURITY-NOTES.md); for the CLI helpers you'll
spawn inside the container, see [`CLI.md`](./CLI.md).

---

## Table of contents

1. [Phase 03 — 2FA + sessions environment variables](#phase-03--2fa--sessions-environment-variables)
2. [Lost 2FA — user can't sign in](#lost-2fa--user-cant-sign-in)
3. [WebAuthn RP-ID change — credential-bricking event](#webauthn-rp-id-change--credential-bricking-event)
4. [Test-only routes flag — production safety check](#test-only-routes-flag--production-safety-check)
5. [Session revocation — operator-initiated](#session-revocation--operator-initiated)

---

## Phase 03 — 2FA + sessions environment variables

These environment variables MUST be set in the Dokploy panel for the
`simplevault-api` service before any user enrols 2FA. Defaults exist for
local dev, but production values are load-bearing — the WebAuthn variables
in particular are bound into every passkey at registration.

| Variable | Default (dev) | Production value | Why it matters |
|---|---|---|---|
| `WEBAUTHN_RP_ID` | `localhost` | `pass.runadev.com` (apex) | Bound into every passkey at registration. Changing it bricks every existing passkey. See [WebAuthn RP-ID change](#webauthn-rp-id-change--credential-bricking-event) below. |
| `WEBAUTHN_RP_NAME` | `SimpleVault` | `SimpleVault` | Display name shown in the OS / browser passkey UI. Cosmetic; safe to change. |
| `WEBAUTHN_ORIGIN` | `http://localhost:3000` | `https://pass.runadev.com` | EXACT match against `window.location.origin` during the ceremony. Must include the scheme + host (no trailing slash, no path). Mismatch → every passkey ceremony fails 100% silently for the user. |
| `STEP_UP_TOKEN_TTL` | `120` | `120` | Lifetime of the JWT issued by `/auth/login` when the user has 2FA enabled. Long enough to retrieve a phone + open authenticator + type 6 digits; short enough that a stolen step-up token is useless before the ceremony completes. Don't raise above ~300s without a threat-model revisit. |
| `SESSION_EPOCH_CACHE_TTL` | `60` | `60` | How long the per-user session_epoch is cached in Redis. This is the worst-case revocation latency: after a `revoke-all`, other devices' access tokens are accepted up to this many seconds before the cache miss + DB re-read forces a 401. Lower values = faster revocation but more DB load on hot users. |
| `EXPOSE_TEST_ROUTES` | unset (or `1` for tests) | **MUST remain unset** | When `1`, the API exposes `POST /vault/_2fa-guard-probe` (Plan 03-07) and the test-helpers routes (Plan 03-12) used by Cypress. PROD MUST NOT have this set. See [Test-only routes flag](#test-only-routes-flag--production-safety-check) below. |

The Phase-03 throttler ceilings (`TWOFA_REGISTER_RATE_LIMIT`,
`TWOFA_WEBAUTHN_AUTH_RATE_LIMIT`, `TWOFA_VERIFY_RATE_LIMIT`,
`SESSIONS_LIST_RATE_LIMIT`, `SESSIONS_REVOKE_RATE_LIMIT`,
`SESSIONS_REVOKE_ALL_RATE_LIMIT`, `TWOFA_METHODS_LIST_RATE_LIMIT`,
`TWOFA_METHODS_DELETE_RATE_LIMIT`) all default to safe values. Override
only if you observe legitimate users tripping a 429 in the audit log.

After updating any of these in Dokploy, **redeploy the api service** —
NestJS reads them at module-init time, not on every request.

---

## Lost 2FA — user can't sign in

**Scenario:** a user reports they've lost both their passkey (e.g.
device wiped, no iCloud Keychain backup) AND their authenticator app
(phone replaced without TOTP export). They have their master password
and secret key, but can't pass the 2FA ceremony at `/login/2fa`.

**Important:** the recovery phrase **does NOT** bypass 2FA — by design.
Phase 11's recovery flow restores `master_DEK` (so the user can read
their data), but it does not give the user a way around the second
factor. This is load-bearing for the threat model: an attacker who
phishes the recovery phrase otherwise gets full access.

**Procedure:**

1. **Verify identity out of band.** Pick a channel the attacker can't
   reach: in-person, video call where you see the user's face, Signal
   account you've previously confirmed, voice call to a phone number
   you trust. **Do not accept email** as the verification channel — if
   the user's email is compromised, the attacker controls the channel.

2. **Open Dokploy → simplevault-api → Terminal**, exec into the
   container, then list the user's enrolled 2FA methods to confirm
   which factor(s) they say they lost:
   ```bash
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "SELECT u.email, w.name, w.created_at FROM webauthn_credentials w JOIN users u ON u.id = w.user_id WHERE u.email = $$<email>$$;"
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "SELECT u.email, t.name, t.created_at FROM totp_credentials t JOIN users u ON u.id = t.user_id WHERE u.email = $$<email>$$;"
   ```
   Cross-check against what the user reports.

3. **Manually delete the lost 2FA rows** (the user keeps any factor
   they still have — e.g. if they have a passkey and lost only TOTP,
   delete only the TOTP row). The 2FA-removal API path normally
   requires the user's own access token; the operator skips that gate
   via direct SQL:
   ```bash
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "DELETE FROM totp_credentials WHERE user_id = (SELECT id FROM users WHERE email = $$<email>$$);"
   ```
   Repeat for `webauthn_credentials` if applicable.

4. **Bump the user's session_epoch** (Plan 04 invariant — invalidates
   any stale step-up or refresh tokens minted before the operator
   intervened):
   ```bash
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "UPDATE users SET session_epoch = session_epoch + 1 WHERE email = $$<email>$$;"
   ```

5. **Tell the user to sign in again.** If they removed their LAST 2FA
   factor, the `/auth/login` 2FA branch will no longer fire — they're
   back to 1FA. **Tell them to re-enrol a fresh factor immediately**
   from `/settings/security` (preferably a passkey on a device they
   still own).

6. **Audit-log this intervention.** Phase 10 will ship a structured
   audit-row for operator actions; until then, write a one-line note in
   `.planning/security/INCIDENT-LOG.md` (create if missing) with: date,
   user email, reason, factors removed, your name. The auditor at the
   next phase gate will read this.

**If the user has lost EVERYTHING** (master password + secret key + 2FA
+ recovery phrase): there is no recovery path. Their data is
cryptographically inaccessible. Issue a fresh invite (`pnpm cli invite
create --email <addr>`); the user signs up a new account; their old
data stays encrypted forever. Document this in
`SECURITY-NOTES.md` as an accepted operational failure mode.

---

## WebAuthn RP-ID change — credential-bricking event

The RP ID is bound into every passkey at registration. Changing it = every
existing passkey on every user's device becomes unusable for SimpleVault,
because the browser refuses to surface a credential whose RP-ID doesn't
match the active RP.

**When this happens:** you migrate the prod hostname (`pass.runadev.com`
→ something else), or you enable `www.` (a subdomain change is an RP-ID
change unless you explicitly use the apex), or you accidentally set
`WEBAUTHN_RP_ID` to a different value in Dokploy.

**Before changing — operator checklist:**

1. **Notify all users** ≥ 7 days in advance via your usual out-of-band
   channel. After the cutover they will need to:
   - Sign in with master password + secret key (1FA still works).
   - Be force-prompted to re-enrol a passkey (the 2FA-required guard
     still fires because `totp_credentials` still has rows; users with
     only WebAuthn need to enrol TOTP first or get an operator unlock).
2. **Pre-stage a TOTP-only fallback path** for users who don't have a
   spare authenticator app handy.
3. **Schedule a maintenance window.** During the cutover, EVERY passkey
   ceremony will fail until the user re-enrols.

**Cutover procedure:**

1. Update `WEBAUTHN_RP_ID` (and `WEBAUTHN_ORIGIN` if the host changed)
   in Dokploy.
2. Bulk-delete every row from `webauthn_credentials`:
   ```bash
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "DELETE FROM webauthn_credentials;"
   ```
   (Leaving stale rows means users see ghost passkeys in
   `/settings/security` that can't ever authenticate.)
3. Bulk-bump every user's `session_epoch` so any in-flight access /
   step-up tokens are invalidated:
   ```bash
   docker exec -it <api-container> psql "$DATABASE_URL" -c \
     "UPDATE users SET session_epoch = session_epoch + 1;"
   ```
4. Redeploy the api service.
5. Send a follow-up notice telling users to re-enrol their passkey from
   `/settings/security`.

**If you change the RP ID accidentally:** revert the env var, redeploy,
and apologise — passkeys WERE bound to the old value, so reverting
restores them. Do NOT bulk-delete `webauthn_credentials` until you've
confirmed the env-var change is intentional.

---

## Test-only routes flag — production safety check

`EXPOSE_TEST_ROUTES=1` enables two surfaces used only by the
integration / Cypress test suites:

- `POST /vault/_2fa-guard-probe` (Plan 03-07): exercises
  `Require2FAGuard` without needing the real Phase-07 vault module.
- The `test-helpers` controller (Plan 03-12): provides the
  `cy.task`-style endpoints the Cypress 2FA + sessions specs use to
  flip the shared-vault-dependency stub, mutate counters, etc.

Both controllers are **omitted** from `AppModule.imports` when
`EXPOSE_TEST_ROUTES` is unset. **Production MUST leave it unset** —
otherwise an attacker can call the test-helpers routes to bypass
guards.

**Verification commands** to run before EVERY production deploy:

```bash
# 1. The Dockerfile must NOT bake EXPOSE_TEST_ROUTES into the image:
grep -n "EXPOSE_TEST_ROUTES" apps/api/Dockerfile docker-compose.yml docker-compose.prod.yml
# Expected: zero matches (the variable is only set by CI and local dev compose).

# 2. The Dokploy env-var panel for simplevault-api must NOT have an
#    EXPOSE_TEST_ROUTES entry. If you see one, REMOVE it and redeploy.

# 3. The running production container must not have it set:
docker exec <api-container> env | grep EXPOSE_TEST_ROUTES
# Expected: no output.
```

If any of those checks return a hit in production, treat it as a
P0 incident — the gated routes are reachable.

---

## Session revocation — operator-initiated

Users can revoke their own sessions via `/settings/sessions`. The
operator may need to force-revoke when:

- A user reports a suspicious device in their session list and asks
  for help.
- An employee leaves and the operator wants to forcibly sign them out
  everywhere.
- An incident response requires invalidating every session of a
  particular user.

**Procedure** (single user, all sessions):

```bash
docker exec -it <api-container> psql "$DATABASE_URL" -c \
  "UPDATE user_sessions SET revoked_at = now() WHERE user_id = (SELECT id FROM users WHERE email = $$<email>$$) AND revoked_at IS NULL;"

docker exec -it <api-container> psql "$DATABASE_URL" -c \
  "UPDATE users SET session_epoch = session_epoch + 1 WHERE email = $$<email>$$;"

# Bust the Redis cache so the next request observes the new epoch immediately:
docker exec -it <api-container> redis-cli -u "$REDIS_URL" DEL "session-epoch:<user-id>"
```

The user's next request from any device is rejected with `401
AUTH_SESSION_REVOKED` within ≤ `SESSION_EPOCH_CACHE_TTL` seconds (or
immediately if you ran the `redis-cli DEL`).

For ALL users in an incident:

```bash
docker exec -it <api-container> psql "$DATABASE_URL" -c \
  "UPDATE user_sessions SET revoked_at = now() WHERE revoked_at IS NULL;"

docker exec -it <api-container> psql "$DATABASE_URL" -c \
  "UPDATE users SET session_epoch = session_epoch + 1;"

docker exec -it <api-container> redis-cli -u "$REDIS_URL" --scan --pattern 'session-epoch:*' | \
  xargs -r -n 100 docker exec -i <api-container> redis-cli -u "$REDIS_URL" DEL
```

Communicate the action out-of-band — users will be bounced to /login on
their next request and may not understand why.
