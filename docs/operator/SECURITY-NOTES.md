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

## CODEOWNERS

`.github/CODEOWNERS` uses `@germankatz` as the sole owner. **Confirm this
matches your actual GitHub username.** If not, edit `CODEOWNERS` and re-push.
This becomes load-bearing once you enable required-reviews branch protection.
