# SimpleVault — Roadmap

> **Mode:** YOLO · **Depth:** Comprehensive · **Parallelization:** enabled · **v1 ship target:** when all 12 auditors sign off and pentester-redteam fails to break in.
>
> Each phase has a **security gate**: relevant auditor agents (per `.planning/security/AGENTS.md`) must produce a PASS verdict in `AUDIT-LOG.md` with no Critical/High findings open in `FINDINGS.md`. Goal-backward: a phase is "done" when the goal is verifiably TRUE, not when tasks are checked off.

---

## Milestone overview

| # | Milestone | Phases | Gate-blocking auditors |
|---|---|---|---|
| M0 | Foundations | 01 | infra-deployment, dependency-supply-chain |
| M1 | Auth + Crypto core | 02, 03 | crypto, auth-flow, owasp-top10, input-validation, rate-limit-dos |
| M2 | Personal vault | 04, 05, 06 | crypto (page-lock), input-validation, frontend-security (TipTap), owasp-top10 |
| M3 | Shared vaults | 07, 08, 09 | crypto, access-control, auth-flow, owasp-top10, rate-limit-dos |
| M4 | Audit log integrity | 10 | audit-log-integrity, access-control |
| M5 | Recovery + export | 11 | crypto, auth-flow, owasp-top10 |
| M6 | Web hardening | 12 | owasp-top10, frontend-security, infra-deployment, rate-limit-dos |
| M7 | **Security Hardening (gate)** | 13 | **ALL 12 auditors in parallel + threat-modeler refresh + pentester-redteam** |
| M8 | Production deploy | 14 | infra-deployment, pentester-redteam (re-run post-deploy smoke) |

`threat-modeler` runs at the start of EVERY milestone, updating `THREAT-MODEL.md` with new attack trees for the flows being introduced.

---

## Phase 01 — Monorepo Foundations + Docker skeleton

**Goal (must be TRUE):** Operator can clone the repo, run `pnpm install && docker compose up -d`, and reach `https://localhost` with a placeholder Next.js page served through Caddy + auto-self-signed cert. CI passes lint + typecheck + dep-audit on every push.

**Deliverables:**
- Turborepo + pnpm workspaces
- `apps/web` (Next.js 15 placeholder), `apps/api` (NestJS health-only)
- `packages/crypto` skeleton (no impl yet, just exports map)
- `packages/db` (Drizzle setup + first migration: `users` table stub)
- `packages/shared` (Zod schemas, error codes)
- `packages/eslint-config`, `packages/tsconfig`
- Hardened `docker-compose.yml`: web, api, postgres, redis, caddy. `internal: true` backend network. Non-root containers, read-only FS, `cap_drop: ALL`, healthchecks, resource limits.
- `Caddyfile` with strict CSP/HSTS/security headers placeholder
- GitHub Actions: lint, typecheck, build, `pnpm audit`, container scan
- `docs/operator/SETUP.md` skeleton

**Security gate:**
- `infra-deployment-auditor` PASS (Docker hardening, network segmentation, secret handling, headers baseline)
- `dependency-supply-chain-auditor` PASS (initial dep tree audit)
- `threat-modeler` runs Milestone 0 baseline: full STRIDE skeleton + AT-1..AT-5 attack-tree drafts

**Done when:** `docker compose up -d` succeeds on a clean Ubuntu 22.04 VM, healthchecks green, CI green, both auditors signed off in `AUDIT-LOG.md`.

---

## Phase 02 — Auth + Crypto core (signup, login, two-secret model)

**Goal:** A user can redeem an operator-issued invite code, generate a master password + secret_key + 24-word recovery phrase client-side, sign up, log in from a fresh browser using all three secrets, and log out — with timing-uniform error handling and short-lived JWT + rotating refresh tokens.

**Deliverables:**
- `packages/crypto`: full impl (libsodium-wrappers-sumo, Argon2id with calibration, XChaCha20-Poly1305, X25519 sealed-box, BIP-39, key hierarchy per REQ-CRYPTO-003..006)
- API: `POST /invite/redeem`, `POST /auth/signup`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /me`
- Web: `/signup` flow with secret_key + recovery phrase generation + transcription confirmation gates; `/login`; auto-refresh hook
- Operator CLI: `pnpm cli invite create --email <addr>`
- DB migrations: `users`, `user_sessions`, `invite_codes`
- Refresh token reuse → revoke session family + emit alert
- Timing-floor pattern on login (dummy Argon2id on miss)
- Pino redaction list active

**Security gate:**
- `crypto-auditor` PASS (key hierarchy, Argon2 params, AAD binding, two-secret invariants, BIP-39 derivation, constant-time comparisons)
- `auth-flow-auditor` PASS (signup/login/logout, account enumeration, timing, refresh rotation, family revocation)
- `owasp-top10-auditor` PASS (A01 broken access control, A02 crypto failures, A07 auth failures focus)
- `input-validation-auditor` PASS (Zod on every DTO, no SQL injection)
- `rate-limit-dos-auditor` PASS (login + signup + refresh limits per REQ-RATELIMIT-002..003)
- `threat-modeler` updates Login flow STRIDE + AT-5

**Done when:** `cypress` happy + sad path E2E passes; auditors signed off; recovery-code rotation NOT yet implemented (deferred to phase 11).

---

## Phase 03 — 2FA (WebAuthn + TOTP) + session management UI

**Goal:** A user can enroll a passkey AND a TOTP credential, log in with master+secret_key+2FA, see their active sessions, and remotely log out a session.

**Deliverables:**
- API: `POST /2fa/webauthn/begin-register`, `/finish-register`, `/begin-auth`, `/finish-auth`; `POST /2fa/totp/begin-register`, `/finish-register`, `/verify`; `GET /2fa/methods`; `DELETE /2fa/methods/:id`; `GET /sessions`, `DELETE /sessions/:id`, `POST /sessions/revoke-all`
- Web: `/settings/security` (2FA enroll/list), `/settings/sessions`
- DB: `webauthn_credentials`, `totp_credentials` (encrypted secret w/ master_DEK)
- Last-step replay guard for TOTP
- API guard: vault create/join requires ≥1 active 2FA

**Security gate:**
- `auth-flow-auditor` PASS (2FA enrollment, replay, fallback paths, removal-while-shared-vault enforcement)
- `crypto-auditor` PASS (TOTP secret encryption, WebAuthn challenge nonces)
- `owasp-top10-auditor` PASS
- `access-control-auditor` PASS (only owner can manage own 2FA, only own sessions visible)

**Done when:** All flows work, removing last 2FA while user is in shared vault is blocked, auditors signed off.

---

## Phase 04 — Personal vault: credentials

**Goal:** A logged-in user can create, edit, view, and delete credentials in their personal vault. All payload data is encrypted client-side; server only sees ciphertext + minimal metadata. Password generator + strength meter + reuse detection work.

**Deliverables:**
- API: `GET /vault/personal`, `POST /credentials`, `GET /credentials/:id`, `PATCH /credentials/:id`, `DELETE /credentials/:id`
- Web: `/vault` list view (mobile-first, Aceternity card layout), `/credential/new`, `/credential/[id]`
- Client-side: encrypt/decrypt with `master_DEK`, reuse detection via local Set
- Password generator UI (length, charset, passphrase EFF-large)
- `zxcvbn-ts` strength meter
- DB: `credentials` table (ciphertext blob + metadata)
- Auto-lock after 15 min idle wipes in-memory keys

**Security gate:**
- `crypto-auditor` PASS (DEK derivation, AAD includes vault_id+credential_id+version)
- `input-validation-auditor` PASS
- `owasp-top10-auditor` PASS
- `access-control-auditor` PASS (no IDOR — credential reads bound to owning user)

---

## Phase 05 — Personal vault: rich-text pages (TipTap)

**Goal:** A user can create rich-text pages (Notion-like, no images/tables in v1) with the strict TipTap schema, see version history, and search by title.

**Deliverables:**
- TipTap setup (paragraph, h1-h3, lists, blockquote, code-block, code-inline, marks, link with sanitized href)
- API: `GET /pages`, `POST /pages`, `GET /pages/:id`, `PATCH /pages/:id`, `DELETE /pages/:id`, `GET /pages/:id/history`
- Web: `/page/new`, `/page/[id]` with TipTap editor; version-history side panel
- Title HMAC-prefix index for server-side title search
- Render via React reconciliation, never `dangerouslySetInnerHTML`
- Defensive `sanitize-html` pass at render in case TipTap schema is bypassed

**Security gate:**
- `frontend-security-auditor` PASS — **CRITICAL**: TipTap schema strictness, link sanitization, no XSS via mark attributes, no DOM clobbering, version history rendering safety
- `input-validation-auditor` PASS (server-side schema check on submitted TipTap JSON)
- `owasp-top10-auditor` PASS (A03 injection focus)
- `access-control-auditor` PASS

---

## Phase 06 — Page double-lock

**Goal:** A user can mark any page as "double-locked" with an additional page-password. Opening a double-locked page requires entering both master+secret_key (login) AND the page-password. Resetting the page-password is auditable and revokes the double-lock.

**Deliverables:**
- Client crypto: page-DEK random, wrapped by both `page_KEK` and `master_KEK`
- API: `POST /pages/:id/lock`, `POST /pages/:id/unlock-attempt`, `POST /pages/:id/reset-lock`
- Web: lock/unlock UI; reset confirmation dialog warns user
- DB: page metadata gains `is_locked`, `page_kek_wrap`, `master_kek_wrap`
- Audit entry on lock/unlock-failure/reset

**Security gate:**
- `crypto-auditor` PASS (double-wrap correctness, AAD binding, unlock failure handling)
- `auth-flow-auditor` PASS (page-password attempts rate-limited)
- `owasp-top10-auditor` PASS
- `access-control-auditor` PASS

---

## Phase 07 — Shared vaults: create, invite, key wrapping

**Goal:** A user with 2FA enabled can create a shared vault, invite another user by email, the invited user can accept (after the owner's OOB approval), and from then on both users can read/write items in that vault using their own credentials. Server never sees plaintext vault_DEK.

**Deliverables:**
- API: `POST /shared-vaults`, `GET /shared-vaults`, `POST /shared-vaults/:id/invites`, `POST /invites/:token/accept`, `POST /shared-vaults/:id/invites/:invite_id/approve`, `GET /shared-vaults/:id/members`
- Web: `/shared-vault/new`, `/shared-vault/[id]` (with member list), `/invite/[token]` (accept flow), `/inbox` (pending join requests for owners to approve)
- HMAC-signed invite token, single-use, 24h, bound to email+vault_id
- Email sending via SMTP (operator-config required)
- Per-user `user_pub_key` published at signup; X25519 sealed-box wrapping client-side
- 2FA-required guard on vault create + invite
- DB: `shared_vaults`, `vault_members` (with `wrapped_vault_dek`), `vault_invites`

**Security gate:**
- `crypto-auditor` PASS (sealed-box correctness, no DEK leak through metadata, key publication integrity)
- `access-control-auditor` PASS — **CRITICAL**: IDOR on vault reads, only owner can invite/approve, only invitee can accept their own token, expired-token rejection
- `auth-flow-auditor` PASS (invite token validation, OOB approval flow, email-binding check)
- `rate-limit-dos-auditor` PASS (invite generation cap per REQ-RATELIMIT-005)
- `input-validation-auditor` PASS
- `owasp-top10-auditor` PASS

---

## Phase 08 — Shared vaults: member mgmt + revocation + DEK rotation

**Goal:** Owner can remove a member; on removal the vault_DEK is rotated and re-wrapped to remaining members; removed member loses server-side access immediately.

**Deliverables:**
- API: `DELETE /shared-vaults/:id/members/:user_id`, `POST /shared-vaults/:id/rotate-key`
- Web: member-management UI in `/shared-vault/[id]/members`
- Client-side: owner generates new vault_DEK, re-encrypts blobs (lazy on next-write OR eager mode toggle), re-wraps to remaining members
- Audit entries on member remove + key rotation
- Caps enforced (max 20 members per vault, max 10 vaults per user)

**Security gate:**
- `access-control-auditor` PASS — only owner can remove; removed member's API requests rejected immediately even with a still-valid JWT
- `crypto-auditor` PASS (rotation atomicity, no DEK reuse after rotation, no leak via lazy re-encrypt)
- `owasp-top10-auditor` PASS

---

## Phase 09 — Unanimous deletion + timeout override

**Goal:** Any member can propose deletion; all members must approve within 30 days; rejection kills the vote; non-response triggers 7-day notice + owner override; all events audit-logged.

**Deliverables:**
- API: `POST /shared-vaults/:id/delete-vote`, `POST /shared-vaults/:id/delete-vote/respond`, `POST /shared-vaults/:id/delete-vote/override` (owner only), `GET /shared-vaults/:id/delete-vote`
- Web: deletion proposal UI, voting UI per member, override UI for owner with full disclosure
- Cron: daily job sends escalation notifications at deadline-7d and processes overrides
- DB: `vault_delete_votes`, `vault_delete_vote_responses`
- Email notifications on every state change
- Re-proposal cooldown (24h after rejection)

**Security gate:**
- `access-control-auditor` PASS — **CRITICAL**: cannot vote on a vault you're not a member of, cannot vote twice, only owner can override, override rejected before deadline
- `auth-flow-auditor` PASS (vote endpoints require fresh auth + 2FA)
- `owasp-top10-auditor` PASS
- `audit-log-integrity-auditor` PASS — every vote event correctly chained

---

## Phase 10 — Audit log + hash chain + verification + signed checkpoints

**Goal:** Every state-changing action across the system is recorded in `audit_log` with HMAC-chained entries per vault. Members can read their vault's audit log; the chain is verified on every read; daily Ed25519-signed Merkle root is committed off-machine.

**Deliverables:**
- DB: `audit_log` table; Postgres role permission revoke (`UPDATE`/`DELETE` denied for app role)
- Audit emitter middleware/interceptor in every relevant module
- Per-vault chain HMAC computation on insert
- Daily cron: Merkle root over chain heads → Ed25519 sign → write to `audit-checkpoints` repo (operator-controlled)
- API: `GET /shared-vaults/:id/audit-log` (paginated)
- Web: `/shared-vault/[id]/audit` table view with chain verification status badge
- Verification on read; mismatch → red banner + operator alert (`audit_chain_breaks_total` Prometheus metric)

**Security gate:**
- `audit-log-integrity-auditor` PASS — **CRITICAL**: chain construction correct, Merkle root reproducible, signing key handling, no plaintext leakage in audit metadata, role permission verified at DB level
- `access-control-auditor` PASS (members see only their vaults' logs)
- `owasp-top10-auditor` PASS (A09 logging failures)

---

## Phase 11 — Recovery + account export + master password change

**Goal:** A user who forgot their master password (but has secret_key + recovery phrase) can recover, set a new master password, and the recovery phrase rotates. Users can export an encrypted account bundle. Users can change master password (re-wrap everything). Users can self-delete (soft 30d → hard).

**Deliverables:**
- API: `POST /recover/initiate`, `POST /recover/verify`, `POST /recover/complete`, `POST /me/change-master-password`, `POST /me/export`, `POST /me/delete`
- Web: `/recover` 3-step flow, `/settings/recovery` (re-display + rotate), `/settings/account` (export, delete)
- Client-side: recovery flow re-wraps everything, generates + shows new BIP-39 phrase
- Encrypted account export (single JSON file, master_KEK encryption)
- Soft-delete with 30-day grace; hard-delete cron

**Security gate:**
- `crypto-auditor` PASS (recovery preserves two-secret invariant, no master_DEK exposure during re-wrap, phrase rotation correctness)
- `auth-flow-auditor` PASS (recovery rate-limited per REQ-RATELIMIT-004, no enumeration on initiate)
- `access-control-auditor` PASS (export and delete are self-only)
- `owasp-top10-auditor` PASS

---

## Phase 12 — Web hardening: CSP, headers, CSRF, clipboard, all rate limits

**Goal:** Every endpoint has correct rate limit. CSP/HSTS/cookie/CSRF/headers shipped to spec. Clipboard auto-clear works. Sensitive data never persisted in browser storage. Auto-lock works.

**Deliverables:**
- Caddyfile final security headers
- Next.js middleware emitting per-request CSP nonce
- NestJS CSRF guard with `__Host-csrf` cookie + `X-CSRF-Token` header
- Throttler tiers per REQ-RATELIMIT-001..006
- Clipboard auto-clear hook
- Auto-lock idle timer + memory wipe on lock
- `Permissions-Policy`, `X-Frame-Options`, `Referrer-Policy` finalized

**Security gate:**
- `owasp-top10-auditor` PASS — full pass; A05 misconfig + A03 injection + A04 insecure design focus
- `frontend-security-auditor` PASS — CSP enforcement verified, clipboard, storage scan
- `infra-deployment-auditor` PASS — header verification, TLS config
- `rate-limit-dos-auditor` PASS — every endpoint mapped, ReDoS scan on regex, billion-laughs scan on JSON parsing

---

## Phase 13 — **MILESTONE GATE: Security Hardening (all 12 auditors in parallel + pentester-redteam)**

**Goal:** All 12 auditors run a final pass against the entire codebase. `threat-modeler` produces a final `THREAT-MODEL.md`. `pentester-redteam` actively attempts to break in (auth bypass, privilege escalation, IDOR, audit-log tampering, abuse of unanimous-delete vote system, supply-chain abuse) and fails. ALL Critical/High findings are VERIFIED-CLOSED.

**Deliverables:**
- `/gsd:audit-milestone security-hardening` orchestration
- `.planning/security/HARDENING-REPORT-2026-XX-XX.md` aggregating every auditor's verdict
- `pentester-redteam` final report (with CVSS-scored attack chains attempted)
- All Critical/High findings remediated and verified
- `THREAT-MODEL.md` finalized with all attack trees, mitigations, accepted risks documented

**Gate (blocks Phase 14):** Zero open Critical/High findings. Pentester gives explicit "could not break in within scope" verdict. Operator signs off.

---

## Phase 14 — Production deploy

**Goal:** SimpleVault is reachable at `https://vault.<your-domain>`, accepts operator's first invite-redeemed signup, runs nightly backups, restore-from-backup tested, monitoring alerts active.

**Deliverables:**
- VPS provisioned + hardened per REQ-INFRA-008 (CIS 22.04 alignment)
- DNS A/AAAA record + TLS via Let's Encrypt verified
- `docker compose up -d` on prod
- Restic sidecar configured + first backup run + first restore drill into staging compose project
- Prometheus + Grafana stack live, alerts configured (req/s, p99, 5xx, login failures, audit chain breaks, 2FA bypass)
- Operator runbook (`docs/operator/RUNBOOK.md`) covering: deploy, upgrade, backup, restore, key rotation, incident response

**Security gate:**
- `infra-deployment-auditor` PASS — final live audit (TLS, headers in prod, container hardening, secrets in env not git, fail2ban active, ufw enabled)
- `pentester-redteam` PASS — re-run against live URL: smoke pen test, no Critical/High found

**Done when:** Operator signs off in `STATE.md` that v1 is shipped. STATE.md updated with deployed-version SHA.

---

## What this roadmap deliberately does NOT include

- "Build feature, then secure later" — every phase has its security gate inline. No separate "QA phase" at the end (Phase 13 is the *consolidated re-pass*, not the first pass).
- Time estimates. Phases progress when their goals are TRUE, not when calendar time has elapsed.
- v2 features (see REQUIREMENTS.md "v2 deferred" section).
