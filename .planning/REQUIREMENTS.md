# SimpleVault — Requirements (v1)

> **Scope:** v1 = "I can self-host this for myself and ~50 friends/family, store credentials and rich-text pages with E2E encryption, share vaults with per-user key wrapping, and have every security auditor sign off before I deploy."
>
> Out-of-scope items are explicit (`v2` or `WONTFIX`) so the boundary is auditable.

---

## REQ-CRYPTO — Cryptographic core

| ID | Requirement | Source |
|---|---|---|
| **REQ-CRYPTO-001** | All credential and page payloads are encrypted client-side with **XChaCha20-Poly1305** (192-bit random nonce, AAD includes KDF params + record metadata). Backend stores ciphertext blobs only. | Crypto research §4 |
| **REQ-CRYPTO-002** | Master password is stretched with **Argon2id** (`m=64 MiB, t=3, p=1` baseline; per-user calibration to ~750 ms target on signup, persisted in user record and bound into AAD to prevent downgrade). | Crypto research §2 + OWASP PSCS |
| **REQ-CRYPTO-003** | **Two-secret model (1Password-style):** signup generates a random 128-bit `secret_key` shown to the user once and required (alongside master password) for every login. `master_KEK = Argon2id(master_password, secret_key ⊕ salt)`. Server only stores `Argon2id(secret_key, server_salt)` for verification — never the secret_key itself. **CHANGE FROM PROJECT.md initial draft** — this is a stronger choice than single-secret; flag for review. | Crypto research §3 |
| **REQ-CRYPTO-004** | Key hierarchy: `master_KEK → master_DEK → user_KEK` (per-user, used as the wrapping key for shared vault DEKs). `vault_DEK` is randomly generated per shared vault and wrapped to each member with X25519 sealed-box. | Crypto research §3 |
| **REQ-CRYPTO-005** | Page double-lock: page-DEK is randomly generated per locked page, wrapped by **both** `page_KEK = Argon2id(page_password, page_salt)` AND `master_KEK`. Both wrapping records persisted; either unwraps. Reset of forgotten page-password is auditable and revokes the double-lock. | PROJECT.md decision |
| **REQ-CRYPTO-006** | Recovery: BIP-39 24-word phrase generated client-side at signup, derives a `recovery_KEK` that wraps `master_DEK`. Recovery still requires `secret_key` (preserves two-secret invariant). Phrase shown once; user must transcribe and confirm before signup completes. Server stores only `HMAC(server_secret, sha256(phrase))` for lookup, not the phrase or its plain hash. | Crypto research §8 + PROJECT.md |
| **REQ-CRYPTO-007** | All security-sensitive comparisons (HMAC tags, recovery hash lookup, TOTP codes, CSRF tokens, session token validation) use `crypto.timingSafeEqual` (Node) / `sodium.memcmp` (browser). | Crypto research §9 |
| **REQ-CRYPTO-008** | Browser crypto via `libsodium-wrappers-sumo` (lazy-loaded WASM, ~250 KB gz only when needed). No raw WebCrypto usage for AEAD or KDF. | Crypto research §1 |

---

## REQ-AUTH — Authentication & session management

| ID | Requirement | Source |
|---|---|---|
| **REQ-AUTH-001** | Signup is **invite-only**. Operator issues invite codes (HMAC-signed, single-use, 7-day TTL). No public registration. | PROJECT.md scope |
| **REQ-AUTH-002** | Signup flow: invite code → email + master password → secret_key generated client-side and shown → recovery phrase generated client-side and shown → user must confirm both transcribed → account created. | PROJECT.md + Crypto research |
| **REQ-AUTH-003** | Login: identical response and timing for "user not found" / "wrong password" / "wrong secret_key". Dummy Argon2id run on miss to floor timing. | Pitfalls research §8-9 |
| **REQ-AUTH-004** | Logout: revokes refresh token in DB + bumps session epoch (forces all access tokens for that user to fail validation server-side). | Pitfalls research §17 |
| **REQ-AUTH-005** | Session model: short-lived access JWT (15 min, HS256 signed with rotated server key) + refresh token (httpOnly+Secure+SameSite=Strict cookie, 30-day TTL, single-use rotation). Refresh token reuse → revoke entire session family + alert user. | Architecture research §7 + Pitfalls §5 |
| **REQ-AUTH-006** | Master password change re-derives `master_KEK`, re-wraps `master_DEK` and all per-user-wrapped vault keys. Old refresh tokens revoked. | Standard practice |
| **REQ-AUTH-007** | Recovery flow: user enters email + secret_key + 24-word phrase → server validates phrase hash → server emits "reset window" token (15 min) → user sets new master password → re-derive everything. Recovery phrase is **rotated** on use (new 24 words generated and shown). | Pitfalls research §18 |

---

## REQ-2FA — Two-factor authentication

| ID | Requirement | Source |
|---|---|---|
| **REQ-2FA-001** | Support **WebAuthn** (passkeys + cross-platform authenticators) via `@simplewebauthn/*` v10+. RP ID pinned to apex domain. `userVerification: required`. | Crypto research §6 |
| **REQ-2FA-002** | Support **TOTP** via `otplib` (RFC 6238, SHA-1, 6 digits, 30-sec step, ±1 step drift tolerance). Server tracks last-used step per credential to prevent replay. | Crypto research §7 |
| **REQ-2FA-003** | 2FA is **optional** for personal vault use; **MANDATORY** before a user can create or join a shared vault. Enforcement at API layer (guard), not just UI. | PROJECT.md decision |
| **REQ-2FA-004** | 2FA enrollment, list, remove, regenerate-recovery-codes pages in user settings. Removing the LAST 2FA method while user is in any shared vault is rejected. | Derived |
| **REQ-2FA-005** | 2FA challenge issued **only after** successful first-factor auth (prevents 2FA-state enumeration). | Pitfalls research §8 |

---

## REQ-VAULT — Personal vault

| ID | Requirement | Source |
|---|---|---|
| **REQ-VAULT-001** | Every user has exactly one **personal vault** auto-created on signup. Items: credentials and pages. | PROJECT.md |
| **REQ-VAULT-002** | Credential record fields (all encrypted as one blob): `name`, `url[]`, `username`, `password`, `notes`, `custom_fields[{name,value,hidden}]`, `created_at`, `updated_at`. Server-readable metadata: `id`, `vault_id`, `version`, `updated_at`. | Features research §1 |
| **REQ-VAULT-003** | Password generator: length 8-128, char-class toggles (upper/lower/digits/symbols), passphrase mode (3-10 words from EFF large list, custom separator). Generated client-side. | Features research §1 |
| **REQ-VAULT-004** | Strength meter via `zxcvbn-ts` shown live in credential editor. | Features research §1 |
| **REQ-VAULT-005** | Reuse detection within the same vault (set of `sha256(password)` computed client-side, intersection check). | Features research §6 |
| **REQ-VAULT-006** | Per-credential **password history** (last 10 versions) — kept as an array inside the encrypted blob. | Features research §1 |
| **REQ-VAULT-007** | Page record (Notion-like rich-text): TipTap JSON document inside encrypted blob. Server-readable metadata: `id`, `vault_id`, `title_search_token` (HMAC-prefix index for title search only), `is_locked` (bool), `version`, `updated_at`. | Features research §2 + Architecture |
| **REQ-VAULT-008** | TipTap schema (v1): paragraph, heading h1-h3, bullet/ordered lists, blockquote, code-block, code-inline, bold/italic/strike/underline, link (with sanitized href, no `javascript:`/`data:`). **No images, no tables, no embeds in v1.** | Pitfalls research §10 |
| **REQ-VAULT-009** | Page version history: server keeps last 10 ciphertext versions; client diffs after decrypt. | Features research §2 |
| **REQ-VAULT-010** | Search: title-only (HMAC-prefix index server-side); body search is client-side after decrypt of currently-loaded vault. No server-side body search (server cannot read body). | Architecture |
| **REQ-VAULT-011** | Favorites flag (per-item, encrypted in blob), UI-pinned. | Features research §8 |

---

## REQ-SHARE — Shared vaults

| ID | Requirement | Source |
|---|---|---|
| **REQ-SHARE-001** | Any user with 2FA enabled can create a shared vault. Creator becomes `owner`. | PROJECT.md |
| **REQ-SHARE-002** | `vault_DEK` is generated client-side; wrapped per-member via X25519 sealed-box to each member's published `user_pub_key`. Server stores wrapped blobs but cannot unwrap any. | Crypto research §3 |
| **REQ-SHARE-003** | Invite flow: owner inputs invitee email → server generates HMAC-signed token (single-use, 24h, bound to email + vault_id) → email sent → invitee clicks link, must be logged in (or signs up first), submits "join request" → **owner must approve OOB in their UI** before invitee receives the wrapped vault_DEK. | PROJECT.md decision |
| **REQ-SHARE-004** | On approval, owner's client unwraps `vault_DEK`, re-wraps it to invitee's `user_pub_key`, posts the wrapped blob to server, server attaches to membership row. **Server never sees plaintext vault_DEK.** | Crypto research §3 |
| **REQ-SHARE-005** | Member list visible to all members. Each member sees all members' display names + role + joined-at + last-active. | Features research §7 |
| **REQ-SHARE-006** | Member removal: only owner can remove. Removal triggers **vault_DEK rotation**: owner generates new vault_DEK, re-encrypts (or marks for re-encrypt at next-write) all blobs, re-wraps to remaining members. Removed member retains any local copies (acceptable risk; documented). | Crypto research + Pitfalls |
| **REQ-SHARE-007** | Maximum members per vault: 20 (v1 cap; tunable). Maximum shared vaults per user: 10 (v1 cap). Both enforced server-side. | Operational sanity |

---

## REQ-DELETE — Unanimous deletion with override

| ID | Requirement | Source |
|---|---|---|
| **REQ-DELETE-001** | Deleting a shared vault (or any item within it) requires a **unanimous vote** of all current active members. | PROJECT.md |
| **REQ-DELETE-002** | Vote initiation: any member proposes deletion → server records `pending_deletion` with deadline `now + 30d` → all members notified (in-app + email). | PROJECT.md |
| **REQ-DELETE-003** | Each member explicitly approves or rejects. Single rejection → vote dies; can be re-proposed after 24h. | Derived |
| **REQ-DELETE-004** | Member with no response: at `deadline - 7d`, escalation notification ("you have 7 days to vote, or you will be marked inactive on this vault"). | PROJECT.md |
| **REQ-DELETE-005** | At `deadline`, owner may invoke **override**: marks non-responding members as inactive on this vault, completes deletion. Override action is logged with full context (which members were marked inactive, when they were last active, when notifications were sent). | PROJECT.md |
| **REQ-DELETE-006** | Inactive-marked members regain access if they log in within 30 days post-deletion-attempt by re-confirming membership; otherwise removed permanently. | Derived |
| **REQ-DELETE-007** | All vote events (proposed, approved, rejected, escalated, overridden, executed) are first-class entries in the audit log. | PROJECT.md |

---

## REQ-AUDIT — Audit log + tamper-evidence

| ID | Requirement | Source |
|---|---|---|
| **REQ-AUDIT-001** | Every state-changing action (signup, login success/fail, 2FA enroll/use/remove, password change, vault create/share/leave/delete-vote/delete-execute, member add/remove, item create/update/delete, recovery use) writes one `audit_log` row. | PROJECT.md |
| **REQ-AUDIT-002** | Per-vault hash chain: `chain_hash_n = HMAC-SHA256(server_chain_secret, canonical_json(entry_n) ‖ chain_hash_{n-1})`. Server stores `(seq, vault_id, prev_chain_hash, chain_hmac)` for each entry. | Crypto research §5 |
| **REQ-AUDIT-003** | Daily cron computes Merkle root of all chain heads and **signs with Ed25519** (key in operator-controlled offline file or HSM). Signed root is committed to a separate git repo by the operator (off-machine checkpoint). | Crypto research §5 + Pitfalls §16 |
| **REQ-AUDIT-004** | Audit log entries include: `seq`, `vault_id`, `actor_user_id`, `action_type` (enum), `target_id`, `payload_metadata` (server-readable, no plaintext secrets), `ip`, `user_agent_hash`, `device_id`, `created_at`. **Never** logs: passwords, recovery codes, plaintext payloads, JWT contents, secret_key. | Pitfalls research §15 |
| **REQ-AUDIT-005** | Members can read their vault's audit log. Verification (`chain_hmac` recompute) runs on every read; mismatch → bright red "TAMPERING DETECTED" UI alert + operator email. | Crypto research §5 |
| **REQ-AUDIT-006** | DB role for app has only `INSERT` on `audit_log` table; `UPDATE`/`DELETE` denied at Postgres role level. | Pitfalls research §16 |

---

## REQ-RECOVERY — Recovery & export

| ID | Requirement | Source |
|---|---|---|
| **REQ-RECOVERY-001** | Account export: client-side bundles all user vaults into single encrypted JSON, downloaded directly. Encrypted with same `master_KEK`. | Features research §5 |
| **REQ-RECOVERY-002** | Account deletion: self-serve. Soft-delete with 30-day grace, then hard delete. Audit log retained per REQ-AUDIT-001 (anonymized actor reference). | Features research §5 |
| **REQ-RECOVERY-003** | "Export then delete" workflow as a single guided flow (so user always has offline backup). | UX |

---

## REQ-RATELIMIT — Rate limiting

| ID | Requirement | Source |
|---|---|---|
| **REQ-RATELIMIT-001** | Per-IP global cap: 1000 req / 15 min. | Architecture research §8 |
| **REQ-RATELIMIT-002** | Login: 5 attempts per IP per 15 min, AND 10 attempts per email per 15 min. Lockout uses sliding window. | Architecture |
| **REQ-RATELIMIT-003** | Signup (invite redeem): 3 per IP per hour. | Architecture |
| **REQ-RATELIMIT-004** | Recovery initiate: 3 per email per hour, 5 per IP per hour. | Architecture |
| **REQ-RATELIMIT-005** | Vault invite generation: 10 per vault per day. | Architecture |
| **REQ-RATELIMIT-006** | Per-user general API: 300 req / 15 min. | Architecture |
| **REQ-RATELIMIT-007** | Backed by Redis with `@nestjs/throttler` v6 (token bucket). | Architecture |

---

## REQ-INFRA — Operator-facing operational

| ID | Requirement | Source |
|---|---|---|
| **REQ-INFRA-001** | Single `docker compose up -d` brings up: `web` (Next.js standalone), `api` (NestJS), `postgres`, `redis`, `caddy` (reverse proxy with auto Let's Encrypt). | Architecture research §9 |
| **REQ-INFRA-002** | Postgres NOT exposed on host port. Networks: `frontend` (caddy ↔ web ↔ api), `backend` (`internal: true`, api ↔ postgres ↔ redis). | Architecture + Pitfalls §13 |
| **REQ-INFRA-003** | All containers run as non-root user, read-only root FS, `cap_drop: ALL` (re-add only what's needed), no docker socket mount, healthchecks per service, resource limits set. | Pitfalls research §13 |
| **REQ-INFRA-004** | Operator-issued invite codes via CLI `pnpm cli invite create --email ...` (one binary in the `api` container). | Operational |
| **REQ-INFRA-005** | Backups: bundled `restic` sidecar runs nightly cron: `pg_dump | restic backup -` to S3-compatible target with separate `RESTIC_PASSWORD`. Weekly off-site copy. Monthly automated restore drill into a `staging` compose project. | Pitfalls research §15 |
| **REQ-INFRA-006** | Migrations: dedicated `api-migrate` one-shot init container runs Drizzle Kit on each deploy, blocks `api` start until success. Expand-then-contract migration policy (no destructive in single deploy). | Architecture research §10 |
| **REQ-INFRA-007** | Observability: pino structured JSON logs with redaction list (passwords, secret_key, recovery, JWT, `Authorization`/`Cookie` headers). Prometheus `/metrics` endpoint. Grafana dashboard with alerts: req/s, p99 latency, 5xx rate, login failure burst, audit chain mismatches (`audit_chain_breaks_total > 0`), 2FA bypass attempts (`twofa_bypass_total > 0`). | Architecture research §11 |
| **REQ-INFRA-008** | VPS hardening (operator runbook in `docs/operator/HARDENING.md`): SSH key-only, root SSH disabled, `ufw` deny-by-default, `fail2ban` for SSH, `unattended-upgrades`, non-root user owns docker. CIS Ubuntu 22.04 alignment. | Pitfalls research §14 |
| **REQ-INFRA-009** | TLS: Caddy auto-provisions Let's Encrypt; HSTS `max-age=31536000; includeSubDomains; preload`; TLS 1.2+ only; ECDHE ciphers. Certificate renewal monitored. | Pitfalls research §7 |

---

## REQ-WEBSEC — Web security headers & client hardening

| ID | Requirement | Source |
|---|---|---|
| **REQ-WEBSEC-001** | CSP: `default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`. No `unsafe-inline`, no `unsafe-eval`. Nonce per request. | Pitfalls research §7 |
| **REQ-WEBSEC-002** | Cookies: `httpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix. | Pitfalls research §6 |
| **REQ-WEBSEC-003** | CSRF: SameSite=Strict + double-submit token (`__Host-csrf` cookie + `X-CSRF-Token` header) on every state-changing endpoint. NestJS guard validates. | Pitfalls research §6 |
| **REQ-WEBSEC-004** | Other headers: `X-Frame-Options: DENY` (defense-in-depth atop CSP), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`. | Pitfalls research §7 |
| **REQ-WEBSEC-005** | TipTap output rendered through React reconciliation (never `dangerouslySetInnerHTML`); link `href` validated client-side AND server-side against `^https?://` allowlist; `target="_blank"` always paired with `rel="noopener noreferrer"`. | Pitfalls research §10 |
| **REQ-WEBSEC-006** | Clipboard ops (copy password) auto-clear after 30 sec via `setTimeout` + `navigator.clipboard.writeText("")`. | Pitfalls research §11 |
| **REQ-WEBSEC-007** | Sensitive plaintext (decrypted DEKs, decrypted blobs) live only in JS variables in client-side React state, never `localStorage`/`sessionStorage`/`IndexedDB`. Auto-lock after 15 min idle wipes the in-memory keys. | Pitfalls research §11 |

---

## REQ-DEPS — Dependencies & supply chain

| ID | Requirement | Source |
|---|---|---|
| **REQ-DEPS-001** | `pnpm-lock.yaml` committed; CI runs `pnpm install --frozen-lockfile`. | Pitfalls research §12 |
| **REQ-DEPS-002** | CI runs `pnpm audit --audit-level=high` and `pnpm dlx socket-npm` (or equivalent) on every PR; **High/Critical block merge.** | Pitfalls research §12 |
| **REQ-DEPS-003** | `pnpm.overrides` documented in PR descriptions when used. `pnpm dlx pnpm-deny-list-check` style review of new deps. | Pitfalls research §12 |
| **REQ-DEPS-004** | Weekly cron: `dependency-supply-chain-auditor` agent reviews newly-added/updated deps. | Security AGENTS.md |

---

## v2 (deferred — explicitly NOT v1)

- TOTP secrets stored as item type
- File attachments on items
- Inline images / tables in pages (TipTap supports; defer schema expansion)
- Browser extension (autofill)
- Mobile native apps
- CLI client for end users
- HIBP breach detection integration
- Email aliases / hide-my-email integration
- Passkey storage as item type
- SSH key item type
- One-time URL share (separate from full-vault sharing)
- Per-share TTL / per-share password gate
- Trusted device login
- Emergency contacts / inheritance
- SSO (SAML/OIDC) / SCIM
- LDAP integration
- Org / group / RBAC beyond `owner`/`member`
- Helm charts / Kubernetes
- Bulk import from other managers (CSV minimal in v1; KeePass XML, 1PUX, LastPass JSON deferred)
- Public registration
- Admin web panel beyond `/health` and CLI

## Permanent OUT OF SCOPE (will not build)

- Billing / paid tiers
- Multi-tenant isolation beyond user-level (no orgs as a separable customer)
- SOC2 / ISO 27001 attestation (not at this scale)
- Server-side recovery / key escrow (would break the threat model)

---

## REQ → Phase mapping (preview — see ROADMAP.md for detail)

| Phase | REQ-IDs delivered |
|---|---|
| 01 — Foundations | REQ-INFRA-001..003, REQ-DEPS-001..002 |
| 02 — Auth + Crypto core | REQ-CRYPTO-001..008, REQ-AUTH-001..007 |
| 03 — 2FA + sessions UI | REQ-2FA-001..005, REQ-AUTH-005 (sessions UI) |
| 04 — Personal vault: credentials | REQ-VAULT-001..006 |
| 05 — Personal vault: pages (TipTap) | REQ-VAULT-007..011, REQ-WEBSEC-005 |
| 06 — Page double-lock | REQ-CRYPTO-005 |
| 07 — Shared vaults: create + invite + key wrap | REQ-SHARE-001..005, REQ-RATELIMIT-005 |
| 08 — Shared vaults: member mgmt + revoke + re-wrap | REQ-SHARE-006..007 |
| 09 — Unanimous delete + timeout override | REQ-DELETE-001..007 |
| 10 — Audit log + hash chain + verification | REQ-AUDIT-001..006 |
| 11 — Recovery + account export | REQ-CRYPTO-006, REQ-RECOVERY-001..003, REQ-AUTH-007 |
| 12 — Web hardening + rate limits + headers | REQ-WEBSEC-001..007, REQ-RATELIMIT-001..007 |
| 13 — **Security Hardening milestone (all auditors)** | (verification, no new REQs) |
| 14 — Production deploy + observability + backups | REQ-INFRA-004..009 |
