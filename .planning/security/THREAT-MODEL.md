# SimpleVault — Threat Model (STRIDE)

**Owner:** `threat-modeler` agent
**Last updated:** 2026-04-28 — **M0 Baseline expansion**
**Status:** **M0 Baseline (2026-04-28)** — full STRIDE skeleton, attack trees AT-1..AT-5, adversaries A1..A5, asset inventory and Phase-01 controls map established. Will be re-expanded at start of each subsequent milestone.

> This document supersedes the prior SCAFFOLD by **extending** it. Sections 1–5 below preserve the original schema; the M0 baseline content is appended in sections 6–13. When the original sections refer to "(to expand)" they are now elaborated below, but the original asset list and trust-boundary diagram remain authoritative for quick reference.

---

## 1. Context & Assumptions

### Adversary profile (assumed, original baseline)

| Attribute | Value |
|---|---|
| Skill level | Web-skilled, motivated, with time |
| Resources | Single attacker or small group, no nation-state budget |
| Access | Internet-only by default; may compromise user email; may obtain leaked DB dump from third-party breach |
| Motivation | Financial (credential resale), targeted access to a specific user's vault, or operator extortion |
| Out of scope | Nation-state APT, hardware side-channels, physical access to user device, kernel-level supply-chain compromise |

> The five formal adversary models A1..A5 in §8 below refine this baseline.

### Trust boundaries (original ASCII diagram)

```
[ User device (browser) ]  ←—— TLS ——→  [ Traefik (Dokploy) ]
                                                 │
                                          [ Next.js web ]
                                                 │
                                          [ NestJS API ]  ←——→  [ Postgres ]
                                                 │              [ Redis ]
                                          [ Operator (semi-trusted) ]
```

(The original diagram referenced Caddy; load-bearing decision §6 in STATE.md replaced this with Traefik under Dokploy. See §7 below for the M0 expanded boundary diagram.)

- **Trusted:** User device (assumed un-compromised; if device is RAT'd, vault is compromised — accepted risk).
- **Semi-trusted:** Operator + server. May read all ciphertext + metadata. **Cannot** read plaintext (E2E). Audit log is tamper-evident, so operator tampering is **detectable** even if not preventable.
- **Untrusted:** Network (assume MITM possible until TLS), all input from clients.

### Crown jewels (asset summary, original baseline)

1. **Vault contents** (credentials + page bodies) — confidentiality CRITICAL, integrity HIGH, availability MEDIUM
2. **Master passwords** (never leave client) — confidentiality CRITICAL
3. **Recovery codes** (never leave client; only hash on server) — confidentiality CRITICAL
4. **Audit log** — integrity CRITICAL (tamper-evident), confidentiality MEDIUM
5. **WebAuthn credentials** — integrity CRITICAL
6. **Session tokens (refresh)** — confidentiality HIGH

> See §6 below for the full M0 asset inventory (adds: secret_key, server master HMAC secret, TLS certs, server FS, public-key directory, etc.).

---

## 2. STRIDE per major flow (original; will be re-expanded per phase as code lands)

### Flow: Signup
- **Spoofing:** N/A (no identity to spoof yet); but invite-code-only signup limits enumeration
- **Tampering:** Argon2id params chosen client-side could be downgraded → server pins minimum
- **Repudiation:** Recovery code shown only once → user may claim "never received" → forced confirmation step
- **Information disclosure:** Account enumeration via signup endpoint → uniform errors + timing
- **DoS:** Signup spam → operator-issued invite codes throttle
- **Elevation:** N/A

### Flow: Login (M0 elaboration)
- **Spoofing:** Phishing of master password + secret_key; mitigated by WebAuthn (RP-ID-bound, phish-resistant) at REQ-2FA-001 (post-Phase 03). At M0 phishing is OPEN (no auth code yet).
- **Tampering:** Client-side Argon2id parameter downgrade; mitigated by binding KDF params into AAD (REQ-CRYPTO-002) and server pinning a minimum.
- **Repudiation:** Login event written to audit log (REQ-AUDIT-001) once Phase 10 lands.
- **Information disclosure:** Account enumeration via timing/error differential — REQ-AUTH-003 mandates uniform response + dummy Argon2id on miss.
- **DoS:** Login bruteforce — REQ-RATELIMIT-002 (5/IP/15min, 10/email/15min sliding window) at Phase 12.
- **Elevation:** 2FA bypass via state confusion — REQ-2FA-005 mandates 2FA challenge issued **only after** first-factor success.

### Flow: Vault sharing — invite (M0 elaboration)
- **Spoofing:** Email-bound invite tokens (REQ-SHARE-003) HMAC-signed + single-use + 24h TTL + bound to email + vault_id; OOB owner approval prevents bait-and-switch.
- **Tampering:** Owner re-wraps vault_DEK to invitee's user_pub_key client-side → server cannot substitute pub-key without detection (TOFU-style: invitee's pub-key is published at signup; member-list signature could later detect swap — defer to Phase 13 hardening review).
- **Repudiation:** Approval action goes to audit log.
- **Information disclosure:** Invitee's email is visible to operator (DB-level metadata); accepted risk.
- **DoS:** Invite spam — REQ-RATELIMIT-005 (10/vault/day).
- **Elevation:** Invitee receiving unintended owner-role — explicit role on membership row, default `member`, escalation requires owner action (see AT-5).

### Flow: Vault sharing — unanimous deletion (M0 elaboration)
- **Spoofing:** Vote signatures by member acct — relies on session auth + 2FA (REQ-2FA-003).
- **Tampering:** Vote tally manipulation by operator — every vote event is an audit-log entry (REQ-DELETE-007 + REQ-AUDIT-001), and votes are HMAC-chained, so post-hoc tampering is detectable.
- **Repudiation:** Each member's vote is timestamped + chained.
- **Information disclosure:** Pending-deletion state visible to all members; accepted (intended).
- **DoS:** Member non-response — 30d timeout + 7d notice + owner-override is the documented mitigation (REQ-DELETE-002..005). See AT-4 for attack tree.
- **Elevation:** Owner-override is the *intended* escalation path; logged in audit chain with full context (REQ-DELETE-005).

### Flow: Page with double-lock (M0 elaboration)
- **Spoofing:** N/A (page identity is internal to vault).
- **Tampering:** Either wrap could be removed by malicious operator → user notices because either path still unwraps; chain entry would log change.
- **Repudiation:** Page edit/lock events logged.
- **Information disclosure:** Title HMAC-prefix index leaks substring matches — accepted; bodies remain encrypted.
- **DoS:** Forgotten page-password + forgotten master_password = lost; the master_KEK wrap is the redundancy (REQ-CRYPTO-005).
- **Elevation:** N/A.

### Flow: Master password reset with recovery code (M0 elaboration)
- **Spoofing:** Recovery requires email + secret_key + 24-word phrase together (REQ-AUTH-007) — three-of-three.
- **Tampering:** Server replaces stored recovery hash → user discovers on next recovery attempt; but recovery wraps `master_DEK`, so a wrong hash just means the recovery KEK won't unwrap → fails closed.
- **Repudiation:** Recovery use is audited.
- **Information disclosure:** Server stores `HMAC(server_secret, sha256(phrase))` only (REQ-CRYPTO-006); leak-resistant.
- **DoS:** Recovery flood — REQ-RATELIMIT-004.
- **Elevation:** Phrase is rotated on use (REQ-AUTH-007) so a leaked old phrase is invalidated.

---

## 3. Attack trees (M0 baseline drafts — see §9 for full elaborations)

- AT-1: Attacker reads another user's vault content → §9.1
- AT-2: Compromise the operator's master server-secret(s) (was: "Attacker reaches operator infra and dumps DB" — generalised at M0) → §9.2
- AT-3: Forge or rewrite the audit log → §9.3
- AT-4: Bypass unanimous deletion → §9.4
- AT-5: Privilege-escalate a non-owner member of a shared vault to owner → §9.5

> Note: original AT-5 ("phishing master password") is folded into AT-1 sub-path "phish credentials" because phishing is a means, not a goal. The original AT-4 ("dump DB") is now AT-2 sub-path A.

---

## 4. Open questions

- Should we require WebAuthn 2FA for the **operator** account specifically (operator has elevated trust)?
  → STATE.md open question; decide before Phase 14.
- Cold storage of audit log merkle root: git tag, separate VPS, or external service?
  → STATE.md open question; decide before Phase 10.
- Disclosure policy if a CVE in a dependency is found in production?
  → Defer to Phase 13.
- M0 add: what is the **device-level secret_key cache** threat model? Currently REQ-CRYPTO-003 says "can be persisted device-locally encrypted afterwards" — this is a new attack surface (encrypted-at-rest by what key?). Flag for Phase 02 design.

---

## 5. Update protocol

`threat-modeler` agent regenerates this doc at the start of each milestone. Diff is reviewed by operator before milestone gate opens.

---

# === M0 BASELINE EXPANSION (2026-04-28) ===

Everything below is new in the M0 baseline.

---

## 6. Asset inventory (M0)

Tier legend: **C** = Confidentiality, **I** = Integrity, **A** = Availability. **H/M/L** = High/Medium/Low.

| # | Asset | Lives where | C | I | A | Notes |
|---|---|---|---|---|---|---|
| 1 | **Master password** | User brain + browser RAM during session | H | H | — | Never transits the wire; never logged. If lost, user MUST use recovery flow. |
| 2 | **secret_key** (128-bit, REQ-CRYPTO-003) | User Emergency Kit (printed/stored offline) + browser RAM during session, optionally device-local cipher cache | H | H | M | Server stores only Argon2id verifier. Lost → vault unrecoverable even with recovery phrase. |
| 3 | **Recovery phrase** (BIP-39 24w) | User offline transcription only | H | H | — | Server stores only `HMAC(server_secret, sha256(phrase))`. Rotates on use. |
| 4 | **master_KEK / master_DEK / user_KEK** | Browser RAM, post-derivation | H | H | M | Wiped on auto-lock (15min idle, REQ-WEBSEC-007). |
| 5 | **vault_DEK** (per shared vault) | Browser RAM; wrapped at-rest in DB per-member with X25519 sealed-box | H | H | M | Server cannot unwrap. Rotated on member-removal. |
| 6 | **page_DEK** (per locked page) | Browser RAM only when unlocked | H | H | M | Double-wrap by page_KEK + master_KEK. |
| 7 | **Encrypted vault items** (credentials + pages, ciphertext blobs) | Postgres `vault_items` (Phase 04+) | M | H | H | Plaintext is H/H; ciphertext is M/H (operator can see *which* user has *how many* items + sizes). |
| 8 | **Per-user public keys (X25519)** | Postgres `users.user_pub_key` | L | **H** | M | Pub-key swap = silent re-wrap attack on shared vaults; integrity is critical. |
| 9 | **Server master HMAC secret** (`SERVER_CHAIN_SECRET`, audit chain) | Dokploy env-var → API container env | **H** | **H** | H | Compromise lets operator forge/rewrite audit log undetectably until next signed Merkle checkpoint. |
| 10 | **Ed25519 audit-checkpoint signing key** | Operator-controlled offline file (NOT in container) | H | **H** | M | Compromise breaks tamper-evidence at the checkpoint layer. |
| 11 | **Server JWT signing secret** (HS256) | Dokploy env-var → API container env | H | H | H | Compromise → forged sessions for any user. Rotation mandatory. |
| 12 | **Audit log table** | Postgres `audit_log` | M | **H** | H | INSERT-only DB role (REQ-AUDIT-006). |
| 13 | **Postgres DB** (full) | Dokploy-managed PG 18.3 | M | H | H | All-ciphertext for vault data + metadata for everything else. Logical pg_dump nightly. |
| 14 | **Server filesystem** (API container rootfs + tmpfs) | Container | L | M | M | Read-only rootfs from M0 onward (Plan 07 hardening). Tmpfs for /tmp. |
| 15 | **TLS private key** | Traefik (Dokploy) auto-managed | H | H | H | Compromise → MITM on `pass.runadev.com` for cert lifetime. |
| 16 | **Refresh tokens** | Postgres `sessions` (Phase 03) + httpOnly cookie | H | H | M | 30-day TTL, single-use rotation, family-revoke on reuse (REQ-AUTH-005). |
| 17 | **WebAuthn credentials** (pub-keys) | Postgres + user authenticator hardware | M | **H** | H | Integrity critical (cannot accept attacker-supplied credential). |
| 18 | **Invite codes** (HMAC-signed) | Postgres + email | M | H | M | Single-use, TTL'd, bound to email+vault_id. |
| 19 | **Backups** (`pg_dump` rsync to offsite NAS) | Operator NAS/VPS via SSH+rrsync wrapper | M | H | H | Same content sensitivity as DB itself; encrypted at rest is operator's responsibility. |
| 20 | **CI/CD secrets** (GitHub Actions: registry creds, Dokploy webhook) | GitHub repo secrets | H | H | M | Compromise → supply-chain push to prod. |

---

## 7. Trust boundaries (M0 expanded diagram)

```
                                       INTERNET
                                          │
                       ┌──────────────────┴──────────────────┐
                       │                                     │
                  [ User browser ]                  [ Anonymous attacker ]
                       │
                       │  TLS 1.2+ (HSTS preload, no host port leak)
                       ▼
================ Boundary T1: Network → Edge =========================
                  [ Traefik (Dokploy) ]
                       │  HTTP, internal docker net only
                       ▼
================ Boundary T2: Edge → App =============================
              ┌────────────────────────┐
              │  apps/web (Next.js)    │   read-only rootfs, non-root,
              │  nonced CSP, helmet    │   cap_drop ALL
              └────────────────────────┘
                       │
                       │  HTTP, frontend network
                       ▼
              ┌────────────────────────┐
              │  apps/api (NestJS)     │
              │  helmet, ValidationPipe│
              │  pino redaction        │
              └────────────────────────┘
                       │  pg + redis client, BACKEND network (internal:true, NO egress)
================ Boundary T3: App → Datastore ========================
                       │
              ┌────────┴───────┐
              ▼                ▼
        [ Postgres 18.3 ]   [ Redis 7.4 ]
        (NO host port)      (NO host port)
                       │
================ Boundary T4: App ↔ Operator ==========================
                       │
              [ Dokploy host (operator root) ]
                       │
              [ Operator workstation (SSH key) ]
                       │
================ Boundary T5: App → Off-site =========================
                       │  rsync over SSH, rrsync wrapper, append-only
                       ▼
              [ Operator NAS/VPS for pg_dump backups ]

================ Boundary T6: Off-machine ============================
              [ Audit Merkle checkpoint git repo ]   (Phase 10; location TBD)
              [ Ed25519 signing key, OFFLINE ]

================ Boundary T7: Inter-tenant ===========================
              Within a shared vault, each member is in a separate
              cryptographic boundary (per-member X25519 sealed-box wrap).
              Operator + server are OUTSIDE this boundary.
```

**Boundary semantics:**

- **T1 (Internet → Edge):** Untrusted → semi-trusted. TLS terminates at Traefik. Traffic in/out is presumed adversarial.
- **T2 (Edge → App):** Both sides controlled by operator. Trust gain: TLS termination, basic L7 routing.
- **T3 (App → Datastore):** `backend` docker network is `internal: true` (no egress). DB/Redis are not exposed to host or internet. Trust on this boundary = "anything that reached the API is allowed to talk to its DB", no further auth between API ↔ Postgres beyond the connection-string password.
- **T4 (App ↔ Operator):** **The semi-trusted boundary**. Operator has root on host → can `docker exec`, read env-vars, dump memory, swap container images. Operator CANNOT read user plaintext (E2E) or undetectably rewrite audit log (chained + Ed25519-checkpointed off-machine).
- **T5 (App → Off-site backups):** Backup container has restricted SSH key (`command="rrsync -wo …"` per STATE.md) so even if API container is popped, the backup target cannot be wiped, only appended.
- **T6 (Off-machine checkpoint):** Hard boundary — operator-controlled but not co-located with the prod VPS. Compromising T4 alone does not let an attacker reach back through T6 to retroactively alter signed checkpoints.
- **T7 (Inter-tenant in shared vault):** Cryptographic, not network. Each member's plaintext access is gated by their own user_KEK + the wrapped vault_DEK. A malicious member sees only what their wrap entitles them to (plus all members' metadata).

---

## 8. Adversary models (M0)

### A1 — Curious / compromised network attacker (active MITM on TLS)

- **Capabilities:** Can observe and modify all traffic between user and `pass.runadev.com`. Cannot break TLS cryptography; can attempt cert mis-issuance / downgrade.
- **Goals:** Steal master password, secret_key, session cookie; serve malicious JS to capture plaintext.
- **Mitigations:** TLS 1.2+ only (REQ-INFRA-009), HSTS preload (REQ-WEBSEC + Plan 05), strict CSP with nonces (REQ-WEBSEC-001 + Plan 05), `__Host-` cookie prefix (REQ-WEBSEC-002), CT log monitoring (operator runbook, Phase 14).
- **Residual risk at M0:** No auth code yet; A1 is contained by TLS + CSP only.

### A2 — Compromised VPS operator (root on host)

- **Capabilities:** Full root on Dokploy host. Can read all env-vars, dump container memory, replace images, read Postgres unencrypted on disk, read backups before they leave. Can write malicious server-side code.
- **Goals:** Read user vault plaintext; rewrite audit log to hide actions; impersonate users.
- **What they CANNOT do without detection:**
  - Read user vault plaintext → blocked by E2E (master password + secret_key never leave client).
  - Undetectably rewrite audit log → blocked by HMAC chain (REQ-AUDIT-002) + off-machine Ed25519 daily Merkle checkpoint (REQ-AUDIT-003). Operator can rewrite log up to last checkpoint (≤24h), but the chain break is detectable.
  - Forge a session for an arbitrary user → CAN do this if JWT signing secret is in the same env they read; mitigation is reactive (audit log + member's WebAuthn 2FA ceremony required for sensitive ops in Phase 03).
- **What they CAN do (accepted risk):**
  - DoS the service (delete data, kill containers).
  - Capture all traffic at the proxy → ciphertext + metadata.
  - Swap a user's published `user_pub_key` → silent re-wrap on next share. **OPEN — see AT-5 leaf.**
  - Push a malicious frontend JS bundle to capture master password on next login. **THIS IS THE FUNDAMENTAL UNAVOIDABLE RISK** of self-hosted web crypto and is documented as accepted.

### A3 — Malicious user with valid account (insider in shared vault)

- **Capabilities:** Has legitimate session, valid 2FA, valid membership in one or more shared vaults.
- **Goals:** Escalate to owner; exfiltrate other vault items they don't own; force deletion of a vault against majority will; replay old vault state.
- **Mitigations:** Role enforced server-side (not just UI) for owner-only ops (REQ-SHARE-006); unanimous-deletion + 30d/7d/owner-override (REQ-DELETE-001..007); audit log records every attempt (REQ-AUDIT-001); rate-limits per-user (REQ-RATELIMIT-006).
- **Residual risk:** A3 already has the vault_DEK for any vault they're in → exfiltration of *that* vault is unavoidable (accepted: "removed member retains local copies", REQ-SHARE-006 documented).

### A4 — Compromised npm / dep author (supply-chain)

- **Capabilities:** Publishes a malicious version of a transitive dep (typo-squat, account compromise, intentional sleeper).
- **Goals:** Exfiltrate master password / secret_key / DEK from the browser bundle; silently weaken Argon2id params; insert backdoor in API.
- **Mitigations (M0):** `pnpm-lock.yaml` committed + `--frozen-lockfile` in CI (REQ-DEPS-001); `pnpm audit --audit-level=high` blocks merge on H/Critical (REQ-DEPS-002); Dependabot weekly grouped PRs; CODEOWNERS gate; `dependency-supply-chain-auditor` weekly cron (REQ-DEPS-004).
- **Residual risk:** Lockfile-pinned dep can still be malicious-but-quiet for weeks. Mitigation strength scales with audit cadence + Socket.dev or similar (Phase 12+).

### A5 — Sophisticated remote attacker exploiting a 0-day in API surface

- **Capabilities:** RCE on `apps/api` via an unpatched CVE in NestJS / pg / a transitive dep.
- **Goals:** Escalate to operator-equivalent (A2). Exfiltrate `SERVER_CHAIN_SECRET`, JWT secret, Postgres creds; pivot to backups.
- **Mitigations (M0):** Container hardening (non-root, read-only rootfs, cap_drop ALL, no-new-privileges, pids_limit, mem_limit); backend network `internal: true` (no egress from API → outside world); Trivy CRITICAL+HIGH container scan in CI (Phase 01 Plan 09); separation of `SERVER_CHAIN_SECRET` from JWT secret (different blast radii).
- **Residual risk:** RCE → A2-equivalent. Detection via audit chain break + checkpoint signature. Recovery requires secret rotation + forced password resets.

---

## 9. Attack trees (M0 drafts)

### 9.1 AT-1: Steal a single user's vault contents

```
GOAL: Adversary reads cleartext vault items of victim user U
├─ A. Compromise U's client device
│   ├─ Phish U's master password + secret_key (A1, A4 via malicious bundle)
│   │   └─ Pre: convince U to enter creds on attacker-controlled origin
│   └─ Malware/RAT on U's device exfiltrates RAM keys
│       └─ Pre: device compromise (out-of-scope per §1)
├─ B. Compromise the served frontend (A2 or A4)
│   ├─ Operator pushes malicious JS bundle that posts master_password to attacker
│   │   └─ Pre: operator A2 OR CI/CD compromise (#20)
│   └─ Compromised dep ships bundle that exfiltrates Argon2id output
│       └─ Pre: A4 supply-chain
├─ C. Cryptanalysis of intercepted ciphertext (A1, A2)
│   ├─ Brute-force master password offline
│   │   └─ Pre: have ciphertext + KDF params + secret_key (still need #2!)
│   │       Mitigation: secret_key has 128 bits of entropy → infeasible
│   └─ Argon2id weakness (none known at M0)
└─ D. Trick U into "sharing" personal vault
    └─ Pre: shared-vault is by-design opt-in; personal-vault never shareable (REQ-VAULT-001)
```

### 9.2 AT-2: Compromise operator master server-secret(s)

```
GOAL: Adversary obtains SERVER_CHAIN_SECRET and/or JWT signing secret
├─ A. Read Dokploy env-var UI
│   ├─ Compromise Dokploy admin account
│   │   └─ Pre: phish operator OR Dokploy 0-day (A5-class against the platform)
│   └─ Direct VPS access (A2)
│       └─ Pre: SSH key compromise OR provider-side console access
├─ B. RCE on apps/api → read process env
│   └─ Pre: A5 0-day in API surface
├─ C. Exfiltrate from a backup
│   └─ Pre: env-vars are NOT in pg_dump (DB-only); only DB creds + plaintext ciphertext-blob data leaks → ATTACK FAILS THIS PATH for chain secret
│   Note: this is a control-by-design — env-vars and DB are different blast radii.
└─ D. Exfiltrate from CI/CD
    └─ Pre: GitHub Actions secret leak + secrets are mirrored to CI (which they are NOT today; CI does not have prod chain secret)
```

### 9.3 AT-3: Forge or rewrite the audit log

```
GOAL: Adversary inserts/deletes/modifies audit_log rows without detection
├─ A. Direct SQL UPDATE/DELETE on audit_log
│   └─ Pre: Postgres role for app has INSERT-only (REQ-AUDIT-006) → BLOCKED for app role
│       Sub-pre: superuser access required → A2 (operator) only
├─ B. Operator-as-postgres-superuser rewrites rows
│   ├─ Pre: A2
│   └─ Detection: HMAC chain break on next read (REQ-AUDIT-005); off-machine Ed25519 Merkle checkpoint mismatches at next daily run
├─ C. Forge entries by knowing SERVER_CHAIN_SECRET
│   └─ Pre: AT-2 (then audit log can be forged consistently up to last off-machine checkpoint, ≤24h window)
│       Detection: only via member behaviour anomaly OR rotation of chain secret + retroactive verification
└─ D. Compromise the off-machine checkpoint (Ed25519 key)
    └─ Pre: T6 boundary breach (operator workstation compromise)
        Detection: dual-checkpoint scheme (operator could mirror to second offline location) — Phase 10 design decision
```

### 9.4 AT-4: Bypass unanimous deletion

```
GOAL: Force deletion of a shared vault without all members' consent
├─ A. Owner abuses override with stale notifications
│   ├─ Owner suppresses 7d notice email (operator A2 collusion)
│   │   └─ Pre: A2 OR SMTP provider tampering
│   │   Detection: REQ-DELETE-005 logs full context (when notifications were sent) — but if logs themselves are tampered → AT-3
│   └─ Owner times override during member's known absence
│       Detection: member regains access within 30d post-deletion via re-confirm (REQ-DELETE-006)
├─ B. Operator (A2) directly DELETEs vault rows
│   └─ Pre: A2; detection via audit chain break + member outcry (no proposal exists)
├─ C. Compromise enough member sessions to fake votes
│   └─ Pre: A1 / A4 / A5 across multiple users; HARD
└─ D. Race-condition in vote tally (TOCTOU)
    └─ Pre: implementation flaw in Phase 09 → security-auditor target
```

### 9.5 AT-5: Privilege-escalate non-owner member to owner

```
GOAL: Member M (role=member) gains role=owner on shared vault V
├─ A. API authz bypass (broken object-level authorization, BOLA)
│   └─ Pre: implementation flaw in Phase 07/08 (server doesn't check role on owner-only endpoints) → security-auditor target
├─ B. JWT/session forgery
│   └─ Pre: AT-2 (JWT signing secret) OR token-reuse / refresh-token theft (REQ-AUTH-005 mitigates)
├─ C. Pub-key swap attack
│   ├─ Operator (A2) replaces another member's user_pub_key with M's
│   │   └─ Pre: A2; M then receives a re-wrapped vault_DEK on next share-touching op
│   │   Detection: member-list signature / TOFU pinning (NOT in v1; OPEN — flag for Phase 13)
│   └─ Mitigation gap: M0 documents this as accepted-with-flag risk
└─ D. Owner account takeover
    └─ Pre: AT-1 against the owner specifically
```

---

## 10. STRIDE skeleton across modules (M0)

One row per module × STRIDE category. Empty cells where M0 provides no code surface yet — but tracked so phase auditors can fill them in as code lands.

| Module | S (Spoofing) | T (Tampering) | R (Repudiation) | I (Info disclosure) | D (DoS) | E (Elevation) |
|---|---|---|---|---|---|---|
| **Auth (Phase 02)** | Phishing of password+secret_key (A1/A4); WebAuthn pinned RP-ID (Ph 03) | Argon2id param downgrade — pin server min, AAD-bind | Login event logged (Ph 10) | Account enum via timing — REQ-AUTH-003 | REQ-RATELIMIT-002 (Ph 12) | 2FA bypass via flow confusion — REQ-2FA-005 |
| **Crypto core (Phase 02)** | N/A | Tampered ciphertext detected by Poly1305 AEAD | N/A | Argon2id timing side-channel — accepted; libsodium constant-time primitives elsewhere | Argon2id resource exhaustion at signup — REQ-RATELIMIT-003 | Library MITM of WASM bundle — A4 / SRI |
| **Sessions (Phase 03)** | Stolen refresh token — single-use rotation, family-revoke (REQ-AUTH-005) | JWT tampering — HS256 verify; `__Host-csrf` (REQ-WEBSEC-003) | Session events logged | Cookie attributes (REQ-WEBSEC-002) | Token mint flood — REQ-RATELIMIT-006 | JWT secret theft — AT-2; rotation policy needed |
| **Personal vault: credentials (Phase 04)** | N/A (single-tenant within user) | Ciphertext integrity via AEAD; metadata integrity via app | All writes audited (Ph 10) | Server-readable metadata (id, vault_id, version, updated_at) — accepted | Heavy clients pulling many items — pagination | N/A |
| **Pages / double-lock (Phase 05–06)** | N/A | Either wrap removal detectable via the other | Lock/unlock audited | Title HMAC-prefix index — accepted | TipTap doc bomb — schema strict, server size cap | Lock bypass via wrap-record manipulation — server enforces both writes |
| **Shared vaults (Phase 07–08)** | Invite-link spoof — HMAC bound to email+vault_id | Server cannot substitute wrapped DEK without member detecting on unwrap; pub-key swap is OPEN at v1 (AT-5C) | All membership ops audited | Member list visible to all members — REQ-SHARE-005 (intended) | Invite spam — REQ-RATELIMIT-005 | BOLA on owner-only ops — server-side role check (Ph 07) |
| **Audit chain (Phase 10)** | N/A | HMAC chain + off-machine Ed25519 Merkle (REQ-AUDIT-002..003) | Whole-system non-repudiation | Audit log readable by members of vault — REQ-AUDIT-005 | INSERT-only role limits volume attacks | Chain secret theft — AT-2/AT-3 |
| **Recovery (Phase 11)** | 3-of-3 (email + secret_key + phrase) defeats single-factor takeover | Phrase rotation on use (REQ-AUTH-007) | Recovery use audited | HMAC-only storage of phrase (REQ-CRYPTO-006) | REQ-RATELIMIT-004 | Recovery skipping secret_key check — explicit requirement |
| **Web app surface (Phase 01 / 05 / 12)** | DNS / TLS — REQ-INFRA-009 | CSP nonced (Plan 05), no `dangerouslySetInnerHTML` (REQ-WEBSEC-005) | N/A (handled per-flow) | CSP + COOP/CORP same-origin (Plan 05); referrer policy no-referrer | Ratelimit at edge (Ph 12) | XSS → token theft mitigated by httpOnly + nonced CSP |
| **API surface (Phase 01+)** | N/A at HTTP layer | helmet, ValidationPipe whitelist+forbidNonWhitelisted (Plan 04) | Per-flow | Pino redaction (Plan 04), canonical error envelope hides internals | REQ-RATELIMIT-001/006 | Authz must be checked per route (Ph 02+) |
| **Dokploy / infra (Phase 01 / 14)** | TLS provisioning (Traefik) | Container image content hashed (Plan 06); compose stack reviewed | Operator actions on host are unaudited by app (accepted) | Env-vars in Dokploy UI; not in git | Resource limits per container (Plan 07) | Operator = A2; documented |
| **Backups (Phase 14)** | rrsync `command=` restricts SSH key power | Append-only target; weekly checksum drill (operator runbook) | Backup runs logged | Backups contain ciphertext + metadata; tier matches DB | Backup target full → alert | Compromise of backup SSH key → write-only via rrsync limits blast radius |

---

## 11. Phase 01 controls map (what M0 just bought us)

Phase 01 (Foundations) does not ship security-critical features (those start Phase 02). What it DOES establish:

| Control landed at Phase 01 | Closes | Partially closes | Open / future-phase |
|---|---|---|---|
| **CSP nonce-per-request, no unsafe-inline/eval** (Plan 05) | XSS via inline injection | A1 (cannot inject scripts) | XSS via dep compromise (A4) |
| **helmet + restrictive CORS allowlist** (Plan 04) | CSRF on legacy XHR; clickjacking (X-Frame-Options DENY) | A1 cross-origin attacks | CSRF token (REQ-WEBSEC-003 — Phase 12) |
| **Pino redaction list** (Plan 04) | Accidental logging of password/secret_key/JWT/recovery | Repudiation: logs are clean | Audit log itself (Phase 10) |
| **`internal: true` backend network + no host port for PG/Redis** (Plan 07) | Direct external DB attack; A1 reaching PG/Redis directly | Limits A5 lateral movement (no egress from backend) | Service-mesh-level mTLS (not pursued at v1 scale) |
| **Container hardening: non-root, read-only rootfs, cap_drop ALL, no-new-privileges, pids/mem limits** (Plan 07) | Container escape primitives reduced | A5 RCE blast radius | Seccomp/AppArmor profiles (Phase 13) |
| **Lockfile + `--frozen-lockfile` + `pnpm audit` H/Critical block in CI** (Plan 09, REQ-DEPS-001/002) | Naïve typosquat / known-CVE merge | A4 supply-chain | Sleeper malicious deps (Socket.dev / weekly auditor cron — Phase 12+) |
| **Trivy CRITICAL+HIGH container scan in CI** (Plan 09) | Known-CVE base-image creep | A5 surface (publishes risky images) | Runtime drift (Phase 14 monitoring) |
| **CODEOWNERS + Dependabot grouped weekly** (Plan 09) | Unauthorised merge to security-critical paths | A4 silent dep updates | Branch protection enforcement (operator decision) |
| **Migration prestart hook fail-fast** (Plan 06/08) | Partial-migration runtime states | DoS from migration-runtime races | — |
| **`migrate-then-start.sh` fail-fast** (Plan 06) | API serving traffic against incompatible schema | — | — |
| **Per-app HEALTHCHECK + Dokploy domain TLS** (Plan 06/10) | Silent broken deploys | A1 (forces TLS) | OCSP stapling / CT monitoring (Phase 14) |

**Threats explicitly STILL OPEN at end of M0** (no code yet): all of REQ-AUTH (Phase 02), REQ-CRYPTO actual primitives (still stubs in `packages/crypto`), REQ-2FA, REQ-VAULT, REQ-SHARE, REQ-DELETE, REQ-AUDIT, REQ-RECOVERY, REQ-RATELIMIT, REQ-WEBSEC-002/003/005/006/007. These are owned by Phases 02–13.

---

## 12. Top-10 priority threats (M0)

Sorted by **likelihood × impact** at M0 close. Each carries the phase/agent that owns the mitigation.

| # | Threat | Likelihood | Impact | Score | Owner |
|---|---|---|---|---|---|
| 1 | **Operator pushes malicious frontend bundle to capture master password** (A2 / B-path of AT-1) | M | Catastrophic | **HIGH** | Accepted by self-hosted model; mitigation: subresource pinning + operator self-discipline; doc in `docs/operator/SECURITY-NOTES.md` (Phase 14) |
| 2 | **`SERVER_CHAIN_SECRET` exfil via A5 0-day in API** (AT-2 path B → AT-3) | L-M | High (audit log forgery window) | **HIGH** | `security-auditor` at every phase gate; secret rotation runbook by **Phase 14**; HSM/KMS upgrade is v2 |
| 3 | **Pub-key swap by operator silently re-wraps shared vault DEK to attacker on next share** (AT-5 C) | L-M | High (silent insider-equiv read of shared vault) | **HIGH** | `crypto-auditor` Phase 07/08; design fix = TOFU pinning + member-list signature; FLAG for Phase 13 |
| 4 | **Supply-chain attack via compromised npm dep** (A4) | M (industry baseline) | High | **MED-HIGH** | `dependency-supply-chain-auditor` weekly cron (REQ-DEPS-004); hardening Phase 12+ |
| 5 | **Argon2id KDF param downgrade at login** (T row, Auth) | L-M | High | **MED** | Phase 02 `crypto-auditor`; pin server-side min + AAD-bind |
| 6 | **JWT signing secret theft → forged sessions** (AT-5 B) | L (gated by A2/A5) | Catastrophic per-user | **MED** | Phase 03 sessions design; rotation playbook; separate from chain secret blast radius |
| 7 | **Owner abuses unanimous-deletion override during member absence** (AT-4 A) | L | Med (data loss; recoverable from backups) | **MED** | Phase 09 `security-auditor`; emphasis on full audit-log context (REQ-DELETE-005) |
| 8 | **Account enumeration via login timing/error differential** | M | Low-Med | **MED** | Phase 02; REQ-AUTH-003 (uniform error + dummy Argon2id) |
| 9 | **CSRF on state-changing endpoints once auth lands** | M (post Phase 02 if missed) | Med | **MED** | Phase 12 `web-security-auditor`; REQ-WEBSEC-003 double-submit |
| 10 | **Off-site backup write-loop ransomware via app-container compromise** (T5) | L | High (data loss) | **MED** | Phase 14 operator runbook; `rrsync -wo` append-only wrapper; verify ≤Phase 14 deploy |

---

## 13. Load-bearing assumptions (changing any of these REQUIRES re-running this threat-modeler)

The 10 STATE.md decisions remain load-bearing. The M0 baseline additionally pins these assumptions:

A. **Two-secret model is GO** (REQ-CRYPTO-003 confirmed 2026-04-28): without secret_key as a second factor in derivation, AT-1 path C ("offline brute-force from leaked DB") becomes feasible against weak master passwords. Reverting this decision invalidates §9.1, §10 row "Personal vault", and the residual-risk analysis for A2.

B. **Off-machine Ed25519 Merkle checkpoint is the *only* defence** that makes audit log tampering by A2 detectable beyond ≤24h. If operator does not actually run the off-machine checkpoint cron, AT-3 path C succeeds undetectably.

C. **Operator does not have access to user master_password / secret_key / recovery phrase**, ever. If at any point we add server-side recovery, key escrow, "admin reset", or browser autofill that posts plaintext, the entire E2E security argument collapses. (Permanently OUT-OF-SCOPE per REQUIREMENTS.md.)

D. **`backend` docker network remains `internal: true`** (no egress from API container outward, only inward). If an operator removes this for "convenience", A5 RCE → exfil over arbitrary port becomes trivial.

E. **Pub-key TOFU-pinning is NOT yet implemented (v1 gap).** The shared-vault security model assumes the operator does not swap published `user_pub_key` values. AT-5 path C is open and must be re-evaluated by `crypto-auditor` at Phase 07.

F. **Container env-vars are the secret store** (Dokploy UI → container env). Compromise of Dokploy admin = compromise of all server-side secrets. If the deployment target changes, re-threat-model.

G. **Single VPS, single domain (`pass.runadev.com`), single operator.** No multi-region, no failover. Availability tier on all "H" assets is bounded by VPS uptime.

H. **Threat actors A1..A5 are exhaustive for v1.** Not modelled: nation-state APT, hardware side-channel, physical access to operator workstation, compromise of upstream Dokploy / Traefik infra. If the user/threat profile expands, re-threat-model.

---

*End of M0 baseline expansion (2026-04-28).*
