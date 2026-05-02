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

---

# === PHASE 02 EXPANSION — Login flow STRIDE + AT-5 refresh (2026-05-02) ===

> **Author:** `threat-modeler` agent (informational; no gate authority).
> **Trigger:** Phase 02 (Auth + Crypto core) implementation complete; updates ROADMAP.md line 72 commitment ("threat-modeler updates Login flow STRIDE + AT-5"). Preserves M0 sections 1–13 above unchanged. Cross-refs `.planning/phases/02-auth-crypto/02-PHASE-SUMMARY.md` for what actually shipped, and `.planning/STATE.md` "Load-bearing decisions" for the four new FROZEN items pinned by Plans 10 + 11.
>
> **Scope of this expansion:** the auth surface that landed in Phase 02 — `POST /invite/redeem`, `POST /auth/signup`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /me`, `GET /auth/params`. Refines AT-5 root from "privilege-escalate non-owner to owner" (M0 framing — re-targeted as AT-5b in Phase 07/08) into the **operationally relevant Phase 02 framing**: "Adversary obtains a valid user session". The two AT-5 framings are complementary: AT-5b (M0 §9.5) is owner-role escalation **inside** a vault; AT-5 below is **session-level compromise** as a *means*.

---

## 14. Phase 02 — Login flow STRIDE per data flow

Each row: **Threat** (S/T/R/I/D/E), **Description**, **Mitigation in shipped code**, **Residual risk**.
File:line citations are illustrative and rounded — see `apps/api/src/auth/*` and `apps/web/src/app/(auth)/*` for canonical implementations; the 02-PHASE-SUMMARY.md is the authoritative SOURCE for every claim below.

### 14.1 Flow: `POST /invite/redeem`

| # | Threat | Description | Mitigation (Phase 02 shipped) | Residual |
|---|---|---|---|---|
| S | Spoofing | Attacker presents a forged invite code to bootstrap a signup | HMAC-SHA256 with `SERVER_INVITE_SECRET` over `(code, email, expires_at)` stored as `invite_codes.code_hash`; raw never persisted (Plan 02-05 schema, Plan 02-07 redeem service). | Operator must keep `SERVER_INVITE_SECRET` ≥32 B and not commit to git. AT-2 path A still applies. |
| T | Tampering | Modify invite payload in transit | TLS 1.2+ at Traefik edge; HMAC validated server-side. | None at this layer. |
| R | Repudiation | "I never redeemed it" | `auth.audit.invite.redeem.{ok,fail}` Pino events with `requestId`+`ipHashB64` (Plan 02-09 audit-events). | Until Phase 10 hash-chain lands, log is mutable by A2 (operator). |
| I | Information disclosure | Probing valid emails / valid codes via differential errors | All failure modes (unknown / expired / already-redeemed / wrong-email) collapse to a single canonical `E1006` envelope; rate limit `invite-redeem-ip` 30/IP/h via `@nestjs/throttler` + Redis (Plan 02-09). | Timing leak from short-circuits (no Argon2 dummy on this endpoint) — accepted because invite codes are operator-issued not user-typed. |
| D | DoS | Spam-redeem to exhaust DB / Redis | Throttler ceiling 30/IP/h; redemption is read-only (no writes), so cost is bounded; fail-open on Redis outage with warn-log + `Retry-After`. | Distributed (botnet) attack would need Phase 12 edge defences. |
| E | Elevation | Stolen invite consumed by attacker → attacker gets a valid signed-up account | **Invite is a single-secret bearer token by design** for v1 — operator delivers OOB (Signal/in-person). Single-use enforced atomically inside the signup tx (Plan 02-07: `UPDATE invite_codes WHERE redeemed_at IS NULL`). | If the OOB channel leaks, attacker wins. SMTP delivery + email-binding is Phase 07. **Invite hijack is the dominant residual at this flow** — see AT-5 leaf "invite hijack". |

### 14.2 Flow: `POST /auth/signup`

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S | Spoofing | Sign up using somebody else's invite | Atomic Drizzle tx with `SELECT ... FOR UPDATE` on the invite row; race-loser sees 0 rows updated and aborts (Plan 02-07). | Same as 14.1 row E (OOB delivery). |
| T | Tampering | Client downgrades Argon2id params to weaken offline attack | **Server-side floor enforcement**: `CryptoService` rejects `argon2Params < floor` (Plan 02-07); AAD canonical 13-byte prefix `[v=0x01][m_be32][t_be32][p_be32]` binds params into every wrap blob (Plan 02-03 `encodeAad`) — downgrade requires re-wrapping under the same params, which is the chosen params. | Operator-set floor must be calibrated; runbook in `docs/operator/SECURITY-NOTES.md` covers `pnpm cli argon2 calibrate`. |
| R | Repudiation | Disputed account creation | `auth.signup.{ok,fail}` audit events. | Phase 10 hash-chain pending. |
| I | Information disclosure | Server logs leak password / secret_key / recovery phrase | **Server NEVER receives these by construction** (10-field envelope; only verifiers + ciphertext + public keys cross the wire — Plan 02-07 + 02-10). Pino redaction list extended for every signup-body bytea field, snake + camel variants, `*.dek`, `*.kek`, `*.argon2*`, `*.wrapped*` etc. (Plan 02-09). Zod `.strict()` on the signup DTO **provably rejects** `password`/`secretKey`/`recoveryPhrase` — verified by E2E sad-path. | Operator with A2 capability could attach a debugger before redaction; this is the fundamental self-hosted limit. |
| D | DoS | Argon2id resource exhaustion at signup; tx bloat | `signup-ip` throttler 3/IP/h; signup also runs Argon2id-on-server only over a 32-B verifier (no KDF on plaintext password). | Distributed signup spam → operator is the only signer of invites, so practical rate is bounded by invite issuance. |
| E | Elevation | Race two signups against same invite → duplicate account | `FOR UPDATE` row lock + single-shot `UPDATE … WHERE redeemed_at IS NULL` returns count==0 for race-loser; verified by E2E race spec. Drizzle pg-error 23505 (unique violation on `lower(email)`) collapses to E1006, leaves invite UNREDEEMED (verified by E2E rollback spec). | None known. |

### 14.3 Flow: `POST /auth/login`

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S | Spoofing | Phishing master_password + secret_key on a look-alike origin | At Phase 02 the only deterrent is the **two-secret model** (REQ-CRYPTO-003): the secret_key 16-B Crockford-base32 string is held in the user's printed Emergency Kit, not memorisable, lowering phish-replay viability vs single-password. WebAuthn (RP-ID phish-resistant) is REQ-2FA-001 in **Phase 03 — not yet shipped.** | **OPEN at Phase 02 close.** Phishing remains the highest-likelihood credential-loss vector for any non-WebAuthn deployment. Documented residual; gated by Phase 03. |
| T | Tampering | Client posts a verifier computed under WEAKER Argon2id params than the server's floor | `LoginService` re-derives the dummy verifier under server's authoritative `argon2Params` and the client's `argon2_secret_key_hash` is treated as opaque — login compares against `users.argon2_secret_key_hash` only, which was itself bound to its params at signup via AAD prefix. A weaker-params verifier simply will not match the stored one (Plan 02-08). | None — bind is byte-exact. |
| R | Repudiation | Disputed login | `auth.login.{ok,fail}` audit events with `actorUserId`, `ipHashB64`, `uaFamily`, `requestId` (Plan 02-09). | Phase 10 hash-chain pending. |
| I | Information disclosure | Account enumeration via response shape, status, body, or timing differential between **unknown email / wrong password / valid creds** | **Three-layer defence (REQ-AUTH-003)**: (1) Lookup via `lower(email)` UNIQUE index; if user-not-found, `LoginService` runs `crypto.timingSafeEqual` against a deterministic `DUMMY_HASH = SHA-256(versioned-label ‖ JWT_SECRET)` so the dummy is unpredictable and not trivially distinguished. (2) Both miss paths return **byte-identical** 401 envelope `{error:{code:"E1001",message:"Invalid credentials"}}` (E2E asserts byte equality — Plan 02-12 sad-path spec). (3) **Timing floor is constant-time-Argon2id-on-miss, NOT `setTimeout`** — measured wrong-vs-unknown delta 0.39 ms in 02-08 E2E, well under 50% threshold. | Network-jitter side-channel against the timing floor is theoretically present but bounded by Argon2id wall-clock dominance. Per-IP fingerprinting via login frequency is bounded by `login-ip` 5/min. |
| D | DoS | Credential stuffing / online brute-force; or Argon2id-on-miss CPU drain | Two-axis rate-limit (Plan 02-09): `login-ip` 5/IP/min AND `login-email` 10/email/h (the latter is body-keyed, lowercased). 9 named ceilings env-tunable. Dummy Argon2id on miss is by-design CPU cost — accepted as the price of timing uniformity. | Distributed credential-stuffing by botnet would saturate `login-email`, slowing per-target probes to ~10/h — still useful but bounded. Phase 12 may add edge-level reputation. |
| E | Elevation | Mint a valid access JWT for someone else | JWT HS256 with `JWT_SECRET` ≥32 B, fail-fast at boot. Claim shape `{sub, sid, fam, iat, exp}` + explicit `kid:"primary"` header for future rotation. ACCESS_TOKEN_TTL=900 s (15 min). | If `JWT_SECRET` is exfiltrated (AT-2 path A or B), attacker mints sessions for any user. Mitigation is reactive: rotation runbook is Phase 14; access-token revocation by epoch is Phase 03. |

### 14.4 Flow: `POST /auth/refresh`

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S | Spoofing | Use somebody else's refresh token | `__Host-refresh` cookie (`HttpOnly` + `Secure` + `SameSite=Strict` + `Path=/` + no `Domain`) — same-origin-only, not exfiltrable to JS, not sendable cross-site. Token raw is base64url(32 random bytes); persisted as BLAKE2b-256 hash only. | If a same-origin XSS lands (CSP failure + dep compromise), an attacker can't read the cookie but can issue a refresh from the user's browser — bounded by token rotation (any out-of-order use trips the family-revoke). |
| T | Tampering | Modify cookie value | Server lookup by hash; mismatched hash → 401 E1001. | None. |
| R | Repudiation | Disputed refresh | `auth.refresh.{ok,fail,reuse_detected}` audit events (Plan 02-08 + 02-09). | Phase 10 hash-chain pending. |
| I | Information disclosure | Cookie leak via TLS, browser, or proxy | TLS 1.2+; `__Host-` prefix + `Secure` enforced by browser; Pino redacts `req.headers.cookie` + `res.headers['set-cookie']` (Plan 02-09). | **Same-origin assumption is LOAD-BEARING** — see §16. If subdomain routing is ever introduced (`alice.pass.runadev.com`), `__Host-` MUST be dropped to a `__Secure-` cookie + explicit `Domain=`, which weakens scoping. Phase 13 hardening item. |
| D | DoS | Refresh flood | `refresh-ip` 60/IP/min throttler. | None practical. |
| E | Elevation | Token reuse / replay → mint a fresh session for an attacker AND keep the legit user logged in | **Single-use rotation with family-revoke on reuse**: rotation is one Drizzle tx with `SELECT … FOR UPDATE`; `used_at IS NOT NULL` → `UPDATE user_sessions SET revoked_at = now() WHERE family_id = $f AND revoked_at IS NULL` inside the same tx + emit `auth.refresh.reuse_detected` + 401 E1005. **Concurrent rotation race verified** in 02-08 E2E: `Promise.all([refresh, refresh])` returns exactly `[200, 401]` — `FOR UPDATE` serialises, loser sees `used_at IS NOT NULL` → reuse path → fail-closed and family-wide revocation. | None at the protocol layer. Open: access-token revocation propagation is bounded by ACCESS_TOKEN_TTL (15 min) — Phase 03 session-epoch closes this gap. |

### 14.5 Flow: `POST /auth/logout`

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S/T/R | (combined) | Forged logout / disputed logout | Logout is idempotent: no cookie still returns 200 + clears cookie; valid cookie revokes its family via `revokeFamilyByToken`; emits `auth.logout` audit event. | None. |
| I | Information disclosure | Client retains cleartext keys after logout | **Client-side wipe is enforced**: `keyStore.wipe()` zero-overwrites every Uint8Array; access-token-store wiped; logout button **always wipes locally** even if API call fails (defence in depth — Plan 02-11). | Browser memory residency post-wipe is OS-dependent; documented limit. |
| D | DoS | Logout spam | `logout-ip` 60/IP/min throttler. | None. |
| E | Elevation | "Logout-all-sessions" missing → an attacker with a stolen refresh on a separate device stays logged in after victim logs out on theirs | **Logout-all is DEFERRED to Phase 03** (REQ-AUTH-004). Currently logout revokes only the active token's family. | DOCUMENTED RESIDUAL. Operator runbook should include "rotate `JWT_SECRET`" as the v1 nuclear option. |

### 14.6 Flow: `GET /me`

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S | Spoofing | Access `/me` without a session | `JwtAuthGuard` on the route; returns 401 uniform on no/expired/garbage token. | None. |
| T | Tampering | Manipulate response shape to leak fields | **Response body shape LOCKED** at `MeResponseSchema = z.object({id, email, createdAt, argon2Params}).strict()`; service calls `.parse(out)` so any forbidden field that ever slips in throws to `SERVER_INTERNAL` (defence-in-depth against schema-evolution leaks — Plan 02-09). | None. |
| R | Repudiation | n/a (read-only) | — | — |
| I | Information disclosure | Leak server-side secrets via /me | The locked schema is the structural firewall: no `argon2_secret_key_hash`, no `wrapped_*`, no `recovery_hmac` can ever serialise. | None at the response layer. |
| D | DoS | /me flood | `me-user` 100/user/min throttler (user-keyed, post-JWT). | None. |
| E | Elevation | n/a (returns own profile only) | — | — |

### 14.7 Flow: `GET /auth/params` (PUBLIC, unauthenticated)

> **This is the new pre-auth surface introduced in Plan 11.** It returns the **global** `argon2Params` AND the **global** `serverArgonSalt` so the client can compute its verifier locally before posting `/auth/login` — without first leaking which emails exist.

| # | Threat | Description | Mitigation | Residual |
|---|---|---|---|---|
| S | Spoofing | Attacker MITMs and substitutes weakened params/salt | TLS 1.2+; client integrity is bounded by what the bundle accepts (no client-side floor check yet — accepted, paired with server-side floor on signup). | Operator A2 could push a malicious bundle that ignores params (REQ-WEBSEC limit, AT-1 path B). |
| T | Tampering | Same as S above | Same. | Same. |
| R | n/a | — | — | — |
| I | Information disclosure | **Pre-auth disclosure of the global `serverArgonSalt`** | **LOAD-BEARING DECISION (STATE.md, Plan 11):** `serverArgonSalt` is treated as an **operator-pepper, not a per-user secret**. Per CRYPTO-STACK §2 it is intentionally not the only entropy in the verifier — the user's 128-bit `secret_key` carries the load. The response is **byte-identical for every caller** (no per-email branching, no `Vary` header on email), so anti-enumeration is preserved at this endpoint. **Mitigation level: ACCEPTED.** | If operator ever switches to per-user salts, this endpoint MUST stop returning a global salt or become authenticated; documented as Phase 13 review item. |
| D | DoS | Pre-auth flood to harvest params | `auth-params-ip` 100/IP/min throttler. | None practical. |
| E | n/a | — | — | — |

---

## 15. AT-5 (Phase 02 reframe): Adversary obtains a valid user session

> **Note vs M0 §9.5:** the M0 framing of AT-5 ("non-owner → owner inside a shared vault") is preserved verbatim above as the **Phase 07/08 attack tree** (re-read at Phase 07 gate). The Phase 02 reframe below is **session-level compromise** — the *means* by which most other goals (vault read, owner escalation, audit-log forge) are reached. Both trees coexist.

```
GOAL (AT-5, Phase-02 framing): Adversary holds a credential set that
                              authenticates as some user U for some
                              non-trivial window of time
│
├─ A. Stolen access token (15-min JWT)
│   ├─ Origin: stolen from victim's browser memory via dep-compromise XSS
│   │  (A4) OR malicious bundle pushed by operator (A2)
│   └─ Mitigations:
│       • ACCESS_TOKEN_TTL = 900 s — stolen token expires within 15 min
│       • Token in MEMORY ONLY (`accessTokenStore`); never localStorage,
│         never cookie — XSS surface is "live page only", not "any future page"
│       • Pino redacts Authorization headers — no log exfiltration vector
│   Verdict: **MITIGATED** (TTL bound + memory-only storage); residual is
│            the in-page XSS/operator-bundle window — fundamental to web crypto.
│
├─ B. Stolen refresh token (30-day, family-rotating)
│   ├─ Origin: cookie exfiltrated via cross-origin attack OR DB read
│   └─ Mitigations:
│       • `__Host-refresh` cookie (HttpOnly + Secure + SameSite=Strict +
│         Path=/ + no Domain) — not readable by JS; not transmittable
│         cross-site
│       • Single-use rotation: any second use of the same token revokes
│         the entire family (REQ-AUTH-005, Plan 02-08)
│       • DB stores BLAKE2b-256 hash only; raw token never persisted
│       • Concurrent rotation race verified by E2E: serialisation via
│         `FOR UPDATE`; loser fails closed and revokes family
│   Verdict: **MITIGATED** at the protocol layer; residual is same-origin
│            XSS (bounded — no JS read of cookie, only abuse from victim's
│            browser, and family-revoke fires on any out-of-order use).
│
├─ C. Credential stuffing (online brute-force of password+secret_key)
│   ├─ Origin: attacker has email list from breach + tries common passwords
│   └─ Mitigations:
│       • Two-secret model: even with the master_password, attacker still
│         needs the user's 128-bit secret_key — infeasible online
│       • Calibrated Argon2id (operator-tuned, server-floor-enforced)
│         imposes per-attempt CPU
│       • Two-axis rate-limit: 5/IP/min AND 10/email/h (Redis-backed,
│         shared across replicas)
│       • Anti-enumeration: byte-identical 401 + constant-time dummy
│         Argon2id on miss → cannot prune target list cheaply
│   Verdict: **MITIGATED** for any reasonable attacker; residual is
│            single-target persistence (target U over months) — bounded
│            but non-zero.
│
├─ D. Invite hijack (capture an invite code → become a NEW account, not an
│    existing one — adjacent goal but worth listing)
│   ├─ Origin: OOB channel leak (Signal screenshot, eavesdropped voice)
│   └─ Mitigations:
│       • Invite is a **bearer token** by design at v1 (single secret)
│       • Single-use: atomic tx + `redeemed_at` UPDATE WHERE NULL
│       • TTL: default 7 days
│       • HMAC-SHA256 binds (code, email, expiry); operator selects email
│         at issuance (binding is a server-side check, not client-claimed)
│   Verdict: **PARTIAL** at v1 — invite is bearer; a leak of the OOB
│            channel = an adversary signs up. SMTP delivery + email-binding
│            is Phase 07; until then the OOB channel quality IS the security.
│
├─ E. Client-side malware (RAT, keylogger, browser extension)
│   ├─ Origin: victim's device compromised
│   └─ Mitigations: NONE in scope. Out-of-scope per §1 adversary profile.
│   Verdict: **RESIDUAL** — documented limit; no v1 control closes this.
│
├─ F. Phishing (look-alike origin captures master_password + secret_key)
│   ├─ Origin: classic phishing email/SMS leading to attacker domain
│   └─ Mitigations at Phase 02:
│       • secret_key UX deters: it is a printed 16-B Crockford-base32
│         string in the Emergency Kit, not a memorisable phrase — users are
│         less likely to type it on a wrong site by reflex
│       • Anti-enumeration on /auth/login removes the "is this the right
│         site?" oracle (a wrong site can't even confirm the email exists
│         on the real one)
│   Verdict: **RESIDUAL at Phase 02 close.** WebAuthn (RP-ID-bound,
│            phish-resistant) closes this in Phase 03 (REQ-2FA-001).
│
└─ G. Backend compromise (operator A2, or A5 → A2-equivalent)
    ├─ Origin: VPS root, RCE, Dokploy admin breach
    └─ Mitigations:
        • End-to-end encryption: even with full DB read + JWT_SECRET, server
          CANNOT decrypt the user's vault — master_password + secret_key
          never reach the server
        • JWT_SECRET separate blast radius from SERVER_CHAIN_SECRET
          (different env-vars; rotation independent)
        • Audit chain detects post-compromise log rewrite ≤24 h after
          off-machine checkpoint (Phase 10 dependency)
    Verdict: **RESIDUAL** for *session forgery* (attacker can mint JWTs at
             will until JWT_SECRET rotation). **MITIGATED** for the more
             important goal of *plaintext vault read* — E2E holds.
             Reactive mitigation: operator runbook rotates JWT_SECRET +
             forces all-user re-login; impact bounded to the mint window.
```

**Leaf summary:**

| Leaf | Verdict | Owner of any residual closure |
|---|---|---|
| A — stolen access token | MITIGATED | — |
| B — stolen refresh token | MITIGATED | — |
| C — credential stuffing | MITIGATED | — |
| D — invite hijack | **PARTIAL** | Phase 07 (SMTP + email-binding hardening) |
| E — client-side malware | **RESIDUAL** | Out-of-scope per §1; user device hygiene |
| F — phishing | **RESIDUAL** | **Phase 03 (WebAuthn 2FA)** |
| G — backend compromise (session forgery) | **RESIDUAL** | **Phase 14 (JWT rotation runbook)**; further: HSM/KMS = v2 |

---

## 16. Cross-cutting load-bearing assertions added in Phase 02

The M0 list (§13 above) gains the following pinned assumptions. **Changing any of these REQUIRES re-running `threat-modeler`.**

**I. `GET /auth/params` returns a GLOBAL `serverArgonSalt`** (Plan 11; STATE.md "Load-bearing decisions" #4).
- This is **pre-auth disclosure of an operator pepper, not a per-user secret**.
- Anti-enumeration is preserved because the response body is **byte-identical for every caller** — no `Vary`, no email branching, no rate-limit fingerprint distinguishing emails.
- The verifier's secrecy load is carried by the user's 128-bit `secret_key` and the master_password's Argon2id work factor, NOT by salt secrecy.
- **Mitigation level: ACCEPTED** for v1.
- *Reverting condition:* if the project moves to per-user salts, this endpoint MUST become authenticated OR stop returning a global salt; otherwise an enumeration oracle opens up.

**II. `__Host-refresh` cookie + same-origin deployment** (Plan 11; STATE.md "Load-bearing decisions" #3).
- The cookie has **no `Domain`** attribute (mandatory under the `__Host-` prefix), `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`.
- The Phase 02 prod assumption is **single-origin `pass.runadev.com`** with Traefik path-routing (`/api/*` → API container, everything else → web container). This makes API + web genuinely same-origin in the browser, so the cookie's narrow scope is sufficient.
- **THIS MUST HOLD IN PROD.** If the operator ever switches to subdomain routing (e.g. `api.pass.runadev.com` + `pass.runadev.com`), the refresh flow **degrades**: `__Host-` would have to drop to `__Secure-` + an explicit `Domain=`, which weakens scoping by allowing the cookie to attach to siblings.
- *Phase 13 hardening review:* either (a) keep same-origin and document; (b) move to a CSRF-token + body-borne refresh model; (c) accept `__Secure-` + `Domain=` with a SameSite=Strict + CSRF defence-in-depth.

**III. `AAD per-user binder = SHA256(lower(email))`** (Plan 10; STATE.md "Load-bearing decisions" #2).
- Re-derived byte-identically at login (Plan 11). If the email-canonicalisation rule ever changes (e.g. trim Unicode normalisation), every existing wrap blob fails to unwrap and existing users are locked out.
- AAD label prefixes are FROZEN: `"sv:user-master:v1|"`, `"sv:user-recovery:v1|"`, `"sv:user-sign-sk:v1|"`, `"sv:user-kx-sk:v1|"`.

**IV. Timing-floor implementation is constant-time-Argon2id-on-miss, NOT setTimeout** (Plan 02-08; STATE.md "Load-bearing decisions" #5).
- Reverting to `setTimeout` would re-introduce a coarse timing oracle. This is a footgun if a future maintainer "simplifies" the login service.

**V. Family-revocation on refresh-token reuse** (Plan 02-08; STATE.md "Load-bearing decisions" #6).
- Removing the `revoke family inside the same tx as detection` semantic = race window for the legit user to be silently followed by an attacker. The `FOR UPDATE` serialisation is what makes this safe.

---

## 17. Updated top-priority threats post-Phase 02

The M0 top-10 (§12) is amended as follows:

| Δ | Item | New status |
|---|---|---|
| #5 (KDF downgrade) | Argon2id param downgrade at login | **MITIGATED** — server-floor + AAD-bind verified end-to-end (Plan 02-07/08). Drop from active list; revisit only on calibration drift. |
| #8 (account enumeration) | Login timing/error differential | **MITIGATED** — byte-identical 401 + constant-time dummy Argon2id; E2E byte-equal assertion in 02-12 sad-path. |
| (NEW) | **Phishing without WebAuthn** | **HIGH (likely × medium-impact-per-target)** — gated by Phase 03. Single largest open credential-loss vector at Phase 02 close. |
| (NEW) | **Invite hijack via OOB channel** | **MED (likely × medium impact)** — single-use + TTL bound the window; SMTP + email-binding is Phase 07. |
| (NEW) | **Same-origin assumption breaks under future subdomain routing** | **LOW now / HIGH if changed** — `__Host-` cookie + path-routing under `pass.runadev.com` MUST hold in prod. Phase 13 review item. |

The M0 top-10 items #1, #2, #3, #4, #6, #7, #9, #10 are unchanged.

---

## 18. Auditor cross-references & open notes

- **For `crypto-auditor` Phase 02:** §14.2 row T (AAD-bind), §14.3 row T (verifier params binding), §14.7 (pre-auth global salt acceptance). Confirm: `argon2Params` floor enforcement value is the actually-calibrated lower bound — operator runbook check.
- **For `auth-flow-auditor` Phase 02:** §14.3 row I (anti-enum via byte-identical envelope + constant-time dummy Argon2id; the dummy hash derivation should NOT be predictable across deployments — verify it's keyed by `JWT_SECRET`). §14.4 row E (concurrent-rotation race serialisation). §14.5 row E (logout-all-sessions DEFERRED — confirm the runbook documents JWT_SECRET rotation as the v1 nuclear option).
- **For `owasp-top10-auditor`:** §14.6 row T (locked `/me` schema with `.strict() + .parse()`). §14.4 row S (`__Host-` cookie attribute set verified by curl in 02-08). §16.II (same-origin invariant for the cookie).
- **For `input-validation-auditor`:** §14.2 row I (Zod `.strict()` rejects extra fields including secret-key/password leakage by accident). Every signup-body bytea length-checked at boundary.
- **For `rate-limit-dos-auditor`:** §14.1 D, §14.3 D, §14.4 D (the 9 named ceilings + Redis backing + fail-open-on-Redis-outage policy + `Retry-After` header).
- **Threat-modeler open notes for future phases:**
  - **Phase 03:** AT-5 leaf F (phishing) — re-verify WebAuthn closes this once REQ-2FA-001 lands.
  - **Phase 03:** AT-5 leaf A residual closure — session-epoch revocation (REQ-AUTH-004) shrinks the access-token-after-compromise window.
  - **Phase 07:** AT-5 leaf D (invite hijack) — revisit when SMTP + email-binding lands; the bearer-token framing should weaken to "bearer-on-channel-bound-to-email".
  - **Phase 10:** Several rows in §14 list "Phase 10 hash-chain pending" as the residual on R (repudiation) — once the hash-chain ships, those become MITIGATED.
  - **Phase 13:** §16.II same-origin review; §14.7 per-user-salt decision; AT-5b (M0 §9.5) pub-key TOFU.

*End of Phase 02 expansion (2026-05-02).*
