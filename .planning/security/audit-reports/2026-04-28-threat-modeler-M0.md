# Threat Modeler — M0 Baseline Audit Report

**Date:** 2026-04-28
**Agent:** `threat-modeler`
**Verdict:** **INFORMATIONAL** — does not block Phase 01 gate
**Milestone:** M0 (Foundations)
**File extended:** `.planning/security/THREAT-MODEL.md`

---

## What changed in the threat model

The prior `THREAT-MODEL.md` was a SCAFFOLD: 6 crown-jewel assets, an ASCII trust-boundary box, an adversary-profile table, STRIDE entries for the Signup flow only (others were `(to expand)` placeholders), and 5 attack-tree titles with no bodies. This M0 pass **extended (did not overwrite)** the file. The original sections 1–5 were preserved verbatim; M0 content was added as sections 6–13:

1. **§6 — Asset inventory (20 entries)** — replaces the 6-entry crown-jewel summary with a full C/I/A-tiered table covering: master password, secret_key, recovery phrase, key hierarchy (master_KEK, master_DEK, user_KEK, vault_DEK, page_DEK), encrypted vault items, per-user public keys, `SERVER_CHAIN_SECRET`, Ed25519 audit-checkpoint key, JWT signing secret, audit log, Postgres DB, container FS, TLS private key, refresh tokens, WebAuthn credentials, invite codes, backups, CI/CD secrets.

2. **§7 — Trust boundaries (T1..T7)** — replaced the 4-line ASCII diagram with 7 explicit numbered boundaries (Internet→Edge, Edge→App, App→Datastore, App↔Operator, App→Off-site backups, Off-machine checkpoint, Inter-tenant cryptographic boundary), each with semantics + trust-direction analysis.

3. **§8 — Adversary models A1..A5** — five formally-documented adversaries (network MITM, compromised operator, malicious shared-vault member, supply-chain dep author, remote 0-day attacker) with capabilities / goals / mitigations / residual-risk for each.

4. **§9 — Attack trees AT-1..AT-5** — drafted with goal at root + 2–4 sub-paths + leaf preconditions for each. Notably:
   - AT-1 (steal vault) has 4 sub-paths (client compromise / served-frontend tamper / cryptanalysis / personal-vault sharing trick).
   - AT-2 (steal server secret) has 4 sub-paths (Dokploy UI / API RCE / backup / CI exfil).
   - AT-3 (audit forgery) maps cleanly onto AT-2 path C as a downstream attack.
   - AT-4 (bypass unanimous delete) and AT-5 (member→owner privesc) document the **pub-key swap** attack as v1-OPEN — flagged for Phase 07/13.

5. **§10 — STRIDE skeleton (12 modules × 6 columns)** — every module gets a non-empty cell or explicit "N/A". Modules covered: Auth, Crypto core, Sessions, Personal vault, Pages/double-lock, Shared vaults, Audit chain, Recovery, Web app surface, API surface, Dokploy infra, Backups.

6. **§11 — Phase 01 controls map** — 11 controls landed in M0 mapped to which threats they close / partially-close / leave open. Confirms: foundations close XSS-via-inline-injection, direct external DB access, A1 cross-origin attacks, naïve typosquats, known-CVE base images, partial-migration runtime states. Foundations DO NOT close: A4 sleeper deps, A2 frontend-bundle-tamper, REQ-WEBSEC-002/003 (Phase 12), and all of Phases 02+.

7. **§12 — Top-10 priority threats** — sorted by likelihood × impact, owner-mapped. Top 3 are (1) operator-malicious-bundle (accepted, doc'd in operator runbook), (2) `SERVER_CHAIN_SECRET` exfil → audit forgery, (3) pub-key-swap silent re-wrap.

8. **§13 — Load-bearing assumptions** — 8 baseline assumptions (A–H) that, if changed, REQUIRE re-running this agent. These extend the 10 STATE.md decisions with M0-specific items: pub-key TOFU-pinning is a known v1 gap; `backend` network must remain `internal: true`; off-machine Ed25519 checkpoint is the *only* tamper-detection beyond a 24h window.

---

## Load-bearing assumptions newly pinned at M0

(Re-stated for visibility. Full text in §13 of the threat model.)

- **Assumption A (Two-secret model)** — REQ-CRYPTO-003 confirmed; reverting invalidates AT-1 path C analysis.
- **Assumption B (Off-machine Ed25519 checkpoint)** — without it, AT-3 path C succeeds undetectably for an operator-class adversary.
- **Assumption D (`backend` `internal: true`)** — without it, A5 RCE → arbitrary outbound exfil becomes trivial.
- **Assumption E (Pub-key TOFU is NOT v1)** — known gap; `crypto-auditor` MUST re-evaluate at Phase 07.
- **Assumption F (Dokploy env-vars = secret store)** — single point of secret compromise; if deploy target changes, re-threat-model.

---

## Findings/recommendations for downstream agents

These are NOT findings against Phase 01 (informational only) but are forward-looking notes the named agents should pick up:

1. **`crypto-auditor` @ Phase 07:** Decide whether to add per-user public-key TOFU pinning + member-list signature to close AT-5 path C, OR explicitly accept-with-doc.
2. **`security-auditor` @ Phase 02:** Verify REQ-AUTH-003 (uniform login response + dummy Argon2id) is implemented and timing-tested. (Top-10 #8.)
3. **`security-auditor` @ Phase 03:** JWT signing secret rotation runbook + ensure JWT secret and `SERVER_CHAIN_SECRET` are stored as separate Dokploy env-vars (different blast radii). (Top-10 #6.)
4. **`security-auditor` @ Phase 09:** TOCTOU review of vote-tally code path (AT-4 D).
5. **`web-security-auditor` @ Phase 12:** Implement REQ-WEBSEC-003 double-submit CSRF. M0 only ships SameSite=Strict cookies and no CSRF token yet.
6. **`infra-deployment-auditor` @ Phase 14:** Verify `command="rrsync -wo …"` is in place on backup target's `authorized_keys` (assumption that closes AT-style backup write-loop attack).
7. **`dependency-supply-chain-auditor` (weekly cron):** Augment `pnpm audit` with Socket.dev or equivalent before Phase 13 — `pnpm audit` alone does not catch sleeper deps (A4 residual risk).
8. **Operator decision pending:** off-machine audit-checkpoint repo location MUST be decided before Phase 10 (Assumption B is load-bearing on this existing).

---

## Files modified by this run

- `.planning/security/THREAT-MODEL.md` — extended (sections 6–13 added; sections 1–5 preserved)
- `.planning/security/audit-reports/2026-04-28-threat-modeler-M0.md` — this report (new)

Files NOT modified (per agent instructions):
- `.planning/security/FINDINGS.md`
- `.planning/security/AUDIT-LOG.md`

---

## Verdict

**INFORMATIONAL** — establishes the M0 baseline that subsequent auditors (security-auditor, crypto-auditor, web-security-auditor, infra-deployment-auditor, dependency-supply-chain-auditor) anchor their phase-by-phase work to. Does not block Phase 01.
