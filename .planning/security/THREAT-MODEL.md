# SimpleVault — Threat Model (STRIDE)

**Owner:** `threat-modeler` agent
**Last updated:** 2026-04-28 (initial scaffold; will be expanded by `threat-modeler` agent before each milestone)
**Status:** SCAFFOLD — full STRIDE per asset + attack trees pending Milestone 0 expansion

---

## 1. Context & Assumptions

### Adversary profile (assumed)

| Attribute | Value |
|---|---|
| Skill level | Web-skilled, motivated, with time |
| Resources | Single attacker or small group, no nation-state budget |
| Access | Internet-only by default; may compromise user email; may obtain leaked DB dump from third-party breach |
| Motivation | Financial (credential resale), targeted access to a specific user's vault, or operator extortion |
| Out of scope | Nation-state APT, hardware side-channels, physical access to user device, kernel-level supply-chain compromise |

### Trust boundaries

```
[ User device (browser) ]  ←—— TLS ——→  [ Caddy reverse proxy ]
                                                 │
                                          [ Next.js web ]
                                                 │
                                          [ NestJS API ]  ←——→  [ Postgres ]
                                                 │              [ Redis ]
                                          [ Operator (semi-trusted) ]
```

- **Trusted:** User device (assumed un-compromised; if device is RAT'd, vault is compromised — accepted risk).
- **Semi-trusted:** Operator + server. May read all ciphertext + metadata. **Cannot** read plaintext (E2E). Audit log is tamper-evident, so operator tampering is **detectable** even if not preventable.
- **Untrusted:** Network (assume MITM possible until TLS), all input from clients.

### Crown jewels (assets)

1. **Vault contents** (credentials + page bodies) — confidentiality CRITICAL, integrity HIGH, availability MEDIUM
2. **Master passwords** (never leave client) — confidentiality CRITICAL
3. **Recovery codes** (never leave client; only hash on server) — confidentiality CRITICAL
4. **Audit log** — integrity CRITICAL (tamper-evident), confidentiality MEDIUM
5. **WebAuthn credentials** — integrity CRITICAL
6. **Session tokens (refresh)** — confidentiality HIGH

---

## 2. STRIDE per major flow (to be expanded by `threat-modeler`)

### Flow: Signup
- **Spoofing:** N/A (no identity to spoof yet); but invite-code-only signup limits enumeration
- **Tampering:** Argon2id params chosen client-side could be downgraded → server pins minimum
- **Repudiation:** Recovery code shown only once → user may claim "never received" → forced confirmation step
- **Information disclosure:** Account enumeration via signup endpoint → uniform errors + timing
- **DoS:** Signup spam → operator-issued invite codes throttle
- **Elevation:** N/A

### Flow: Login
- (to expand)

### Flow: Vault sharing — invite
- (to expand)

### Flow: Vault sharing — unanimous deletion
- (to expand)

### Flow: Page with double-lock
- (to expand)

### Flow: Master password reset with recovery code
- (to expand)

---

## 3. Attack trees (placeholders — to be drawn by `threat-modeler`)

- AT-1: Attacker reads another user's vault content
- AT-2: Attacker forces vault deletion against members' will
- AT-3: Attacker tampers audit log to hide their actions
- AT-4: Attacker reaches operator infra (VPS) and dumps DB
- AT-5: Attacker phishes a user's master password

---

## 4. Open questions

- Should we require WebAuthn 2FA for the **operator** account specifically (operator has elevated trust)?
- Cold storage of audit log merkle root: git tag, separate VPS, or external service?
- Disclosure policy if a CVE in a dependency is found in production?

---

## 5. Update protocol

`threat-modeler` agent regenerates this doc at the start of each milestone. Diff is reviewed by operator before milestone gate opens.
