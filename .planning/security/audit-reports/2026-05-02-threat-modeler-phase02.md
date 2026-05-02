# threat-modeler — Phase 02 update (informational)

**Date:** 2026-05-02
**Agent:** `threat-modeler`
**Phase:** 02 — Auth + Crypto core
**Role:** **Informational** (per `.planning/security/AGENTS.md` — does NOT block the gate; the 5 blocking auditors hold gate authority).
**Result:** `THREAT-MODEL.md` updated. No findings filed in `FINDINGS.md`.

---

## What changed in `.planning/security/THREAT-MODEL.md`

Appended four new sections **after** the M0 baseline (sections 1–13 preserved verbatim — no rewrite):

| Section | Content |
|---|---|
| **§14 — Phase 02 STRIDE per data flow** | Six STRIDE tables, one per shipped endpoint: `POST /invite/redeem`, `POST /auth/signup`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /me`, plus `GET /auth/params` (the new pre-auth surface from Plan 11). Each row carries threat → description → mitigation in shipped Phase-02 code → residual risk. |
| **§15 — AT-5 reframe (Phase 02 framing)** | Attack tree rooted at "Adversary obtains a valid user session". Seven leaves: stolen access token, stolen refresh token, credential stuffing, invite hijack, client-side malware, phishing, backend compromise. Each leaf marked **MITIGATED / PARTIAL / RESIDUAL** with closure owner. Coexists with M0 §9.5 (which is now treated as the Phase 07/08 attack tree on owner-role escalation; both framings preserved). |
| **§16 — Cross-cutting load-bearing assertions added in Phase 02** | Five new pinned assumptions (numbered I–V) extending M0 §13: pre-auth global `serverArgonSalt` ACCEPTED; `__Host-` cookie + same-origin requirement; AAD per-user binder = `SHA256(lower(email))`; constant-time-Argon2id timing floor (NOT setTimeout); family-revocation transactional semantics. |
| **§17 — Updated top-priority threats post-Phase 02** | M0 #5 (KDF downgrade) and #8 (account enumeration) flipped to MITIGATED. Three NEW entries: phishing-without-WebAuthn (HIGH; gated by Phase 03), invite hijack via OOB channel (MED; gated by Phase 07), same-origin invariant for `__Host-` cookie (LOW now / HIGH if ever broken). |
| **§18 — Auditor cross-references & open notes** | Per-auditor pointers into §14 rows + open follow-ups for Phases 03 / 07 / 10 / 13. |

The M0 baseline (sections 1–13) is **untouched**. The Phase 02 expansion is purely additive.

---

## Top-3 residual risks worth flagging to the operator

1. **Phishing without WebAuthn** — leaf F of AT-5 reframe. At Phase 02 close the only deterrents are (a) the two-secret model (the printed Crockford-base32 `secret_key` is not memorisable, lowering reflex-typing on look-alike domains) and (b) the anti-enumeration on `/auth/login` removing the "is this the real site?" oracle. **WebAuthn (REQ-2FA-001) in Phase 03 is the closure.** Until Phase 03 ships, a successful phishing campaign against a single user yields full session-mint capability.
2. **Invite hijack via OOB channel leak** — leaf D of AT-5 reframe, marked PARTIAL. The invite is a single-secret bearer token at v1 (operator delivers via Signal / in-person / OOB email). Single-use + 7-day TTL + HMAC-binding to email ARE in place server-side, but if the OOB delivery channel is intercepted (Signal screenshot, voice eavesdrop), an attacker can bootstrap a real account. SMTP delivery + email-channel-binding is Phase 07. **Operator runbook should explicitly call out "OOB channel quality IS the security at v1".**
3. **`__Host-refresh` cookie + same-origin invariant** — assertion §16.II. Phase 02 deployment relies on Traefik path-routing all of `pass.runadev.com` to the same origin; the cookie has **no `Domain`** by mandate of the `__Host-` prefix. If the operator ever switches to subdomain routing (e.g. `api.pass.runadev.com`), the refresh flow degrades and the cookie scoping weakens. Documented in `docs/operator/DOKPLOY-DEPLOY.md` per Plan 02-12 — verify pre-cutover that Traefik routes are path-based, not host-based.

Honourable mention: **logout-all-sessions is deferred to Phase 03** (REQ-AUTH-004). At Phase 02 close, the v1 "kick everyone off" lever is `JWT_SECRET` rotation. The Phase 14 cutover runbook should treat this as a known operational gap, not a blocker.

---

## Cross-auditor flags

No genuinely critical issues spotted that warrant escalation to a blocking auditor. The Phase-02 implementation as documented in `02-PHASE-SUMMARY.md` lines up coherently with the M0 threat model; the new attack surface is well-mitigated where mitigation was claimed.

Soft pointers (NOT findings — courtesy notes for the blocking auditors):

- **`auth-flow-auditor`** — confirm in `apps/api/src/auth/login/login.service.ts` that the `DUMMY_HASH` derivation is keyed by `JWT_SECRET` (so it's deployment-unique and not a deterministic constant across SimpleVault installs). Per 02-08 SUMMARY this is the case (`SHA-256(versioned-label ‖ JWT_SECRET)`); just worth a code-eye to confirm against drift.
- **`crypto-auditor`** — the AAD label prefix scheme (`"sv:user-master:v1|"` etc.) is now a versioned wire format; any future change is a forward-compat break. Worth one explicit grep across the crypto package + signup/login services to confirm there's a single source-of-truth constants module per Plan 11's "shared `aad-labels.ts`" hand-off recommendation.
- **`rate-limit-dos-auditor`** — the **fail-OPEN on Redis storage outage** decision (Plan 02-09) is operationally pragmatic but is itself a residual: a clever DoS against Redis disables all rate limiting. Already documented in 02-09 SUMMARY; flag for confirmation that the warn-log + structured event reaches the operator's alerting path (Phase 14 monitoring).

None of the above warrant a `FINDINGS.md` entry. If any blocking auditor wants to turn one into a finding, the threat-model rows in §14 are the cross-reference.

---

## File touched

- `.planning/security/THREAT-MODEL.md` — appended sections §14–§18 (Phase 02 expansion). M0 sections 1–13 unchanged.

## Files NOT touched

- `.planning/security/FINDINGS.md` (per role mandate — informational only).
- `.planning/security/AUDIT-LOG.md` (the gate-running auditors append there).
- Any source under `apps/`, `packages/`, `migrations/` (read-only).

---

*Report path:* `.planning/security/audit-reports/2026-05-02-threat-modeler-phase02.md`
