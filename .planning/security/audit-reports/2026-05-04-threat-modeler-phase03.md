# threat-modeler — Phase 03 update (informational)

**Date:** 2026-05-04
**Agent:** `threat-modeler`
**Phase:** 03 — 2FA (WebAuthn + TOTP) + session management
**Role:** **Informational** (per `.planning/security/AGENTS.md` — does NOT block the gate; the 4 blocking auditors at this gate hold gate authority).
**Result:** `THREAT-MODEL.md` updated. No findings filed in `FINDINGS.md`.

---

## What changed in `.planning/security/THREAT-MODEL.md`

Appended a Phase 03 expansion **after** §18 (Phase 02). M0 sections 1–13 and Phase-02 sections 14–18 preserved verbatim — purely additive.

| Section | Content |
|---|---|
| **§17.1 — Phase 03 transitions** | Records three §17 transitions agreed in `03-INDEX.md` Security gate row: (1) phishing-without-WebAuthn HIGH → MITIGATED-FOR-WEBAUTHN-USERS / RESIDUAL-FOR-TOTP-ONLY; (2) AT-5 leaf A (stolen access token) MITIGATED → MITIGATED-WITHIN-EPOCH-LATENCY; (3) AT-5 leaf F (phishing) RESIDUAL → MITIGATED-FOR-WEBAUTHN-USERS / RESIDUAL-FOR-TOTP-ONLY. Adds a new AT-5 leaf **H — TOTP secret extraction from compromised browser** (RESIDUAL — same class as A4 client-malware in §15). Refreshed leaf-summary table for Phase 03 close. |
| **§19 — Phase 03 STRIDE per data flow** | Eight STRIDE tables, one per shipped flow: 19.1 `/auth/login` step-up issuance, 19.2 WebAuthn enrol, 19.3 WebAuthn step-up, 19.4 TOTP enrol, 19.5 TOTP verify, 19.6 `/2fa/methods` list+remove (incl. removal-guard), 19.7 `/sessions` list+revoke+revoke-all, 19.8 cross-cutting 2FA-removal guard. Each row carries threat → description → mitigation in shipped Phase-03 code → residual risk. |
| **§19.9 — Cross-cutting load-bearing assertions added in Phase 03** | Five new pinned assumptions (numbered VI–X) extending §16: VI session-epoch column, VII WebAuthn RP-ID = pass.runadev.com (apex), VIII step-up vs access JWT mutual-exclusion via `purpose` claim, IX TOTP-browser-only barrel parity, X 2FA-removal guard wiring + Phase-07 stub function. |
| **§19.10 — Auditor cross-references & open notes (Phase 03)** | Per-auditor pointers into §19 rows + open follow-ups for Phases 07 / 10 / 13 / 14. |

---

## §17 transitions made

- **Phishing-without-WebAuthn**: HIGH → **MITIGATED-FOR-WEBAUTHN-USERS / RESIDUAL-FOR-TOTP-ONLY-USERS**. Residual = users who never enrol any 2FA method or who enrol only TOTP. UX label primacy on `/settings/security` (Truth 16, Key Link 12) is part of the control.
- **AT-5 leaf A (stolen access token, 15-min JWT)**: MITIGATED → **MITIGATED-WITHIN-EPOCH-LATENCY**. `users.session_epoch` column + JWT `epoch` claim + `JwtAuthGuard` cached check + cache-bust on revoke. Worst-case window after revoke = next-request latency. Closes Phase-02 deferred REQ-AUTH-004.
- **AT-5 leaf F (phishing)**: RESIDUAL → **MITIGATED-FOR-WEBAUTHN-USERS / RESIDUAL-FOR-TOTP-ONLY-USERS**. WebAuthn RP-ID + `expectedOrigin` binding closes the leaf for passkey-enrolled users; TOTP remains phishable (6-digit code is not origin-bound).
- **NEW leaf H — TOTP secret extraction from compromised browser**: documented as **RESIDUAL** (A4-class client-malware). No v1 control closes it; reactive lever is user-initiated `DELETE /2fa/methods/:id` + re-enrol after suspected device compromise.

---

## §19 STRIDE entries added (one-line per flow)

- **19.1 /auth/login → step-up issuance** — server-authoritative branch on 2FA presence (post-1FA only); step-up shape distinguishable from full-session shape ONLY after Argon2id verify passes.
- **19.2 WebAuthn enrol (begin/finish-register)** — atomic `DELETE … RETURNING` consume, `expectedRPID`/`expectedOrigin` passed explicitly to `@simplewebauthn/server` v11, attestation = none accepted at ≤50-user scale.
- **19.3 WebAuthn step-up (begin/finish-auth)** — RP-ID + origin binding closes phishing leaf F for passkey users; counter-regression check rejects clones; `Require2FAStepUpGuard` gates the begin endpoint to post-1FA only.
- **19.4 TOTP enrol** — server NEVER sees plaintext (browser-only barrel + parity test); AAD label `"sv:user-totp:v1|"` + per-user `SHA256(lower(email))` binder; enrolment code burned at insert via seeded `last_used_step`.
- **19.5 TOTP verify** — TOTP IS PHISHABLE (documented residual, leaf F for TOTP-only users); atomic CAS replay guard (`UPDATE … WHERE last_used_step < $cs RETURNING`) closes single-code replay; brute-force bounded by two-axis throttler.
- **19.6 /2fa/methods list + remove + removal-guard** — uniform 404 (NOT 403) on cross-user; removal-guard 409 `AUTH_2FA_REMOVAL_BLOCKED` when removing last method while shared-vault dependency true (stub returns false at Phase 03; integration test stubs `() => true` to assert 409 path).
- **19.7 /sessions list + revoke + revoke-all** — `ipHashB64Prefix` 6-char only; uniform 404 on cross-user; revoke-all bumps `users.session_epoch` and family-revokes refresh cookies — current request returns 200 before epoch takes effect; next request fails epoch check ≤ next-request latency.
- **19.8 Cross-cutting 2FA-removal guard (E only row)** — bridge invariant to Phase 07: integration test stubbing `userHasSharedVaultDependency(() => true)` is the regression sentinel for the guard wiring + decorator presence.

---

## New residual risks identified

1. **AT-5 leaf H — TOTP secret extraction from compromised browser** (NEW). Same class as A4 client-malware (§15 leaf E). WebAuthn-only users are not exposed because the private key is hardware-bound; this leaf is specific to TOTP-enrolled users with a compromised browser session. **Reactive lever:** user-initiated `DELETE /2fa/methods/:id` + re-enrol after suspected device compromise. Operator runbook should call this out at Phase 14.
2. **Removal-guard wiring drift hazard** (§19.8). If a Phase-07 maintainer flips `userHasSharedVaultDependency` to live impl AND simultaneously removes the integration test, the guard's regression sentinel disappears. Mitigation: §19.9 Assertion X pins both the function signature and the test as load-bearing.
3. **WebAuthn RP-ID drift** (§19.9 Assertion VII; Key Link 1). Changing `WEBAUTHN_RP_ID` is a data-migration event; every existing passkey breaks. Same direction as the §16.II same-origin invariant — both invariants fail together if the operator ever moves to subdomain routing.

Honourable mention: **§19.5 TOTP-phishable** is the largest open credential-loss vector for any user who enrols TOTP without also enrolling WebAuthn. The UX nudge on `/settings/security` (passkey "Recommended — phishing-resistant", TOTP "can be entered into a phishing site") is the only mitigation. **Operator runbook should document "encourage all users to enrol a passkey, not just TOTP" as a v1 hardening posture.**

---

## Cross-auditor flags

No genuinely critical issues spotted that warrant escalation to a blocking auditor. The Phase-03 implementation as documented in `03-VERIFICATION.md` (20/20 structural truths verified) lines up coherently with the Phase 02 + M0 threat model; the new attack surface is well-mitigated where mitigation was claimed.

Soft pointers (NOT findings — courtesy notes for the 4 blocking auditors):

- **`auth-flow-auditor`** — confirm in `apps/api/src/auth/login/login.service.ts:137–161` that the 2FA-counts query runs ONLY after the 1FA Argon2id-verify path completes successfully (i.e. NOT before, which would create a pre-1FA enumeration oracle on "is this user 2FA-enrolled"). Per `03-08-SUMMARY.md` this is the case; just worth a code-eye to confirm against drift.
- **`crypto-auditor`** — per `03-VERIFICATION.md` notes, only refs to `master_DEK`/`master_kek` under `apps/api/src` are (a) Pino redaction keys in `app.module.ts` and (b) docstring assertions in `step-up-material.controller.ts`. Worth a confirming `grep -r "master_DEK\|master_kek" apps/api/src` returning only those expected hits.
- **`access-control-auditor`** — §19.6 row S + §19.7 row S both rely on the **uniform 404 NOT 403** anti-enumeration rule for cross-user `DELETE /2fa/methods/:id` and `DELETE /sessions/:id`. A casual maintainer "improving error messages" could regress this to 403; worth one E2E spec asserting the 404 status byte-exact (per `03-VERIFICATION.md` Truth 12 evidence at `sessions.controller.ts:79`).
- **`owasp-top10-auditor`** — §19.4 row I (TOTP QR + provisioning URL never crosses the wire from server) is by-design but the QR-screenshot-to-cloud-sync path is a user-side risk. Out-of-scope per §1 adversary profile, but worth a copy-block on the enrolment screen ("don't screenshot this code") in a future Phase 13 UX pass.

None of the above warrant a `FINDINGS.md` entry. If any blocking auditor wants to turn one into a finding, the threat-model rows in §19 are the cross-reference.

---

## Files touched

- `.planning/security/THREAT-MODEL.md` — appended §17.1 (Phase 03 transitions + new AT-5 leaf H), §19 (Phase 03 STRIDE per data flow, 8 sub-flows), §19.9 (cross-cutting assertions VI–X), §19.10 (auditor cross-references). M0 §1–§13 and Phase 02 §14–§18 unchanged.

## Files NOT touched

- `.planning/security/FINDINGS.md` (per role mandate — informational only).
- `.planning/security/AUDIT-LOG.md` (the gate-running auditors append there).
- Any source under `apps/`, `packages/`, `migrations/` (read-only).

---

*Report path:* `.planning/security/audit-reports/2026-05-04-threat-modeler-phase03.md`
