# SimpleVault — Security Auditor Audit Log

Append-only log of every security auditor run, its scope, and its verdict.

**Format per entry:**

```
## YYYY-MM-DD — [agent-name] — Phase XX

**Scope:** files/modules/flows audited
**Method:** what the agent did
**Findings:** count by severity (Critical / High / Medium / Low / Info)
**Verdict:** PASS / FAIL / PASS-WITH-CONCERNS
**Findings filed:** FINDING-IDs in FINDINGS.md
**Next review:** when this should be re-run
```

---

## 2026-04-28 — threat-modeler — Milestone 0 baseline (Phase 01 gate)

**Scope:** Whole-system M0 baseline (assets, trust boundaries, A1..A5 adversary models, full STRIDE skeleton across 12 modules, AT-1..AT-5 attack-tree drafts, Phase 01 controls map).
**Method:** Reviewed PROJECT.md, REQUIREMENTS.md, ROADMAP.md, STATE.md (load-bearing decisions), research/* outputs, and the codebase as it stands at Phase 01 close.
**Findings:** Critical 0 / High 0 / Medium 0 / Low 0 / Info 0 (informational agent, does not file findings)
**Verdict:** PASS-WITH-CONCERNS (informational; does not gate phase)
**Findings filed:** none (informational); see `.planning/security/THREAT-MODEL.md` (M0 Baseline 2026-04-28) for the threat model itself
**Top threats now load-bearing:** operator-pushed-malicious-frontend (A2/AT-1), SERVER_CHAIN_SECRET exfil → audit-log forgery within 24h checkpoint window (AT-2/AT-3), pub-key-swap by operator on shared-vault re-wrap (A2/AT-5 path C — known v1 gap, owned by Phase 07/13)
**Next review:** start of Milestone 1 (after Phase 02 lands auth+crypto core).

---

## 2026-04-28 — infra-deployment-auditor — Phase 01

**Scope:** docker-compose.yml, apps/api/Dockerfile, apps/web/Dockerfile, .dockerignore (root + per-app), .env.example, app-layer security headers (apps/web/middleware.ts + apps/api/src/main.ts helmet/CORS), CI scan hooks, migration safety (apps/api/scripts/migrate-then-start.sh).
**Method:** Static analysis (grep + read), no runtime execution.
**Findings:** Critical 0 / High 2 / Medium 6 / Low 4 / Info 13
**Verdict:** PASS-WITH-CONCERNS (per phase-gate rubric: 2 High = BLOCKING until closed)
**Findings filed:** FINDING-0005, FINDING-0006
**Report:** `.planning/security/audit-reports/2026-04-28-infra-deployment-auditor-phase01.md`
**Top issues:** postgres + redis services in docker-compose.yml missing `cap_drop: [ALL]` — every other service drops all caps; trivial 4-line YAML fix.
**Next review:** Phase 14 (production deploy gate); also any change to docker-compose, Dockerfiles, or app-layer security middleware.

---

## 2026-04-28 — dependency-supply-chain-auditor — Phase 01

**Scope:** All package.json files (root, apps/*, packages/*), pnpm-lock.yaml, .npmrc, .github/dependabot.yml, postinstall hooks in dep tree, `pnpm audit --audit-level=high --prod`, workspace-protocol consistency, version pinning hygiene.
**Method:** Static + `pnpm install --frozen-lockfile` + `pnpm audit`. Read-only.
**Findings:** Critical 2 / High 7 / Medium 4 / Low 3 / Info 7
**Verdict:** **FAIL — phase BLOCKED** until Critical/High findings reach VERIFIED-CLOSED.
**Findings filed:** FINDING-0001, FINDING-0002, FINDING-0003, FINDING-0004 (consolidated; the auditor's 7 Highs roll up into FINDING-0003 + FINDING-0004 + 2 Highs in next@<15.5.15 already inside FINDING-0001/0002).
**Report:** `.planning/security/audit-reports/2026-04-28-dependency-supply-chain-auditor-phase01.md`
**Top issues:**
- next@15.1.0 — 2 Critical CVEs (RCE + middleware auth bypass) → bump to ^15.5.15
- drizzle-orm@0.38.4 — SQL-injection-via-identifier → bump to ^0.45.2
- multer@2.0.2 (transitive of @nestjs/platform-express@10.4.22) — 3 High DoS CVEs → upgrade @nestjs/* to ^11 OR pnpm.overrides multer >=2.1.1

Lockfile clean, workspace-protocol use consistent, no typosquats, hygiene solid — failure is purely outdated CVE-bearing versions, all upstream-patched.
**Next review:** after upgrades land — re-run this auditor to verify VERIFIED-CLOSED. Recurring weekly via Dependabot + cron-driven `pnpm audit` step in CI.

---

## 2026-04-28 — gsd-verifier — Phase 01 (initial)

**Scope:** 11 goal-backward truths from `01-INDEX.md`. Three-level structural verification (exists / substantive / wired) on every artifact, requirements coverage check (REQ-INFRA-001..003, REQ-WEBSEC-001/004), anti-pattern scan.
**Method:** grep + file checks + reading SUMMARY.md files as evidence corroboration (not as ground truth).
**Findings:** 1 truth gap (Truth 4) + 1 informational observation. Filed as FINDING-0007 (Low) and FINDING-0008 (Info).
**Verdict:** gaps_found (10/11 truths verified). The single failed truth is a literal-wording gap, not a functional gap — operator's actual goal (`docker compose up -d`) is fully met.
**Report:** `.planning/phases/01-foundations/01-VERIFICATION.md`
**Next review:** after closure of FINDING-0007 — re-verify Truth 4.

---

## 2026-04-29 — gsd-verifier — Phase 01 (re-verification)

**Scope:** Re-verify Truth 4 (`pnpm dev` schedules api+web) after FINDING-0007 closure; quick regression check on Truths 5-7, 9-11 after dep bumps.
**Method:** grep + file checks + `turbo run dev --dry=json`.
**Findings:** none new.
**Verdict:** **PASS — 11/11 truths verified.** Gap closed (Truth 4); no regressions from dep bumps.
**Findings filed:** none. FINDING-0007 → VERIFIED-CLOSED.
**Report:** `.planning/phases/01-foundations/01-VERIFICATION.md` (updated in place with re-verification frontmatter).
**Next review:** Phase 02 implementation.

---

## 2026-04-29 — infra-deployment-auditor — Phase 01 (re-run)

**Scope:** Verify FINDING-0005 + FINDING-0006 closure; regression check on docker-compose + Dockerfiles + app-layer headers.
**Method:** Static analysis + brief runtime healthcheck (`docker compose up -d postgres redis`).
**Findings:** Critical 0 / High 0 / Medium 0 (carried-over from 2026-04-28 unchanged) / Low 0 (carried-over) / Info 0.
**Verdict:** **PASS.** Both Highs VERIFIED-CLOSED. Postgres/redis come up healthy with `cap_drop:[ALL]` + minimal `cap_add` (postgres: SETUID/SETGID/DAC_READ_SEARCH/CHOWN/FOWNER; redis: SETUID/SETGID). `security_opt: no-new-privileges:true` on both.
**Findings filed:** none new. FINDING-0005 + FINDING-0006 → VERIFIED-CLOSED.
**Report:** `.planning/security/audit-reports/2026-04-29-infra-deployment-auditor-phase01-rerun.md`.
**Next review:** Phase 14 (production deploy gate); also any change to docker-compose, Dockerfiles, or app-layer security middleware.

---

## 2026-04-29 — dependency-supply-chain-auditor — Phase 01 (re-run + lodash closure)

**Scope:** Verify FINDING-0001..0004 closure; full `pnpm audit --prod --audit-level=high` re-run; check for new CVEs surfaced by the bumps.
**Method:** Lockfile inspection + `pnpm install --frozen-lockfile` + `pnpm audit`.
**Findings:** Critical 0 / High 1 (lodash — patch became available since 2026-04-28; filed as FINDING-0009 and closed within same gate cycle via `pnpm.overrides`) / Medium 4 prod (carry-over, below blocking threshold) / Dev-only Highs 2 (glob CLI command-injection + picomatch ReDoS via `@nestjs/cli@10.4.9` — non-blocking, will clear with NestJS 11 in Phase 02) / Low 3 dev / Info 7.
**Verdict:** **PASS.** Critical 0; production High 0 after lodash override (commit `ac55411`). All FINDING-0001..0004 + FINDING-0009 VERIFIED-CLOSED.
**Findings filed:** FINDING-0009 (closed same cycle).
**Report:** `.planning/security/audit-reports/2026-04-29-dependency-supply-chain-auditor-phase01-rerun.md`.
**Tech-debt tracked:** Two `pnpm.overrides` (multer + lodash) to remove during Phase 02 NestJS 11 upgrade. Dev-deps Highs (glob/picomatch via @nestjs/cli) acceptable for Phase 01; remediated by Phase 02.
**Next review:** Recurring weekly via Dependabot + cron-driven `pnpm audit` in CI; also re-run on next phase gate.

---

## 2026-05-04 — gsd-verifier — Phase 03 (initial)

**Scope:** 20 goal-backward truths from `03-INDEX.md`. Three-level structural verification (exists / substantive / wired) on every artifact, requirements coverage check, anti-pattern scan.
**Method:** grep + file checks + reading SUMMARY.md as evidence corroboration (not as ground truth).
**Findings:** 20/20 truths structurally verified; 4-auditor security gate explicitly deferred to dedicated runs; two operator checkpoints (Plan 10 T4 UX + Plan 12 T4 runbook) flagged for human verification.
**Verdict:** human_needed (structural complete; awaiting auditor + operator gates).
**Report:** `.planning/phases/03-2fa-sessions/03-VERIFICATION.md`
**Next review:** after auditor gate closure.

---

## 2026-05-04 — auth-flow-auditor — Phase 03

**Scope:** 2FA enrol leak (Truth 8), TOTP replay guard, WebAuthn counter regression, step-up token containment, removal-while-shared-vault, session-epoch revocation latency.
**Method:** Static read-only audit of `apps/api/src/twofa/`, `apps/api/src/auth/jwt/`, `apps/api/src/auth/login/`, `apps/api/src/sessions/`, plus web step-up flow.
**Findings:** Critical 0 / High 1 (FINDING-0031 — `revokeOne` did not bump `session_epoch`, contradicted Truth 12; **VERIFIED-CLOSED same gate cycle** by adding `bumpEpoch(userId)` after family-revoke + JSDoc fix tracked as FINDING-0034 also VERIFIED-CLOSED) / Medium 1 (FINDING-0032 `/2fa/totp/verify` IP-only throttler, OPEN deferrable) / Low 1 (FINDING-0033 step-up guard doesn't validate epoch claim, OPEN).
**Verdict:** **PASS** (post-closure; was PASS-WITH-CONCERNS pre-closure).
**Findings filed:** FINDING-0031 (HIGH, closed), FINDING-0032 (MED), FINDING-0033 (LOW), FINDING-0034 (INFO, closed).
**Report:** `.planning/security/audit-reports/2026-05-04-auth-flow-auditor-phase03.md` (with re-run section appended for 0031 closure).
**Cross-auditor concern:** access-control-auditor's PASS treated the missing bump as deliberate based on inline doc; auth-flow-auditor treated INDEX Truth 12 as ground truth. Resolution: INDEX is authoritative; code now matches INDEX.
**Next review:** after FINDING-0032 closure (defer-or-fix decision pending operator).

---

## 2026-05-04 — crypto-auditor — Phase 03

**Scope:** TOTP browser-only invariant (server grep clean), AAD label `"sv:user-totp:v1|"` + per-user binder `SHA256(lower(email))`, WebAuthn challenge entropy + atomic consume, `@simplewebauthn/server` v11 explicit RP-ID/origin, counter regression, step-up JWT signing key.
**Method:** Static read-only audit of `packages/crypto/src/totp.ts` + `apps/api/src/twofa/{webauthn,totp}/`, server-side `grep -rn "master_DEK|master_kek|computeTotpStep|verifyTotpCandidate"` under `apps/api/src/`.
**Findings:** Critical 0 / High 0 / Medium 0 / Low 1 (FINDING-0040 — client trusts server-supplied `encryptedSecretAad` instead of recomputing locally) / Info 2 (FINDING-0041 pino-redact `master_kek` grep noise; FINDING-0042 unset `engines` in `apps/api/package.json`).
**Verdict:** **PASS-WITH-CONCERNS** (matches Phase 02's bar).
**Findings filed:** FINDING-0040 (LOW), FINDING-0041 (INFO), FINDING-0042 (INFO). All OPEN, none blocking.
**Report:** `.planning/security/audit-reports/2026-05-04-crypto-auditor-phase03.md`.
**Server-side grep:** 6 hits, all classified as doc-strings or pino-redaction wildcards; no implementation references → invariant HOLDS.
**Next review:** Phase 04 / 07 vault-wrap audits.

---

## 2026-05-04 — owasp-top10-auditor — Phase 03

**Scope:** Systematic OWASP Top 10 (2021) pass with Phase-03 focus on A01 (access control), A02 (cryptographic failures — TOTP secret never reaches server), A07 (auth failures — uniform 401 on 2FA fail paths).
**Method:** Static read-only audit of `apps/api/src/twofa/`, `apps/api/src/sessions/`, `apps/api/src/auth/`, `apps/api/src/common/throttler.config.ts`, `apps/web/src/app/(authed)/settings/` and `apps/web/src/app/login/2fa/`.
**Findings:** Critical 0 / High 0 / Medium 0 / Low 1 (FINDING-0052 boot-time guard for `EXPOSE_TEST_ROUTES=1 && NODE_ENV=production`) / Info 4 (FINDING-0050 webauthn finish-auth status drift; FINDING-0051 `ParseUUIDPipe` 400-vs-404 on cross-user IDs; FINDING-0053 counter-regression doesn't logger.warn; FINDING-0054 pino redact list lacks new field names).
**Verdict:** **PASS-WITH-CONCERNS** (no Critical/High; all 5 informational).
**Findings filed:** FINDING-0050..0054.
**Report:** `.planning/security/audit-reports/2026-05-04-owasp-top10-auditor-phase03.md`.
**Per-category:** A01 PASS (every route scoped to `req.user.id` / `req.stepUp.sub`; cross-user → 404). A02 PASS (server grep clean of TOTP plaintext / RFC 6238 logic). A07 PASS (uniform 401 on TOTP verify, step-up purpose discriminator dual-guarded). A03/A04/A05/A08/A09 PASS. A06/A10 N/A.
**Next review:** Phase 04 OWASP delta.

---

## 2026-05-04 — access-control-auditor — Phase 03

**Scope:** First gate run. Owner-only listing/revoke (Truth 11/13), 404-not-403 anti-enumeration on `DELETE /sessions/:id` and `DELETE /2fa/methods/:id`, per-user (not per-session) session-epoch.
**Method:** Static read-only audit per-route (10 Phase-03 endpoints) of guard chain, owner-scope filters (`WHERE user_id = req.user.id`), cross-user behaviour, step-up token containment.
**Findings:** Critical 0 / High 0 / Medium 0 / Low 0 / Info 0.
**Verdict:** **PASS.**
**Findings filed:** none.
**Report:** `.planning/security/audit-reports/2026-05-04-access-control-auditor-phase03.md`.
**Note:** Initial PASS treated the missing `bumpEpoch` on `revokeOne` as deliberate based on inline JSDoc — this was overridden by auth-flow-auditor (FINDING-0031, INDEX as authoritative). Code now bumps the epoch; access-control posture unchanged (all routes still 404 anti-enumeration on cross-user).
**Next review:** Phase 04/07 sharing/wrapping; Phase 13 hardening.

---

## 2026-05-04 — threat-modeler — Phase 03

**Scope:** Update `THREAT-MODEL.md` for Phase 03 close — §17 transitions for AT-5 leaves A and F + phishing-without-WebAuthn, new leaf H (TOTP secret extraction from compromised browser), §19 STRIDE per Phase-03 data flow.
**Method:** Append-only edits to THREAT-MODEL.md preserving §1–§18 verbatim.
**Verdict:** Informational — does not block.
**Findings filed:** none (informational role).
**Report:** `.planning/security/audit-reports/2026-05-04-threat-modeler-phase03.md`.
**Key transitions:** AT-5 leaf A RESIDUAL → MITIGATED-WITHIN-EPOCH-LATENCY; AT-5 leaf F RESIDUAL → MITIGATED-FOR-WEBAUTHN-USERS / RESIDUAL-FOR-TOTP-ONLY-USERS; phishing-without-WebAuthn HIGH → MITIGATED-FOR-WEBAUTHN-USERS. New leaf H (TOTP-secret extraction) RESIDUAL.
**Next review:** Milestone M1 baseline (start of Phase 04).

---

## 2026-05-05 — crypto-auditor — Phase 05 + Phase 07 (MVP-Phase-Z gate)

**Scope:** Phase 05 page-cipher high-level API (encryptPage/decryptPage, aadParamsJson round-trip, titleSearchToken derivation), page/new POST flow (client-side pageId AAD consistency), vault-key.ts sealed-box wrappers, resolveVaultDek fallback logic.
**Method:** Static read-only. Source grep + flow trace on `apps/web/src/lib/crypto/`, `apps/web/src/app/(authed)/page/`, `packages/crypto/src/vault-page.ts`, `apps/web/src/lib/vault/resolve-vault-dek.ts`.
**Findings:** Critical 1 (FINDING-0701) / Medium 1 (FINDING-0702) / Low 2 (FINDING-0703, FINDING-0704)
**Verdict:** **FAIL** (Critical finding — gate blocked)
**Findings filed:** FINDING-0701 (CRITICAL, closed e332e1c), FINDING-0702 (MEDIUM, closed 365c8b1), FINDING-0703 (LOW, closed 663edeb), FINDING-0704 (LOW, closed 365c8b1)
**Next review:** Phase 08 or next crypto surface change.

---

## 2026-05-05 — access-control-auditor — Phase 05 + Phase 07 (MVP-Phase-Z gate)

**Scope:** IDOR guards on credential + page routes, shared vault membership access model, vault-sharing controller RBAC, invite lifecycle access control, owner/member role enforcement.
**Method:** Static read-only. Route-by-route ownership predicate audit, cross-user 404 anti-enumeration check, membership EXISTS subquery review.
**Findings:** Critical 0 / High 0 / Medium 3 (FINDING-0060, 0061, 0062) / Low 5 (FINDING-0063, 0064, 0065, 0066, 0067)
**Verdict:** **PASS-WITH-CONCERNS**
**Findings filed:** 0060 (MED, closed 663edeb), 0061 (MED, closed 663edeb), 0062 (MED, closed 663edeb), 0063 (LOW, closed 365c8b1), 0064 (LOW, closed 365c8b1), 0065 (LOW, closed 663edeb), 0066 (LOW, closed 365c8b1), 0067 (LOW, closed 365c8b1)
**Next review:** Phase 08 vault credential sharing extension.

---

## 2026-05-05 — auth-flow-auditor — Phase 05 + Phase 07 (MVP-Phase-Z gate)

**Scope:** Invite accept/decline flow (DEK unwrap order, kx key derivation), resolveVaultDek fallback, vault DEK lifecycle (create, accept, leave), hard-refresh key restoration, invites page UX on locked state.
**Method:** Static read-only. Flow trace on `apps/web/src/app/(authed)/invites/`, `apps/web/src/lib/vault/resolve-vault-dek.ts`, `apps/web/src/app/(authed)/vaults/`.
**Findings:** Critical 0 / High 0 / Medium 2 (FINDING-0071, 0079) / Low 3 (FINDING-0072, 0074, 0076)
**Verdict:** **PASS-WITH-CONCERNS**
**Findings filed:** 0071 (MED, closed 663edeb), 0079 (MED, closed 663edeb), 0072 (LOW, closed 2704b36), 0074 (LOW, closed 365c8b1), 0076 (LOW, WONTFIX — DEK rotation post-MVP)
**Next review:** Phase 12 or vault re-key ceremony planning.

---

## 2026-05-05 — owasp-top10-auditor — Phase 05 + Phase 07 (MVP-Phase-Z gate)

**Scope:** OWASP Top 10 (2021) delta for Phase 05 + 07. A01 (vault-sharing RBAC), A02 (page AAD self-consistency), A04 (insecure design — name plaintext), A05 (rate-limit gaps), A07 (vault-sharing auth gaps), A09 (audit logging gaps).
**Method:** Static read-only. Route enumeration + input validation audit + audit-log grep.
**Findings:** Critical 0 / High 1 (FINDING-0085) / Medium 5 (FINDING-0080, 0081, 0082, 0083, 0084) / Low 2 (FINDING-0086, 0087)
**Verdict:** **PASS-WITH-CONCERNS**
**Findings filed:** 0085 (HIGH, closed e332e1c), 0080 (MED, WONTFIX — vault name design), 0081 (MED, closed 663edeb), 0082 (MED, closed 663edeb), 0083 (MED, closed 663edeb), 0084 (MED, closed 663edeb), 0086 (LOW, closed 365c8b1), 0087 (LOW, closed 365c8b1)
**Next review:** Phase 08 or next OWASP delta pass.

---

## 2026-05-05 — MVP-Phase-Z GATE OUTCOME

**Verdict:** **PASS.**
- 4 auditors: FAIL → PASS after closure cycle (all Critical/High/Medium resolved).
- 0 Critical OPEN / 0 High OPEN / 0 Medium OPEN.
- Low findings: 0072/0063/0064/0065/0066/0067/0074/0086/0087/0703/0704 CLOSED. 0076/0080 WONTFIX with documented rationale.
- 71 API tests + 105 web tests green. Both typechecks clean.
- Phase 05 (pages) + Phase 07 (shared vaults) security gate passed.
**Accepted tech-debt to Phase 12/13:** FINDING-0076 (DEK rotation on member removal), FINDING-0080 (vault name plaintext).
**Remaining open from prior phases:** FINDING-0032, 0033, 0040, 0050-0054 (Phase 03 deferred Low/Info).

---

## 2026-05-04 — Phase 03 GATE OUTCOME

**Verdict:** **PASS.**
- 4 blocking auditors all PASS / PASS-WITH-CONCERNS post-closure.
- Threat-modeler informational pass committed to THREAT-MODEL.md §17 + §19.
- 0 Critical / 0 High OPEN. Mediums (1) + Lows (3) + Info (8) tracked OPEN; none block per AGENTS.md gate rule.
- Goal-backward verification 20/20 truths verified.
- gsd-verifier flagged two operator checkpoints (Plan 10 T4 UX + Plan 12 T4 runbook) which remain owner-side.
**Operator checkpoints still pending (NON-blocking):** Plan 10 T4 visual UX review of `/settings/security`; Plan 12 T4 review of new `docs/operator/RUNBOOK.md`.
**Tracked tech-debt to Phase 13:** FINDING-0032 (TOTP verify user-keyed throttler), FINDING-0033 (step-up guard epoch check), FINDING-0040 (TOTP unwrap AAD recompute), FINDING-0050..0054.
