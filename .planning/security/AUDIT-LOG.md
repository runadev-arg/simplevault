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
