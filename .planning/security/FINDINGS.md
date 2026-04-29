# SimpleVault — Security Findings Tracker

All findings reported by security auditor agents (manual or automated). Tracked from open → fixed → verified.

**Severity scale:** Critical / High / Medium / Low / Info (mapped to CVSS v3.1 base score where applicable).

**Gate rule:** No Critical or High finding may remain `OPEN` when a phase is marked complete. Medium/Low can be deferred with explicit operator sign-off and a follow-up phase commitment.

---

## Schema (per finding)

```
### FINDING-XXXX — short title

- **Severity:** Critical | High | Medium | Low | Info
- **CVSS:** (if applicable)
- **Reporter:** [agent-name] OR operator OR external
- **Date opened:** YYYY-MM-DD
- **Phase:** XX
- **Affected:** files / endpoints / flows
- **Description:** what is wrong
- **Reproduction:** steps / PoC
- **Recommendation:** how to fix
- **Status:** OPEN | IN-PROGRESS | FIXED-PENDING-VERIFICATION | VERIFIED-CLOSED | WONTFIX-WITH-RATIONALE
- **Resolved-by-commit:** sha (when fixed)
- **Verified-by:** [agent-name] on YYYY-MM-DD
```

---

## Open findings

### FINDING-0001 — next@15.1.0 RCE via React-flight protocol (GHSA-9qr9-h5gf-34mp)

- **Severity:** Critical
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/web/package.json` (`next@15.1.0`)
- **Description:** Known critical RCE in Next.js < 15.5.15 via React-flight protocol.
- **Recommendation:** Bump `next` to `^15.5.15` (or latest stable 15.x). Re-run `pnpm install` and verify `apps/web` builds + middleware/CSP still works.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 59c2e19
- **Verified-by:** —

### FINDING-0002 — next@15.1.0 middleware auth bypass (GHSA-f82v-jwr5-mffw)

- **Severity:** Critical
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/web/package.json` (`next@15.1.0`)
- **Description:** Auth-bypass in Next.js middleware. SimpleVault uses middleware for security headers + (future) auth gating, so this is a direct hit on a load-bearing layer.
- **Recommendation:** Bump `next` to `^15.5.15`. Same upgrade as FINDING-0001.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 59c2e19
- **Verified-by:** —

### FINDING-0003 — drizzle-orm@0.38.4 SQL injection via identifier (GHSA-gpj5-g38j-94v9)

- **Severity:** High
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `packages/db/package.json`, `apps/api/package.json` (`drizzle-orm@0.38.4`); also `drizzle-kit@0.30.6`
- **Description:** SQL-injection-via-identifier in drizzle-orm — direct hit on the data layer of a vault product. Only `users` stub schema today, but every later schema runs through this.
- **Recommendation:** Bump `drizzle-orm` to `^0.45.2` (and `drizzle-kit` to a matching stable version). Re-generate migration with new drizzle-kit and re-verify against PG 18.3 (Plan 08 verification path).
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 8a31481
- **Verified-by:** —

### FINDING-0004 — multer@2.0.2 DoS CVEs via @nestjs/platform-express@10.4.22 (3× High)

- **Severity:** High
- **Reporter:** dependency-supply-chain-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/api/package.json` (`@nestjs/platform-express@10.4.22` → transitive `multer@2.0.2`)
- **Description:** Three High DoS CVEs in `multer@2.0.2`, fixed in `multer >= 2.1.1`.
- **Recommendation:** Either upgrade `@nestjs/*` from 10.4.x to `^11` (preferred, broader hardening) or pin `multer >= 2.1.1` via `pnpm.overrides` in root package.json as a stop-gap.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 71c6399 (pnpm.overrides path; full Nest 11 upgrade slated for Phase 02)
- **Verified-by:** —

### FINDING-0005 — postgres service in docker-compose missing cap_drop: [ALL]

- **Severity:** High
- **Reporter:** infra-deployment-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `docker-compose.yml` (postgres service)
- **Description:** Defense-in-depth gap: postgres container retains the full default Linux capability set. Other services in this compose drop ALL caps; postgres + redis are the exceptions.
- **Recommendation:** Add `cap_drop: [ALL]` and only add back what postgres needs (`SETUID`, `SETGID`, `DAC_READ_SEARCH` for the official image initdb path). Test with `docker compose up -d` that postgres still starts and is healthy.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 579ea8d
- **Verified-by:** —

### FINDING-0006 — redis service in docker-compose missing cap_drop: [ALL]

- **Severity:** High
- **Reporter:** infra-deployment-auditor
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `docker-compose.yml` (redis service)
- **Description:** Same defense-in-depth gap as FINDING-0005, on the redis service.
- **Recommendation:** Add `cap_drop: [ALL]`. Redis (alpine) typically needs no caps added back.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 579ea8d (cap_drop ALL applied; SETUID/SETGID added back — entrypoint needs them to drop to the redis user, otherwise the container restart-loops)
- **Verified-by:** —

### FINDING-0007 — apps/api missing `dev` script (Truth 4 gap)

- **Severity:** Low
- **Reporter:** gsd-verifier
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `apps/api/package.json`
- **Description:** Truth 4 of 01-INDEX.md states "`pnpm dev` starts both web (`:3000`) and api (`:3001`) concurrently." `apps/api` declares `start:dev` only — `turbo run dev` silently skips api. The `docker compose up -d` path (operator's actual goal) is fully met, so this is a literal-wording gap, not a functional gap.
- **Recommendation:** Add `"dev": "nest start --watch"` to `apps/api/package.json` scripts. One-line change.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** 31574f8
- **Verified-by:** —

### FINDING-0008 — container scan workflow path-filtered

- **Severity:** Info
- **Reporter:** gsd-verifier
- **Date opened:** 2026-04-28
- **Phase:** 01
- **Affected:** `.github/workflows/container-scan.yml`
- **Description:** Workflow only triggers on changes to Dockerfiles, lockfile, or package.json — code-only PRs do not run Trivy. Intentional cost optimization, but creates a window where new `RUN`/dependency-pulled-via-CI changes could introduce image-level issues silently.
- **Recommendation:** Add a weekly cron `schedule:` trigger to container-scan.yml so all merged code is scanned at least every 7 days regardless of which paths changed. Non-blocking.
- **Status:** FIXED-PENDING-VERIFICATION
- **Resolved-by-commit:** bac1fa3
- **Verified-by:** —

## Closed findings

_(none yet)_
