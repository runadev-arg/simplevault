# Phase 01 / Plan 10 — SUMMARY

**Plan:** 01-10 — README + Dokploy operator runbook + LOCAL-DEV docs
**Status:** COMPLETE
**Date:** 2026-04-28
**Wave:** 7 (final wave of Phase 01)

## What shipped

Four docs, two atomic commits.

| File | Purpose |
|---|---|
| `README.md` | 30-second pitch, CI + Container-Scan badges, links into operator docs and `.planning/` |
| `docs/operator/LOCAL-DEV.md` | Fresh-clone → `curl /health` returns ok in <5 min, plus daily-dev workflow, migrations, troubleshooting |
| `docs/operator/DOKPLOY-DEPLOY.md` | Full Dokploy runbook for `pass.runadev.com` — build context, Dockerfile paths, env-var mapping, networking, deploy + verify + rollback |
| `docs/operator/SECURITY-NOTES.md` | The operator-must list — secrets to back up offline, off-site rsync target prep, audit-checkpoint repo, SMTP choice, operator 2FA, periodic tasks, detection signals |

## Commits

- `3d05ae7` — `docs(01-10-T1): README + LOCAL-DEV runbook`
- `2e056b5` — `docs(01-10-T2): DOKPLOY-DEPLOY + SECURITY-NOTES runbooks`

## Load-bearing details lifted into the docs (so they don't drift)

- **Build context = repo root** (`.`), Dockerfile path = `apps/<app>/Dockerfile`. Called out at the top of DOKPLOY-DEPLOY as the easy-to-make mistake.
- **Secrets via Dokploy encrypted env-var UI**, never `.env` in git. `.env.example` is reference-only.
- **Required env vars** for prod (api + web) tabulated, derived from `turbo.json` `passThroughEnv` + Plan 07's `.env.example`.
- **No host port mapping in prod** — Traefik (Dokploy) handles TLS + routing; `apps/web` runs `HOSTNAME=0.0.0.0`.
- **Security headers in app layer** (Next.js middleware + NestJS helmet) — operator instructed NOT to set them in Traefik.
- **Migrations run inline** at api startup via `migrate-then-start.sh`; PG 18.3 verified in `01-08-COMPAT.md` (linked from LOCAL-DEV).
- **`@germankatz` CODEOWNERS** flagged — operator must confirm GitHub username matches.
- **Audit-chain ceremony for `SERVER_CHAIN_SECRET`** referenced (Phase 10 owns the procedure); operator told never to rotate casually.
- **Off-site backup** = rsync over SSH with `command="rrsync -wo ..."` restriction in target's `authorized_keys` (append-only blast-radius).

## TBD — operator must decide before downstream phases

These are the items SECURITY-NOTES surfaces that **block specific phases**.
Listed here for the orchestrator and the next-phase planner to see at a glance:

1. **SMTP provider** — Postmark / Mailgun / Mailjet / self-hosted Postfix.
   Required by **Phase 02** (signup invite + login-alert emails) at the latest.
2. **Audit-checkpoint git repo location** — private GitHub vs self-hosted Gitea
   vs separate VPS. Required by **Phase 10** (audit log + hash chain).
3. **Off-site backup target** — host + user + path + dedicated SSH keypair on
   target's `authorized_keys` with `rrsync` restriction. Required by **Phase 14**
   (production deploy).
4. **Operator account 2FA policy** — should the operator account require a
   hardware key (no TOTP-only fallback)? Decide before **Phase 14**.
5. **`@germankatz` GitHub username** — operator must confirm `.github/CODEOWNERS`
   matches their real handle. Becomes load-bearing once branch-protection
   required-reviews is enabled (Phase 14, optionally earlier).

## Verification

- `<verify>` blocks ran:
  - All four files committed.
  - DOKPLOY-DEPLOY explicitly states build context = repo root and Dockerfile paths `apps/api/Dockerfile` + `apps/web/Dockerfile`.
  - SECURITY-NOTES surfaces every "operator must" item.
- Quickstart steps mentally walked through against the existing
  `.env.example`, `docker-compose.yml`, and the verified compose stack from
  Plan 07.
- No deviations from the plan.

## Phase 01 status

This is the **final plan in Phase 01**. With Plans 01–10 all complete, Phase
01 (Foundations) is **COMPLETE**. The repo is now deployable end-to-end:

- Turborepo + pnpm scaffold (Plan 01)
- Shared tsconfig + eslint-config (Plan 02)
- shared/crypto/db skeletons (Plan 03)
- apps/api skeleton + `/health` (Plan 04)
- apps/web Next.js + security middleware (Plan 05)
- Production Dockerfiles (Plan 06)
- Local docker-compose + `.env.example` (Plan 07)
- Drizzle migration + PG 18.3 verify (Plan 08)
- GitHub Actions CI + container scan + Dependabot + CODEOWNERS (Plan 09)
- README + operator runbooks (Plan 10) — **this plan**

Next: orchestrator runs `/gsd:verify-work 1` (security gate for Phase 01).
After the gate passes, plan Phase 02 (Auth + Crypto core) via
`/gsd:plan-phase 2`.
