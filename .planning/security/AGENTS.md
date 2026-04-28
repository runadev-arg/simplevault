# SimpleVault — Security Agents Roster

The 12 specialized security agents that audit SimpleVault throughout development. Each runs as a subagent (via the `Agent` tool) with a focused prompt template stored in `.claude/agents/` (to be created on first use).

Each agent's mandate, when it runs, and its gate authority is defined here.

---

## Roster

| # | Agent | When it runs | Authority |
|---|---|---|---|
| 1 | `crypto-auditor` | After any change to `packages/crypto`, key derivation, encryption, or wrapping logic. **Mandatory before** Phase 02 (Auth/Crypto) gate, Phase 04 (Sharing/Wrapping) gate, and Milestone "Security Hardening". | Critical/High findings BLOCK phase merge. |
| 2 | `auth-flow-auditor` | After any change to signup/login/logout/recovery/2FA/session. **Mandatory before** Phase 02 and Phase 03 gates and Security Hardening. | Critical/High BLOCK. |
| 3 | `owasp-top10-auditor` | At the gate of EVERY phase. Systematic pass against OWASP Top 10 (2021). | Critical/High BLOCK. |
| 4 | `access-control-auditor` | After any change touching authorization, especially Phases 04 (Sharing), 05 (Unanimous Delete), 06 (Audit Log read paths). | Critical/High BLOCK. |
| 5 | `input-validation-auditor` | At every phase gate where new endpoints/forms were added. | Critical/High BLOCK. |
| 6 | `dependency-supply-chain-auditor` | After every `pnpm add`/upgrade. CI cron weekly. Mandatory before Security Hardening. | Critical/High BLOCK; Medium reviewed. |
| 7 | `infra-deployment-auditor` | **TOP PRIORITY for SimpleVault** (self-hosted). Runs on Phase 01 (Monorepo+Docker), Phase 09 (Deploy), and Security Hardening. | Critical/High BLOCK. |
| 8 | `rate-limit-dos-auditor` | Phase 02, Phase 04 (invites), Security Hardening. | Critical/High BLOCK. |
| 9 | `audit-log-integrity-auditor` | Phase 06 (Audit log + Hash chain), Security Hardening. | Critical/High BLOCK. |
| 10 | `frontend-security-auditor` | Phase 07 (Notion-like editor) is the **highest XSS surface** — mandatory then. Also Security Hardening. | Critical/High BLOCK. |
| 11 | `threat-modeler` | Milestone 0 baseline + before each milestone. Updates `THREAT-MODEL.md`. | Output is informational; gates use other auditors. |
| 12 | `pentester-redteam` | **FINAL gate before production deploy.** Active simulation: tries to break auth, escalate, exfiltrate, abuse the unanimous-delete system. | ANY Critical = block production deploy. |

---

## Gate protocol per phase

1. Phase implementation complete; all tests pass; commits clean.
2. Operator runs `/gsd:verify-work N` which spawns the relevant auditors in parallel for that phase (see "Phase → auditors" matrix in ROADMAP.md).
3. Each auditor produces a report appended to `AUDIT-LOG.md` and files findings in `FINDINGS.md`.
4. If any Critical/High remains OPEN → phase BLOCKED; fix → re-run auditor → repeat.
5. If clean → phase marked complete; STATE.md updated; next phase planning begins.

---

## "Security Hardening" milestone protocol

Before Phase 09 (Production Deploy), ALL 12 agents run in parallel via `/gsd:audit-milestone security-hardening`. Outputs aggregated into `.planning/security/HARDENING-REPORT-{date}.md`. Production deploy is BLOCKED until all Critical/High findings are VERIFIED-CLOSED.

---

## Notes

- Agent prompt files live in `.claude/agents/<name>.md` (created at first use; standardized template).
- Agents have read-only access to the repo; they do NOT write fixes — they file findings. Fixes are the operator's job.
- For each finding, the operator decides: fix, defer (Medium/Low only, with rationale), or wontfix (rare, requires written justification in FINDINGS.md).
