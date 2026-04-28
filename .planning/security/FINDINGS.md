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

_(none — pre-implementation)_

## Closed findings

_(none — pre-implementation)_
