/**
 * Phase 04 Plan 03 — throttler-ceiling cross-plan name agreement spec.
 *
 * The Plan 04-02 controller decorators reference three ceiling NAMES by
 * string literal (`credentials-write-user`, `credentials-read-user`,
 * `vault-list-user`). Plan 04-03 declares those names in
 * `apps/api/src/common/throttler.config.ts`. This spec is the static
 * cross-plan agreement check — if either side renames a ceiling, the
 * suite fails before Wave-2 closure.
 *
 * Also pins the value semantics so a careless edit can't quietly weaken a
 * limit (e.g. raise from 60 → 60_000 unintentionally) or change the TTL.
 * Env-overrides are deliberately NOT exercised here — the constants are
 * the safe defaults consumed when envs are unset (production posture).
 */
import { describe, it, expect } from "vitest";

import { RateLimits } from "../src/common/throttler.config.js";

describe("Plan 04-03 throttler ceilings", () => {
  it("declares credentials-write-user 60/min/user", () => {
    expect(RateLimits.credentialsWriteUser.name).toBe("credentials-write-user");
    expect(RateLimits.credentialsWriteUser.limit).toBe(60);
    expect(RateLimits.credentialsWriteUser.ttl).toBe(60_000);
  });

  it("declares credentials-read-user 300/min/user (REQ-RATELIMIT-006 spirit)", () => {
    expect(RateLimits.credentialsReadUser.name).toBe("credentials-read-user");
    expect(RateLimits.credentialsReadUser.limit).toBe(300);
    expect(RateLimits.credentialsReadUser.ttl).toBe(60_000);
  });

  it("declares vault-list-user 120/min/user", () => {
    expect(RateLimits.vaultListUser.name).toBe("vault-list-user");
    expect(RateLimits.vaultListUser.limit).toBe(120);
    expect(RateLimits.vaultListUser.ttl).toBe(60_000);
  });

  it("ceiling NAMES are stable strings (referenced by Plan 04-02 + 04-03 decorators)", () => {
    // If a name changes, every controller @Throttle({...}) referencing it
    // by string-literal-key silently falls back to the module-default
    // (1000/15min). Pinning the names here makes that regression visible.
    const names = [
      RateLimits.credentialsWriteUser.name,
      RateLimits.credentialsReadUser.name,
      RateLimits.vaultListUser.name,
    ];
    expect(new Set(names).size).toBe(3); // unique
    for (const n of names) expect(n).toMatch(/^[a-z0-9-]+$/);
  });
});
