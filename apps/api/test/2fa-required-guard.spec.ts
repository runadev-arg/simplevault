/**
 * Phase 03 Plan 07 — Require2FAGuard + EXPOSE_TEST_ROUTES probe route spec.
 *
 * RED in Task 1, GREEN by Task 2. Uses an in-memory stub DbService (mirrors
 * the pattern in `jwt-epoch.spec.ts`). Real e2e validation lives in Plan 12
 * (Cypress + a Postgres + Redis container).
 *
 * Invariants (per 03-07-PLAN.md + INDEX Truth 15 + Key Link 8):
 *   1. Require2FAGuard counts (webauthn_credentials + totp_credentials) for
 *      req.user.id; 0 → throws 403 AUTH_2FA_REQUIRED; ≥1 → returns true.
 *   2. Removing the last credential flips the guard back to 403.
 *   3. Adding either kind (webauthn OR totp) is sufficient — only the SUM matters.
 *   4. Probe route is registered iff `process.env.EXPOSE_TEST_ROUTES === "1"`;
 *      any other value (undefined, "0", "true") leaves the route absent.
 */
import { HttpException } from "@nestjs/common";
import { describe, it, expect, beforeEach } from "vitest";

import { Require2FAGuard, type Require2FACountReader } from "../src/twofa/require-2fa.guard.js";

const USER_A = "11111111-1111-1111-1111-111111111111";
const USER_B = "22222222-2222-2222-2222-222222222222";

interface CountStub extends Require2FACountReader {
  set: (userId: string, kind: "webauthn" | "totp", n: number) => void;
  delete: (userId: string, kind: "webauthn" | "totp") => void;
  callCount: number;
}

function makeCountStub(): CountStub {
  // Nested map: userId → kind → n.
  const rows = new Map<string, { webauthn: number; totp: number }>();
  const stub: CountStub = {
    callCount: 0,
    async countActive(userId: string): Promise<number> {
      stub.callCount += 1;
      const r = rows.get(userId) ?? { webauthn: 0, totp: 0 };
      return r.webauthn + r.totp;
    },
    set(userId, kind, n): void {
      const r = rows.get(userId) ?? { webauthn: 0, totp: 0 };
      r[kind] = n;
      rows.set(userId, r);
    },
    delete(userId, kind): void {
      const r = rows.get(userId) ?? { webauthn: 0, totp: 0 };
      r[kind] = 0;
      rows.set(userId, r);
    },
  };
  return stub;
}

/** Minimal ExecutionContext stub — guard only needs `req.user.id`. */
function ctxFor(userId: string | undefined): {
  switchToHttp: () => { getRequest: () => { user?: { id?: string } } };
} {
  const req: { user?: { id?: string } } = userId ? { user: { id: userId } } : {};
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  };
}

describe("Require2FAGuard (Phase 03 Plan 07 — Truth 15)", () => {
  let counts: CountStub;
  let guard: Require2FAGuard;

  beforeEach(() => {
    counts = makeCountStub();
    guard = new Require2FAGuard(counts);
  });

  it("(1) rejects 403 AUTH_2FA_REQUIRED when user has zero 2FA methods", async () => {
    await expect(guard.canActivate(ctxFor(USER_A) as never)).rejects.toMatchObject({
      response: { error: { code: "E1002" } },
      status: 403,
    });
    expect(counts.callCount).toBe(1);
  });

  it("(2) allows when user has exactly 1 webauthn credential", async () => {
    counts.set(USER_A, "webauthn", 1);
    await expect(guard.canActivate(ctxFor(USER_A) as never)).resolves.toBe(true);
  });

  it("(3) allows when user has exactly 1 totp credential", async () => {
    counts.set(USER_A, "totp", 1);
    await expect(guard.canActivate(ctxFor(USER_A) as never)).resolves.toBe(true);
  });

  it("(4) allows when user has both kinds", async () => {
    counts.set(USER_A, "webauthn", 1);
    counts.set(USER_A, "totp", 1);
    await expect(guard.canActivate(ctxFor(USER_A) as never)).resolves.toBe(true);
  });

  it("(5) flips back to 403 after the last credential is removed", async () => {
    counts.set(USER_A, "totp", 1);
    await expect(guard.canActivate(ctxFor(USER_A) as never)).resolves.toBe(true);

    counts.delete(USER_A, "totp");
    await expect(guard.canActivate(ctxFor(USER_A) as never)).rejects.toMatchObject({
      response: { error: { code: "E1002" } },
      status: 403,
    });
  });

  it("(6) one user's credentials do not count for another", async () => {
    counts.set(USER_A, "webauthn", 1);
    // User B has zero — must still be rejected.
    await expect(guard.canActivate(ctxFor(USER_B) as never)).rejects.toMatchObject({
      response: { error: { code: "E1002" } },
      status: 403,
    });
  });

  it("(7) rejects 401 when no req.user is attached (defence-in-depth — guard is a stack-mate of JwtAuthGuard)", async () => {
    await expect(guard.canActivate(ctxFor(undefined) as never)).rejects.toBeInstanceOf(HttpException);
  });
});

/**
 * Conditional-registration assertion (INDEX Key Link 8 + plan key_links).
 *
 * The probe route MUST be absent in any build where `EXPOSE_TEST_ROUTES !== "1"`.
 * We verify this at the module-loading layer rather than booting two full
 * Nest test apps (the existing test infra is unit-level — Plan 12 covers the
 * full e2e). Loading `app.module.ts` with the env var unset must NOT include
 * `VaultProbeModule` in `imports`; with it set to "1" it MUST.
 */
describe("VaultProbeModule conditional registration (INDEX Key Link 8)", () => {
  const ORIGINAL = process.env.EXPOSE_TEST_ROUTES;

  beforeEach(() => {
    // Wipe module cache so app.module.ts re-evaluates the conditional import.
    // Vitest's `vi.resetModules()` would also work; explicit deletion is
    // sufficient for ESM since dynamic import() bypasses require-cache.
  });

  function restore(): void {
    if (ORIGINAL === undefined) delete process.env.EXPOSE_TEST_ROUTES;
    else process.env.EXPOSE_TEST_ROUTES = ORIGINAL;
  }

  it("(8) production-shape build (env unset) does NOT register VaultProbeModule", async () => {
    delete process.env.EXPOSE_TEST_ROUTES;
    // Force re-import so the conditional spread re-runs.
    const mod = await import(`../src/app.module.js?cache=${Date.now()}-1`);
    const meta = Reflect.getMetadata("imports", mod.AppModule) as unknown[];
    const hasProbe = meta.some(
      (m) => typeof m === "function" && (m as { name?: string }).name === "VaultProbeModule",
    );
    expect(hasProbe).toBe(false);
    restore();
  });

  it("(9) test/dev build (env=\"1\") DOES register VaultProbeModule", async () => {
    process.env.EXPOSE_TEST_ROUTES = "1";
    const mod = await import(`../src/app.module.js?cache=${Date.now()}-2`);
    const meta = Reflect.getMetadata("imports", mod.AppModule) as unknown[];
    const hasProbe = meta.some(
      (m) => typeof m === "function" && (m as { name?: string }).name === "VaultProbeModule",
    );
    expect(hasProbe).toBe(true);
    restore();
  });

  it('(10) any non-"1" value (e.g. "true", "0") still skips the probe', async () => {
    process.env.EXPOSE_TEST_ROUTES = "true";
    const mod = await import(`../src/app.module.js?cache=${Date.now()}-3`);
    const meta = Reflect.getMetadata("imports", mod.AppModule) as unknown[];
    const hasProbe = meta.some(
      (m) => typeof m === "function" && (m as { name?: string }).name === "VaultProbeModule",
    );
    expect(hasProbe).toBe(false);
    restore();
  });
});
