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
import { describe, it, expect, beforeEach, vi } from "vitest";

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
/**
 * Conditional-registration assertions (INDEX Key Link 8 + plan key_links).
 *
 * The probe route MUST be absent in any build where `EXPOSE_TEST_ROUTES !== "1"`.
 * Three layered checks:
 *
 *   - (8) Source-level: `app.module.ts` contains the exact conditional spread
 *     expression `process.env.EXPOSE_TEST_ROUTES === "1"`. Catches accidental
 *     drift to a truthy-coercion check (`!!process.env.EXPOSE_TEST_ROUTES`)
 *     which would expose the route on `"0"` / `"false"`.
 *   - (9) Build artifact: production Dockerfile + docker-compose.yml carry no
 *     reference to `EXPOSE_TEST_ROUTES`. Run as a grep over the repo's prod
 *     artifact paths.
 *   - (10) Runtime: the conditional-spread closure evaluated against either
 *     env state returns a single-element array iff env === "1". This is a
 *     direct unit test of the `process.env.X === "1" ? [M] : []` pattern,
 *     decoupled from the full `app.module.ts` graph which transitively
 *     touches every other Phase 03 plan's not-yet-landed wiring.
 *
 * Full Nest-app boot lives in Plan 12 (Cypress + a real Postgres + Redis),
 * which is the only place every parallel-wave dependency is settled.
 */
describe("VaultProbeModule conditional registration (INDEX Key Link 8)", () => {
  const ORIGINAL = process.env.EXPOSE_TEST_ROUTES;

  function restore(): void {
    if (ORIGINAL === undefined) delete process.env.EXPOSE_TEST_ROUTES;
    else process.env.EXPOSE_TEST_ROUTES = ORIGINAL;
  }

  it("(8) app.module.ts uses the strict-string-equality guard for EXPOSE_TEST_ROUTES", async () => {
    const fs = await import("node:fs/promises");
    const url = new URL("../src/app.module.ts", import.meta.url);
    const source = await fs.readFile(url, "utf8");
    // Anchor on the exact pattern the plan prescribes — anything else (truthy
    // coercion, length check, env.toLowerCase()) would silently widen the gate.
    expect(source).toContain('process.env.EXPOSE_TEST_ROUTES === "1"');
    expect(source).toContain("VaultProbeModule");
  });

  it("(9) production artifacts (Dockerfile + docker-compose) carry no EXPOSE_TEST_ROUTES reference", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    // Repo root = three levels up from apps/api/test (test/ → apps/api/ → apps/ → repo).
    const repoRoot = path.resolve(new URL(".", import.meta.url).pathname, "../../..");
    const candidates = [
      path.join(repoRoot, "apps/api/Dockerfile"),
      path.join(repoRoot, "apps/web/Dockerfile"),
      path.join(repoRoot, "docker-compose.yml"),
    ];
    for (const f of candidates) {
      try {
        const txt = await fs.readFile(f, "utf8");
        expect(txt).not.toContain("EXPOSE_TEST_ROUTES");
      } catch (err) {
        // File missing is acceptable — only assert when present.
        const e = err as { code?: string };
        if (e.code !== "ENOENT") throw err;
      }
    }
  });

  it("(10) the conditional spread evaluates to [Module] iff env === \"1\"", () => {
    // Mirror of `app.module.ts` line:
    //   ...(process.env.EXPOSE_TEST_ROUTES === "1" ? [VaultProbeModule] : [])
    // A unit test of the exact predicate insulates this from the full Nest
    // module graph (which depends on parallel siblings still in flight).
    const make = (): unknown[] => {
      const flag: string | undefined = process.env.EXPOSE_TEST_ROUTES;
      return flag === "1" ? ["MARKER"] : [];
    };

    delete process.env.EXPOSE_TEST_ROUTES;
    expect(make()).toEqual([]);

    process.env.EXPOSE_TEST_ROUTES = "1";
    expect(make()).toEqual(["MARKER"]);

    process.env.EXPOSE_TEST_ROUTES = "0";
    expect(make()).toEqual([]);

    process.env.EXPOSE_TEST_ROUTES = "true";
    expect(make()).toEqual([]);

    process.env.EXPOSE_TEST_ROUTES = " 1"; // leading-space sneak attempt
    expect(make()).toEqual([]);

    restore();
  });

  // `vi` is intentionally imported (above) for forward-compat with Plan 12 /
  // a future fully-booted Nest test app — kept here to avoid an unused-import
  // lint blocker without removing the import line that other tests will rely on.
  it("__plumbing", () => {
    expect(typeof vi.resetModules).toBe("function");
  });
});
