/**
 * Phase 03 Plan 06 / Task 2 — removal-guard integration test.
 *
 * Verifies the Phase-07 hand-off seam (`userHasSharedVaultDependency`).
 * Phase 03's default-false stub means `removeGuarded` always proceeds; the
 * 409 branch is only exercised when something injects a `() => true` dep.
 *
 * Mock-based unit test (no real DbService / Postgres). Mirrors the pattern
 * in `jwt-epoch.spec.ts` + `2fa-required-guard.spec.ts`. Real PG e2e
 * coverage lives in Plan 12 (Cypress + service containers).
 */
import { HttpException, HttpStatus } from "@nestjs/common";
import { describe, it, expect, beforeEach, vi } from "vitest";

import {
  MethodsService,
  type SharedVaultDependencyCheck,
} from "../src/twofa/methods/methods.service.js";

const USER_A = "11111111-1111-1111-1111-111111111111";
const METHOD_X = "22222222-2222-2222-2222-222222222222";
const METHOD_Y = "33333333-3333-3333-3333-333333333333";

/**
 * Make a MethodsService whose db / count / remove behaviour we can control
 * test-by-test without standing up a real DbService. The only piece we
 * actually exercise is `removeGuarded` — its dependencies (`countActive`,
 * `remove`) are stubbed via `vi.spyOn`.
 */
function makeService(): MethodsService {
  // Construct with a stub DbService — we never call into it from the spied
  // methods, so an empty placeholder is fine.
  const stubDb = { db: undefined as never };
  return new MethodsService(stubDb as never);
}

describe("MethodsService.removeGuarded — Phase 07 hand-off seam (Plan 06 Truth 10)", () => {
  let svc: MethodsService;
  let countSpy: ReturnType<typeof vi.spyOn>;
  let removeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    svc = makeService();
    countSpy = vi.spyOn(svc, "countActive");
    removeSpy = vi.spyOn(svc, "remove");
  });

  it("(1) baseline (Phase 03 default stub) — removing the last method succeeds with 204", async () => {
    countSpy.mockResolvedValue(1);
    removeSpy.mockResolvedValue({ kind: "webauthn" });
    // Default sharedVaultDependencyCheck returns false (Phase 03 stub).
    const result = await svc.removeGuarded(USER_A, METHOD_X);
    expect(result).toEqual({ kind: "webauthn" });
    expect(removeSpy).toHaveBeenCalledWith(USER_A, METHOD_X);
  });

  it("(2) deps=true + count goes to 0 → throws 409 AUTH_2FA_REMOVAL_BLOCKED; method NOT removed", async () => {
    countSpy.mockResolvedValue(1);
    const trueStub: SharedVaultDependencyCheck = async () => true;
    svc.sharedVaultDependencyCheck = trueStub;

    await expect(svc.removeGuarded(USER_A, METHOD_X)).rejects.toMatchObject({
      response: {
        error: {
          code: "E1018",
          data: { requires: "shared_vault_2fa" },
        },
      },
      status: HttpStatus.CONFLICT,
    });
    // The DELETE must NOT have run — the method survives.
    expect(removeSpy).not.toHaveBeenCalled();
  });

  it("(3) deps=true + count after = 1 (i.e. removing 1 of 2) → succeeds; only 0-after triggers", async () => {
    countSpy.mockResolvedValue(2);
    removeSpy.mockResolvedValue({ kind: "totp" });
    svc.sharedVaultDependencyCheck = async () => true;

    const result = await svc.removeGuarded(USER_A, METHOD_Y);
    expect(result).toEqual({ kind: "totp" });
    expect(removeSpy).toHaveBeenCalledWith(USER_A, METHOD_Y);
  });

  it("(4) cross-user / non-existent (count=0) → null (caller maps to 404, NEVER 403)", async () => {
    countSpy.mockResolvedValue(0);
    removeSpy.mockResolvedValue(null);
    // Even with deps=true, count=0 means there's nothing to guard — fall
    // through to `remove` which itself returns null.
    svc.sharedVaultDependencyCheck = async () => true;
    const result = await svc.removeGuarded(USER_A, METHOD_X);
    expect(result).toBeNull();
    expect(removeSpy).toHaveBeenCalledWith(USER_A, METHOD_X);
  });

  it("(5) the 409 carries the canonical envelope shape (code + message + data.requires)", async () => {
    countSpy.mockResolvedValue(1);
    svc.sharedVaultDependencyCheck = async () => true;
    try {
      await svc.removeGuarded(USER_A, METHOD_X);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(HttpException);
      const e = err as HttpException;
      expect(e.getStatus()).toBe(HttpStatus.CONFLICT);
      const body = e.getResponse() as { error?: { code?: string; message?: string; data?: { requires?: string } } };
      expect(body.error?.code).toBe("E1018");
      expect(typeof body.error?.message).toBe("string");
      expect(body.error?.data?.requires).toBe("shared_vault_2fa");
    }
  });
});
