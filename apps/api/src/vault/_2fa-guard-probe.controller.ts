import { Controller, HttpCode, HttpStatus, Post, UseGuards } from "@nestjs/common";

import { JwtAuthGuard } from "../auth/jwt/jwt-auth.guard.js";
import { Require2FAGuard } from "../twofa/require-2fa.guard.js";

/**
 * Phase 03 Plan 07 — `POST /vault/_2fa-guard-probe`.
 *
 * EXISTS ONLY IN BUILDS WHERE `process.env.EXPOSE_TEST_ROUTES === "1"`.
 * The route lets the integration / e2e suites exercise `Require2FAGuard`
 * (INDEX Truth 15) without requiring the actual vault module — which lands
 * in Phase 07.
 *
 * Production builds MUST leave `EXPOSE_TEST_ROUTES` undefined so the
 * surrounding `VaultProbeModule` is never imported by `AppModule` and the
 * route is therefore absent from the router. Verification: the production
 * Dockerfile + docker-compose.yml carry no reference to `EXPOSE_TEST_ROUTES`
 * (grep-clean — see plan key links).
 *
 * Phase 07 cleanup (documented as Phase 07's first commit per INDEX
 * Operator decision §6 + Plan 06/07 Phase-07 hand-off rule):
 *   1. Delete this file.
 *   2. Delete `vault-probe.module.ts`.
 *   3. Delete the conditional spread in `app.module.ts`.
 *   4. Add the real `vault.create` / `vault.join` controllers, both
 *      decorated `@UseGuards(JwtAuthGuard, Require2FAGuard)`. The guard
 *      contract is unchanged; the probe was only a temporary surface.
 */
@Controller("vault")
export class TwoFaGuardProbeController {
  /**
   * Trivial body — returns `{ok: true}`. The interesting behaviour is
   * entirely in the guard stack: `JwtAuthGuard` rejects unauthed callers
   * with 401, `Require2FAGuard` rejects callers with no enrolled 2FA
   * methods with 403 `AUTH_2FA_REQUIRED`. Successful traversal of both
   * guards is itself the assertion that the gate works.
   */
  @Post("_2fa-guard-probe")
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard, Require2FAGuard)
  probe(): { ok: true } {
    return { ok: true };
  }
}
