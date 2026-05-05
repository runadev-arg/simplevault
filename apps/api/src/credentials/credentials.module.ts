import { Module } from "@nestjs/common";

import { CredentialsController } from "./credentials.controller.js";
import { CredentialsService } from "./credentials.service.js";

/**
 * Phase 04 / Plan 02 — credentials CRUD module.
 *
 * Wiring is intentionally minimal: `JwtAuthGuard` is APP_GUARD-registered
 * in `app.module.ts` so it covers every route automatically (FINDING-0021
 * carry-over closure). No `Require2FAGuard` here — REQ-2FA-003: personal
 * vault is 2FA-optional (Key Link 3 of 04-INDEX). Phase 07 will reuse
 * Require2FAGuard on `/shared-vaults/*` only.
 *
 * `DbModule` is `@Global` so `DbService` is available without an explicit
 * import here.
 */
@Module({
  controllers: [CredentialsController],
  providers: [CredentialsService],
  exports: [CredentialsService],
})
export class CredentialsModule {}
