import { Module } from "@nestjs/common";

import { PagesController } from "./pages.controller.js";
import { PagesService } from "./pages.service.js";

/**
 * Phase 05 / Plan 02 — pages CRUD module.
 *
 * Sibling parity with `CredentialsModule`. `JwtAuthGuard` is APP_GUARD-
 * registered in `app.module.ts` so it covers every route automatically. No
 * `Require2FAGuard` — REQ-2FA-003 (personal vault is 2FA-optional).
 *
 * `DbModule` is `@Global` so `DbService` is available without an explicit
 * import here.
 */
@Module({
  controllers: [PagesController],
  providers: [PagesService],
  exports: [PagesService],
})
export class PagesModule {}
