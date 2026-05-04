import { Module } from "@nestjs/common";

import { DbModule } from "../db/db.module.js";
import { TwoFaModule } from "../twofa/twofa.module.js";

import { TestHelpersController } from "./test-helpers.controller.js";

/**
 * Phase 03 Plan 12 — gated module exposing the Cypress test-helpers
 * routes. Conditionally registered by `AppModule` IFF
 * `process.env.EXPOSE_TEST_ROUTES === "1"` (mirrors the
 * `VaultProbeModule` pattern from Plan 03-07). Production builds MUST
 * leave the env var unset.
 *
 * Reuses `MethodsService` (from `TwoFaModule`) for the
 * `sharedVaultDependencyCheck` flip and `DbService` (from `DbModule`)
 * for the direct webauthn-counter write.
 */
@Module({
  imports: [TwoFaModule, DbModule],
  controllers: [TestHelpersController],
})
export class TestHelpersModule {}
