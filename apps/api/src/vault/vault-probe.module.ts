import { Module } from "@nestjs/common";

import { AuthModule } from "../auth/auth.module.js";
import { TwoFaModule } from "../twofa/twofa.module.js";

import { TwoFaGuardProbeController } from "./_2fa-guard-probe.controller.js";

/**
 * Phase 03 Plan 07 — gated probe module for the 2FA-required guard.
 *
 * This module is registered by `AppModule` IFF
 * `process.env.EXPOSE_TEST_ROUTES === "1"` (INDEX Key Link 8). It carries
 * exactly one controller — the `_2fa-guard-probe` route — and zero
 * providers of its own; it relies on:
 *
 *   - `AuthModule` for `JwtAuthGuard` (and its `JwtService` / `SessionEpochCache`
 *     transitive deps).
 *   - `TwoFaModule` for `Require2FAGuard` (and its `REQUIRE_2FA_COUNT_READER`
 *     binding which provides the `(webauthn + totp)` count query).
 *
 * Phase 07 deletes this module + the `_2fa-guard-probe` controller as its
 * FIRST commit, replacing both with the real `vault.create` / `vault.join`
 * controllers using the same guard stack.
 */
@Module({
  imports: [AuthModule, TwoFaModule],
  controllers: [TwoFaGuardProbeController],
})
export class VaultProbeModule {}
