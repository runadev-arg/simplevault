import { Module } from "@nestjs/common";

import { AuthModule } from "../auth/auth.module.js";
import { DbModule } from "../db/db.module.js";

import { StepUpJwtService } from "./step-up/step-up-jwt.service.js";
import { Require2FAStepUpGuard } from "./step-up/step-up.guard.js";
import { WebauthnRegisterController } from "./webauthn/webauthn-register.controller.js";
import { WebauthnRegisterService } from "./webauthn/webauthn-register.service.js";

/**
 * Phase 03 — 2FA module.
 *
 * Owns:
 *   - WebAuthn ceremony endpoints (begin/finish — register + auth).
 *   - TOTP endpoints land in Plan 03-03 (parallel) — that plan adds a
 *     `TotpController` and `TotpService` here via separate sub-folder.
 *   - Step-up JWT service + Require2FAStepUpGuard (consumed by all 2FA
 *     `auth` ceremony endpoints + by Plan 03-03 TOTP /verify).
 *
 * Imports `AuthModule` to reuse `JwtService` (the symmetric secret backing
 * the step-up token) and `SessionService` (full-session minting after
 * successful 2FA).
 */
@Module({
  imports: [AuthModule, DbModule],
  controllers: [WebauthnRegisterController],
  providers: [
    StepUpJwtService,
    Require2FAStepUpGuard,
    WebauthnRegisterService,
  ],
  exports: [StepUpJwtService, Require2FAStepUpGuard, WebauthnRegisterService],
})
export class TwoFaModule {}
