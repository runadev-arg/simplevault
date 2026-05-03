import { Module } from "@nestjs/common";

import { AuthModule } from "../auth/auth.module.js";
import { DbModule } from "../db/db.module.js";

import { MethodsController } from "./methods/methods.controller.js";
import { MethodsService } from "./methods/methods.service.js";
import {
  DbBackedRequire2FACountReader,
  REQUIRE_2FA_COUNT_READER,
  Require2FAGuard,
} from "./require-2fa.guard.js";
import { StepUpJwtService } from "./step-up/step-up-jwt.service.js";
import { Require2FAStepUpGuard } from "./step-up/step-up.guard.js";
import { TotpController } from "./totp/totp.controller.js";
import { TotpService } from "./totp/totp.service.js";
import { WebauthnAuthController } from "./webauthn/webauthn-auth.controller.js";
import { WebauthnAuthService } from "./webauthn/webauthn-auth.service.js";
import { WebauthnRegisterController } from "./webauthn/webauthn-register.controller.js";
import { WebauthnRegisterService } from "./webauthn/webauthn-register.service.js";

/**
 * Phase 03 — 2FA module.
 *
 * Owns:
 *   - WebAuthn ceremony endpoints (begin/finish — register + auth).
 *   - TOTP enrolment + verification endpoints (begin/finish-register +
 *     /verify). The TOTP secret is BROWSER-ONLY — the server stores only
 *     the wrapped blob + AAD bytes (Plan 03-03, Key Link 3).
 *   - Step-up JWT service + Require2FAStepUpGuard (consumed by all 2FA
 *     `auth` ceremony endpoints + by TOTP /verify).
 *
 * Imports `AuthModule` to reuse `JwtService` (the symmetric secret backing
 * the step-up token) and `SessionService` (full-session minting after
 * successful 2FA). RedisModule is `@Global()` so TotpService can inject
 * RedisService for the issuance-nonce cache without an explicit import.
 */
@Module({
  imports: [AuthModule, DbModule],
  controllers: [
    WebauthnRegisterController,
    WebauthnAuthController,
    TotpController,
    MethodsController,
  ],
  providers: [
    StepUpJwtService,
    Require2FAStepUpGuard,
    WebauthnRegisterService,
    WebauthnAuthService,
    TotpService,
    MethodsService,
    DbBackedRequire2FACountReader,
    { provide: REQUIRE_2FA_COUNT_READER, useExisting: DbBackedRequire2FACountReader },
    Require2FAGuard,
  ],
  exports: [
    StepUpJwtService,
    Require2FAStepUpGuard,
    WebauthnRegisterService,
    WebauthnAuthService,
    TotpService,
    MethodsService,
    Require2FAGuard,
    REQUIRE_2FA_COUNT_READER,
  ],
})
export class TwoFaModule {}
