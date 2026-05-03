import { forwardRef, Module } from "@nestjs/common";

import { TwoFaModule } from "../twofa/twofa.module.js";

import { JwtAuthGuard } from "./jwt/jwt-auth.guard.js";
import { JwtService } from "./jwt/jwt.service.js";
import { LoginController } from "./login/login.controller.js";
import { LoginService } from "./login/login.service.js";
import { LogoutController } from "./logout/logout.controller.js";
import { RefreshController } from "./refresh/refresh.controller.js";
import { SessionEpochCache } from "./sessions/session-epoch.cache.js";
import { SessionService } from "./sessions/session.service.js";
import { SignupController } from "./signup/signup.controller.js";
import { SignupService } from "./signup/signup.service.js";

/**
 * AuthModule.
 *
 * Phase 03 Plan 08 — `forwardRef(() => TwoFaModule)` breaks the
 * AuthModule ↔ TwoFaModule cycle introduced when `LoginService` started
 * branching on 2FA presence (it now depends on `MethodsService` +
 * `StepUpJwtService`, both exported by TwoFaModule). TwoFaModule already
 * imported AuthModule (for JwtService); the cycle is resolved at the
 * module-graph layer by forwardRef on BOTH sides + at the provider layer
 * by `@Inject(forwardRef(() => ...))` on the LoginService constructor
 * params. NestJS docs:
 *   https://docs.nestjs.com/fundamentals/circular-dependency
 */
@Module({
  imports: [forwardRef(() => TwoFaModule)],
  controllers: [SignupController, LoginController, RefreshController, LogoutController],
  providers: [SignupService, LoginService, JwtService, SessionService, SessionEpochCache, JwtAuthGuard],
  exports: [SignupService, JwtService, SessionService, SessionEpochCache, JwtAuthGuard],
})
export class AuthModule {}
