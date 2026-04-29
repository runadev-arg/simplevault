import { Module } from "@nestjs/common";

import { JwtAuthGuard } from "./jwt/jwt-auth.guard.js";
import { JwtService } from "./jwt/jwt.service.js";
import { LoginController } from "./login/login.controller.js";
import { LoginService } from "./login/login.service.js";
import { LogoutController } from "./logout/logout.controller.js";
import { RefreshController } from "./refresh/refresh.controller.js";
import { SessionService } from "./sessions/session.service.js";
import { SignupController } from "./signup/signup.controller.js";
import { SignupService } from "./signup/signup.service.js";

@Module({
  controllers: [SignupController, LoginController, RefreshController, LogoutController],
  providers: [SignupService, LoginService, JwtService, SessionService, JwtAuthGuard],
  exports: [SignupService, JwtService, SessionService, JwtAuthGuard],
})
export class AuthModule {}
