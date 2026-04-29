import { Module } from "@nestjs/common";

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
  providers: [SignupService, LoginService, JwtService, SessionService],
  exports: [SignupService, JwtService, SessionService],
})
export class AuthModule {}
