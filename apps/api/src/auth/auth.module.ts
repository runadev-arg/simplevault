import { Module } from "@nestjs/common";

import { SignupController } from "./signup/signup.controller.js";
import { SignupService } from "./signup/signup.service.js";

@Module({
  controllers: [SignupController],
  providers: [SignupService],
  exports: [SignupService],
})
export class AuthModule {}
