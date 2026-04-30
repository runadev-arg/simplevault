import { BadRequestException, Body, Controller, HttpCode, HttpStatus, Post } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";

import { RateLimits } from "../../common/throttler.config.js";

import { SignupSchema } from "./signup.dto.js";
import { SignupService } from "./signup.service.js";

@Controller("auth")
export class SignupController {
  constructor(private readonly signupSvc: SignupService) {}

  @Post("signup")
  @HttpCode(HttpStatus.CREATED)
  // REQ-RATELIMIT-003 — 3 signups / IP / hour. Redis-backed, shared across replicas.
  @Throttle({ [RateLimits.signupIp.name]: { limit: RateLimits.signupIp.limit, ttl: RateLimits.signupIp.ttl } })
  async signup(@Body() body: unknown): Promise<unknown> {
    const parsed = SignupSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: {
          code: ErrorCodes.VALIDATION_FAILED,
          message: "Invalid request body",
        },
      });
    }
    return this.signupSvc.signup(parsed.data);
  }
}
