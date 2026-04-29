import { BadRequestException, Body, Controller, HttpCode, HttpStatus, Post, Req } from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request } from "express";

import { clientIpKey, FixedWindowRateLimiter } from "../../common/rate-limit.js";

import { SignupSchema } from "./signup.dto.js";
import { SignupService } from "./signup.service.js";

@Controller("auth")
export class SignupController {
  // REQ-RATELIMIT-003: 3 signups / IP / hour. In-memory; 02-09 supersedes with Redis.
  // Env-tunable for E2E (02-12) so the test harness can disable; production
  // leaves these unset to use the defaults.
  private readonly limiter = new FixedWindowRateLimiter(
    "auth.signup",
    Number.parseInt(process.env.SIGNUP_RATE_LIMIT ?? "3", 10) || 3,
    Number.parseInt(process.env.SIGNUP_RATE_WINDOW_MS ?? "3600000", 10) || 3_600_000,
  );

  constructor(private readonly signupSvc: SignupService) {}

  @Post("signup")
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() body: unknown, @Req() req: Request): Promise<unknown> {
    this.limiter.consume(clientIpKey(req));

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
