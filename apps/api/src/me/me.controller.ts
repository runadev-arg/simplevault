import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { MeResponse } from "@simplevault/shared/zod";

import { JwtAuthGuard, type AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";
import { RateLimits } from "../common/throttler.config.js";

import { MeService } from "./me.service.js";

@Controller()
@UseGuards(JwtAuthGuard)
export class MeController {
  constructor(private readonly me: MeService) {}

  @Get("me")
  // 100 req / user / minute (post-auth keying via SimpleVaultThrottlerGuard).
  @Throttle({ [RateLimits.meUser.name]: { limit: RateLimits.meUser.limit, ttl: RateLimits.meUser.ttl } })
  async getMe(@Req() req: AuthedRequest): Promise<MeResponse> {
    return this.me.get(req.user.id);
  }
}
