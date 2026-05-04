import { BadRequestException, Body, Controller, HttpCode, HttpStatus, Post } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";

import { Public } from "../auth/jwt/public.decorator.js";
import { RateLimits } from "../common/throttler.config.js";

import { InviteRedeemSchema } from "./invite.dto.js";
import { InviteService } from "./invite.service.js";

@Controller("invite")
export class InviteController {
  constructor(private readonly invites: InviteService) {}

  @Post("redeem")
  @Public()
  @HttpCode(HttpStatus.OK)
  // 30 / IP / hour — lookup is cheap; advisory ceiling against scraping.
  @Throttle({ [RateLimits.inviteRedeemIp.name]: { limit: RateLimits.inviteRedeemIp.limit, ttl: RateLimits.inviteRedeemIp.ttl } })
  async redeem(@Body() body: unknown): Promise<unknown> {
    const parsed = InviteRedeemSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    return this.invites.redeem(parsed.data.code);
  }
}
