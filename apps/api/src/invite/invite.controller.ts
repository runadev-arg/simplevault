import { BadRequestException, Body, Controller, HttpCode, HttpStatus, Post, Req } from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request } from "express";

import { clientIpKey, FixedWindowRateLimiter } from "../common/rate-limit.js";

import { InviteRedeemSchema } from "./invite.dto.js";
import { InviteService } from "./invite.service.js";

@Controller("invite")
export class InviteController {
  // 30 / IP / hour (lookup is cheap; advisory ceiling against scraping).
  private readonly limiter = new FixedWindowRateLimiter("invite.redeem", 30, 60 * 60 * 1000);

  constructor(private readonly invites: InviteService) {}

  @Post("redeem")
  @HttpCode(HttpStatus.OK)
  async redeem(@Body() body: unknown, @Req() req: Request): Promise<unknown> {
    this.limiter.consume(clientIpKey(req));

    const parsed = InviteRedeemSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    return this.invites.redeem(parsed.data.code);
  }
}
