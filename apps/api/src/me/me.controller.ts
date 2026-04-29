import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import type { MeResponse } from "@simplevault/shared/zod";

import { JwtAuthGuard, type AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";

import { MeService } from "./me.service.js";

@Controller()
@UseGuards(JwtAuthGuard)
export class MeController {
  constructor(private readonly me: MeService) {}

  @Get("me")
  async getMe(@Req() req: AuthedRequest): Promise<MeResponse> {
    return this.me.get(req.user.id);
  }
}
