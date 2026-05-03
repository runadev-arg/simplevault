import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/types";
import { eq } from "drizzle-orm";

import { JwtAuthGuard, type AuthedRequest } from "../../auth/jwt/jwt-auth.guard.js";
import { RateLimits } from "../../common/throttler.config.js";
import { DbService } from "../../db/db.service.js";

import { WebauthnRegisterService } from "./webauthn-register.service.js";
import { FinishRegisterSchema } from "./webauthn.dto.js";

@Controller("2fa/webauthn")
@UseGuards(JwtAuthGuard)
export class WebauthnRegisterController {
  constructor(
    private readonly registerSvc: WebauthnRegisterService,
    private readonly db: DbService,
  ) {}

  /**
   * `POST /2fa/webauthn/begin-register` — emit the registration ceremony
   * options + persist the challenge.
   */
  @Post("begin-register")
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaRegisterUser.name]: {
      limit: RateLimits.twoFaRegisterUser.limit,
      ttl: RateLimits.twoFaRegisterUser.ttl,
    },
  })
  async beginRegister(@Req() req: AuthedRequest): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const userId = req.user.id;
    const emailRows = await this.db.db
      .select({ email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    const email = emailRows[0]?.email ?? "";
    if (!email) {
      // User has a valid JWT but has been deleted — unusual but possible.
      throw new BadRequestException({
        error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "User not found" },
      });
    }
    return await this.registerSvc.beginRegister(userId, email);
  }

  /**
   * `POST /2fa/webauthn/finish-register` — verify the attestation and
   * persist the credential row. Atomic challenge consume in the service.
   */
  @Post("finish-register")
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaRegisterUser.name]: {
      limit: RateLimits.twoFaRegisterUser.limit,
      ttl: RateLimits.twoFaRegisterUser.ttl,
    },
  })
  async finishRegister(
    @Req() req: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ id: string; name: string }> {
    const parsed = FinishRegisterSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    return await this.registerSvc.finishRegister(
      req.user.id,
      // Cast: Zod-validated minimal shape + library-trusted `passthrough`.
      parsed.data.response as unknown as Parameters<
        WebauthnRegisterService["finishRegister"]
      >[1],
      parsed.data.name,
    );
  }
}

