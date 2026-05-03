import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";
import {
  TwoFaMethodsListSchema,
  type TwoFaMethod,
} from "@simplevault/shared/zod";

import { JwtAuthGuard, type AuthedRequest } from "../../auth/jwt/jwt-auth.guard.js";
import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { RateLimits } from "../../common/throttler.config.js";

import { MethodsService } from "./methods.service.js";

/**
 * `/2fa/methods` controller — list + delete user's 2FA methods.
 *
 * SECURITY (Truth 9, 10):
 *   - List output goes through `TwoFaMethodsListSchema.parse(...)` as a
 *     defence-in-depth check before responding (catches future ORM
 *     hydration leaks at runtime).
 *   - Cross-user DELETE → 404 (NOT 403). Anti-enumeration posture.
 *   - DELETE emits `2fa.method.removed` audit on success.
 *
 * The removal-guard (`userHasSharedVaultDependency`) is wired in T2 — see
 * `methods.controller` + `two-fa-guard.ts` for the seam to Phase 07.
 */
@Controller("2fa/methods")
@UseGuards(JwtAuthGuard)
export class MethodsController {
  private readonly logger = new Logger(MethodsController.name);

  constructor(private readonly methods: MethodsService) {}

  // ---------------------------------------------------------------- list

  @Get()
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaMethodsListUser.name]: {
      limit: RateLimits.twoFaMethodsListUser.limit,
      ttl: RateLimits.twoFaMethodsListUser.ttl,
    },
  })
  async list(@Req() req: AuthedRequest): Promise<TwoFaMethod[]> {
    const items = await this.methods.list(req.user.id);
    // Defence-in-depth: re-parse our own output. A future ORM leak
    // surfaces as a 500, not a silent secret exfil.
    return TwoFaMethodsListSchema.parse(items);
  }

  // ---------------------------------------------------------------- delete

  @Delete(":id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({
    [RateLimits.twoFaMethodsDeleteUser.name]: {
      limit: RateLimits.twoFaMethodsDeleteUser.limit,
      ttl: RateLimits.twoFaMethodsDeleteUser.ttl,
    },
  })
  async remove(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) methodId: string,
  ): Promise<void> {
    // T2: removal-guard wired (Truth 10 + Phase 07 hand-off seam).
    // Throws 409 AUTH_2FA_REMOVAL_BLOCKED when the user would be left with
    // 0 active 2FA AND `userHasSharedVaultDependency(userId)` returns true.
    // Phase 03 stub returns false unconditionally — exercised via the
    // `2fa-removal.spec.ts` integration test that flips the dep to true.
    const result = await this.methods.removeGuarded(req.user.id, methodId);
    if (!result) {
      // Truth 10: cross-user attempts (or non-existent ids) collapse to a
      // uniform 404. NEVER 403 — that would confirm the id exists.
      throw new NotFoundException({
        error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Not found" },
      });
    }
    AuditEventService.emit(this.logger, {
      action: AuditAction.TwoFaMethodRemoved,
      actorUserId: req.user.id,
      targetId: methodId,
      outcome: "ok",
      data: { kind: result.kind },
    });
  }
}
