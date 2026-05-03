import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";
import { SessionListResponseSchema, type SessionListItem } from "@simplevault/shared/zod";

import { JwtAuthGuard, type AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";
import { RateLimits } from "../common/throttler.config.js";

import { SessionsService } from "./sessions.service.js";

/**
 * Phase 03 / Plan 05 — `/sessions` controller (Truths 11–13).
 *
 *   - GET    /sessions             — list active sessions for the caller.
 *   - DELETE /sessions/:id         — family-revoke that session. Cross-user
 *                                    or unknown id → 404 (NOT 403 — Truth 12
 *                                    anti-enumeration).
 *
 * `POST /sessions/revoke-all` lands in T2 (next commit) along with the
 * bumpEpoch wiring + revoke-all-user throttler ceiling + cookie clear.
 *
 * All endpoints require `JwtAuthGuard` (auth required). Output schemas are
 * `.parse(...)`'d server-side as a defence-in-depth check against ORM
 * hydration leaks.
 */
@Controller("sessions")
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Get()
  @Throttle({
    [RateLimits.sessionsListUser.name]: {
      limit: RateLimits.sessionsListUser.limit,
      ttl: RateLimits.sessionsListUser.ttl,
    },
  })
  async list(@Req() req: AuthedRequest): Promise<SessionListItem[]> {
    const items = await this.sessions.list(req.user.id, req.user.sessionId);
    // Defence-in-depth: parse the strict-allowlist schema before responding.
    // A future ORM-hydration leak surfaces as a 500, not a silent exfil.
    return SessionListResponseSchema.parse(items);
  }

  @Delete(":id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({
    [RateLimits.sessionsRevokeUser.name]: {
      limit: RateLimits.sessionsRevokeUser.limit,
      ttl: RateLimits.sessionsRevokeUser.ttl,
    },
  })
  async revokeOne(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) sessionId: string,
  ): Promise<void> {
    const requestId = req.headers["x-request-id"];
    const ok = await this.sessions.revokeOne(req.user.id, sessionId, {
      ...(typeof requestId === "string" ? { requestId } : {}),
    });
    if (!ok) {
      // Truth 12: cross-user or non-existent → uniform 404. NEVER 403.
      throw new NotFoundException({
        error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Not found" },
      });
    }
    // 204, no body — keeps the response identical for "I revoked my current
    // session" vs "I revoked a sibling session".
  }
}
