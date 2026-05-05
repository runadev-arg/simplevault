import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Req,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";

import type { AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";
import { AuditAction, AuditEventService } from "../common/audit-events.js";
import { RateLimits } from "../common/throttler.config.js";

import { CredentialCreateSchema, CredentialUpdateSchema } from "./credentials.dto.js";
import { CredentialsService, type CredentialResponse } from "./credentials.service.js";

/**
 * Phase 04 / Plan 02 — `/credentials` REST surface.
 *
 * Routes:
 *   - POST   /credentials       — create
 *   - GET    /credentials/:id   — read
 *   - PATCH  /credentials/:id   — atomic CAS update
 *   - DELETE /credentials/:id   — delete (204)
 *
 * KEY INVARIANTS (04-INDEX):
 *   - APP_GUARD `JwtAuthGuard` (FINDING-0021 carry-over) authenticates every
 *     route; the controller class is INTENTIONALLY NOT decorated with
 *     `@UseGuards(Require2FAGuard)` — REQ-2FA-003: personal vault is
 *     2FA-optional (Key Link 3). Phase 07 will reuse Require2FAGuard for
 *     `/shared-vaults/*`, never personal-vault routes.
 *   - `ParseUUIDPipe` on `:id` (FINDING-0051 carry-posture) keeps the
 *     400-vs-404 disambiguation consistent with every other route.
 *   - Cross-user / not-found returns uniform 404 `CREDENTIAL_NOT_FOUND`
 *     (Truth 3 anti-enumeration; the service guarantees this).
 *
 * Audit: emits `credential.{create,view,update,delete}` on success
 * (CredentialCreate / CredentialView / CredentialUpdate / CredentialDelete
 * — added to the v1 enum in this commit; Plan 04-11 finalises the redact
 * list). Failure paths are NOT audit-emitted — same posture as
 * `DELETE /sessions/:id` (Phase 03 Plan 05) where emitting a fail row keyed
 * off a probed id would itself become an enumeration oracle. Standard
 * request-log lines still fire on failure.
 */
@Controller()
export class CredentialsController {
  private readonly logger = new Logger(CredentialsController.name);

  constructor(private readonly svc: CredentialsService) {}

  // ----------------------------------------------------------------- POST

  @Post("credentials")
  @HttpCode(HttpStatus.CREATED)
  @Throttle({
    [RateLimits.credentialsWriteUser.name]: {
      limit: RateLimits.credentialsWriteUser.limit,
      ttl: RateLimits.credentialsWriteUser.ttl,
    },
  })
  async create(@Req() req: AuthedRequest, @Body() body: unknown): Promise<CredentialResponse> {
    const parsed = CredentialCreateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    const r = await this.svc.create(req.user.id, parsed.data);
    AuditEventService.emit(this.logger, {
      action: AuditAction.CredentialCreate,
      actorUserId: req.user.id,
      targetId: r.id,
      outcome: "ok",
      data: { credentialId: r.id, vaultId: r.vaultId, version: r.version },
    });
    return r;
  }

  // ----------------------------------------------------------------- GET

  @Get("credentials/:id")
  @Throttle({
    [RateLimits.credentialsReadUser.name]: {
      limit: RateLimits.credentialsReadUser.limit,
      ttl: RateLimits.credentialsReadUser.ttl,
    },
  })
  async getById(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ): Promise<CredentialResponse> {
    const r = await this.svc.getById(req.user.id, id);
    AuditEventService.emit(this.logger, {
      action: AuditAction.CredentialView,
      actorUserId: req.user.id,
      targetId: r.id,
      outcome: "ok",
      data: { credentialId: r.id, vaultId: r.vaultId, version: r.version },
    });
    return r;
  }

  // ----------------------------------------------------------------- PATCH

  @Patch("credentials/:id")
  @Throttle({
    [RateLimits.credentialsWriteUser.name]: {
      limit: RateLimits.credentialsWriteUser.limit,
      ttl: RateLimits.credentialsWriteUser.ttl,
    },
  })
  async update(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: unknown,
  ): Promise<CredentialResponse> {
    const parsed = CredentialUpdateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    const r = await this.svc.update(req.user.id, id, parsed.data);
    AuditEventService.emit(this.logger, {
      action: AuditAction.CredentialUpdate,
      actorUserId: req.user.id,
      targetId: r.id,
      outcome: "ok",
      data: { credentialId: r.id, vaultId: r.vaultId, version: r.version },
    });
    return r;
  }

  // ----------------------------------------------------------------- DELETE

  @Delete("credentials/:id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({
    [RateLimits.credentialsWriteUser.name]: {
      limit: RateLimits.credentialsWriteUser.limit,
      ttl: RateLimits.credentialsWriteUser.ttl,
    },
  })
  async delete(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ): Promise<void> {
    await this.svc.delete(req.user.id, id);
    AuditEventService.emit(this.logger, {
      action: AuditAction.CredentialDelete,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
      data: { credentialId: id },
    });
  }
}
