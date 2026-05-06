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
  Query,
  Req,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";
import { PageCreateSchema, PageUpdateSchema } from "@simplevault/shared/zod";

import type { AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";
import { AuditAction, AuditEventService } from "../common/audit-events.js";
import { RateLimits } from "../common/throttler.config.js";

import {
  type PageHistoryEntry,
  type PageListItem,
  type PageResponse,
  PagesService,
} from "./pages.service.js";

/**
 * Phase 05 / Plan 02 — `/pages` REST surface.
 *
 * Routes:
 *   - GET    /pages?q=<hex>       — list (metadata only) / title-prefix search
 *   - POST   /pages               — create
 *   - GET    /pages/:id           — read (full envelope)
 *   - PATCH  /pages/:id           — atomic CAS update + history rotation
 *   - DELETE /pages/:id           — delete (204)
 *   - GET    /pages/:id/history   — last 10 ciphertext snapshots
 *
 * KEY INVARIANTS:
 *   - APP_GUARD `JwtAuthGuard` authenticates every route. NO `Require2FAGuard`
 *     here — REQ-2FA-003 (personal vault is 2FA-optional).
 *   - `ParseUUIDPipe` on `:id` keeps the 400-vs-404 disambiguation consistent.
 *   - Cross-user / not-found returns uniform 404 `PAGE_NOT_FOUND` (Truth 3).
 *   - Server NEVER parses page plaintext — body is opaque ciphertext.
 *
 * Audit emission lands in T3 (extends `AuditAction` enum + emits per route).
 */
@Controller()
export class PagesController {
  private readonly logger = new Logger(PagesController.name);

  constructor(private readonly svc: PagesService) {}

  @Get("pages")
  @Throttle({
    [RateLimits.pagesSearchUser.name]: {
      limit: RateLimits.pagesSearchUser.limit,
      ttl: RateLimits.pagesSearchUser.ttl,
    },
  })
  async list(
    @Req() req: AuthedRequest,
    @Query("q") q?: string,
  ): Promise<PageListItem[]> {
    let normQ: string | undefined;
    if (q !== undefined) {
      if (typeof q !== "string" || !/^[0-9a-fA-F]{1,16}$/.test(q)) {
        throw new BadRequestException({
          error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid q (expected 1..16 hex chars)" },
        });
      }
      normQ = q.toLowerCase();
    }
    return this.svc.list(req.user.id, normQ);
  }

  @Post("pages")
  @HttpCode(HttpStatus.CREATED)
  @Throttle({
    [RateLimits.pagesWriteUser.name]: {
      limit: RateLimits.pagesWriteUser.limit,
      ttl: RateLimits.pagesWriteUser.ttl,
    },
  })
  async create(@Req() req: AuthedRequest, @Body() body: unknown): Promise<PageResponse> {
    const parsed = PageCreateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    const result = await this.svc.create(req.user.id, parsed.data);
    AuditEventService.emit(this.logger, {
      action: AuditAction.PageCreate,
      actorUserId: req.user.id,
      targetId: result.id,
      outcome: "ok",
      data: { vaultId: result.vaultId, version: result.version },
    });
    return result;
  }

  @Get("pages/:id")
  @Throttle({
    [RateLimits.pagesReadUser.name]: {
      limit: RateLimits.pagesReadUser.limit,
      ttl: RateLimits.pagesReadUser.ttl,
    },
  })
  async getById(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ): Promise<PageResponse> {
    const result = await this.svc.getById(req.user.id, id);
    AuditEventService.emit(this.logger, {
      action: AuditAction.PageView,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
      data: { vaultId: result.vaultId, version: result.version },
    });
    return result;
  }

  @Patch("pages/:id")
  @Throttle({
    [RateLimits.pagesWriteUser.name]: {
      limit: RateLimits.pagesWriteUser.limit,
      ttl: RateLimits.pagesWriteUser.ttl,
    },
  })
  async update(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
    @Body() body: unknown,
  ): Promise<PageResponse> {
    const parsed = PageUpdateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    const result = await this.svc.update(req.user.id, id, parsed.data);
    AuditEventService.emit(this.logger, {
      action: AuditAction.PageUpdate,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
      data: { vaultId: result.vaultId, version: result.version },
    });
    return result;
  }

  @Delete("pages/:id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({
    [RateLimits.pagesWriteUser.name]: {
      limit: RateLimits.pagesWriteUser.limit,
      ttl: RateLimits.pagesWriteUser.ttl,
    },
  })
  async delete(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ): Promise<void> {
    await this.svc.delete(req.user.id, id);
    AuditEventService.emit(this.logger, {
      action: AuditAction.PageDelete,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
    });
  }

  @Get("pages/:id/history")
  @Throttle({
    [RateLimits.pagesReadUser.name]: {
      limit: RateLimits.pagesReadUser.limit,
      ttl: RateLimits.pagesReadUser.ttl,
    },
  })
  async history(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe({ version: "4" })) id: string,
  ): Promise<PageHistoryEntry[]> {
    return this.svc.history(req.user.id, id);
  }
}
