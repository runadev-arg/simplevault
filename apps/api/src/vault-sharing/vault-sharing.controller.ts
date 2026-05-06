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
  Post,
  Query,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";

import type { AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";
import { AuditAction, AuditEventService } from "../common/audit-events.js";
import { RateLimits } from "../common/throttler.config.js";
import { Require2FAGuard } from "../twofa/require-2fa.guard.js";

import {
  VaultSharingService,
  type MemberSummary,
  type PendingInvite,
  type VaultListItem,
} from "./vault-sharing.service.js";

/**
 * Phase 07 / Plan 02 — VaultSharingController.
 *
 * Routes:
 *   POST   /vaults/group              — create a group vault
 *   GET    /vaults                    — list all accessible vaults
 *   GET    /users/lookup?email=...    — resolve email → public key
 *   GET    /vaults/:id/invites        — list pending invites (owner view)
 *   POST   /vaults/:id/invites        — send invite
 *   GET    /invites                   — list pending invites (invitee view)
 *   POST   /invites/:inviteId/accept  — accept invite
 *   POST   /invites/:inviteId/decline — decline invite
 *   GET    /vaults/:id/members        — list active members
 *   DELETE /vaults/:id/members/:userId — remove member / leave vault
 *
 * Require2FAGuard is stacked after JwtAuthGuard (APP_GUARD) to enforce 2FA
 * for all shared-vault management routes (REQ-2FA-003 / Phase 07 mandate).
 */
@Controller()
@UseGuards(Require2FAGuard)
export class VaultSharingController {
  private readonly logger = new Logger(VaultSharingController.name);

  constructor(private readonly svc: VaultSharingService) {}

  // ------------------------------------------------------------------ POST /vaults/group

  @Post("vaults/group")
  @HttpCode(HttpStatus.CREATED)
  @Throttle({
    [RateLimits.vaultSharingCreate.name]: {
      limit: RateLimits.vaultSharingCreate.limit,
      ttl: RateLimits.vaultSharingCreate.ttl,
    },
  })
  async createGroupVault(
    @Req() req: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ id: string; name: string; kind: string }> {
    const b = body as Record<string, unknown> | null | undefined;
    const name = typeof b?.name === "string" ? b.name : null;
    const wrappedVaultKey = typeof b?.wrappedVaultKey === "string" ? b.wrappedVaultKey : null;
    if (!name || !wrappedVaultKey) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "name and wrappedVaultKey are required" },
      });
    }
    const result = await this.svc.createGroupVault(req.user.id, name, wrappedVaultKey);
    AuditEventService.emit(this.logger, {
      action: AuditAction.VaultCreate,
      actorUserId: req.user.id,
      targetId: result.id,
      outcome: "ok",
      data: { kind: "shared" },
    });
    return result;
  }

  // ------------------------------------------------------------------ GET /vaults

  @Get("vaults")
  @Throttle({
    [RateLimits.vaultListUser.name]: {
      limit: RateLimits.vaultListUser.limit,
      ttl: RateLimits.vaultListUser.ttl,
    },
  })
  async listAllVaults(@Req() req: AuthedRequest): Promise<VaultListItem[]> {
    return this.svc.listAllVaults(req.user.id);
  }

  // ------------------------------------------------------------------ GET /users/lookup

  @Get("users/lookup")
  @Throttle({
    [RateLimits.vaultUserLookup.name]: {
      limit: RateLimits.vaultUserLookup.limit,
      ttl: RateLimits.vaultUserLookup.ttl,
    },
  })
  async lookupUser(
    @Req() req: AuthedRequest,
    @Query("email") email: string,
  ): Promise<{ id: string; kxPublicKey: string }> {
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || typeof email !== "string" || email.length > 254 || !EMAIL_RE.test(email)) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "valid email query parameter is required" },
      });
    }
    return this.svc.lookupUser(req.user.id, email);
  }

  // ------------------------------------------------------------------ GET /vaults/:id/invites

  @Get("vaults/:id/invites")
  @Throttle({
    [RateLimits.vaultListUser.name]: {
      limit: RateLimits.vaultListUser.limit,
      ttl: RateLimits.vaultListUser.ttl,
    },
  })
  async getVaultInvites(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe()) id: string,
  ): Promise<PendingInvite[]> {
    return this.svc.getVaultInvites(req.user.id, id);
  }

  // ------------------------------------------------------------------ POST /vaults/:id/invites

  @Post("vaults/:id/invites")
  @HttpCode(HttpStatus.NO_CONTENT)
  @Throttle({
    [RateLimits.vaultSharingInvite.name]: {
      limit: RateLimits.vaultSharingInvite.limit,
      ttl: RateLimits.vaultSharingInvite.ttl,
    },
  })
  async createInvite(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ): Promise<void> {
    const b = body as Record<string, unknown> | null | undefined;
    const inviteeId = typeof b?.inviteeId === "string" ? b.inviteeId : null;
    const wrappedVaultKey = typeof b?.wrappedVaultKey === "string" ? b.wrappedVaultKey : null;
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!inviteeId || !wrappedVaultKey) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "inviteeId and wrappedVaultKey are required" },
      });
    }
    if (!UUID_RE.test(inviteeId)) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "inviteeId must be a valid UUID" },
      });
    }
    // Sealed-box wrappedVaultKey is 80 bytes → 107 base64url chars; cap at 256.
    if (wrappedVaultKey.length > 256) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "wrappedVaultKey exceeds maximum length" },
      });
    }
    await this.svc.createInvite(req.user.id, id, inviteeId, wrappedVaultKey);
    AuditEventService.emit(this.logger, {
      action: AuditAction.VaultInviteSent,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
      data: { inviteeId },
    });
  }

  // ------------------------------------------------------------------ GET /invites

  @Get("invites")
  @Throttle({
    [RateLimits.vaultListUser.name]: {
      limit: RateLimits.vaultListUser.limit,
      ttl: RateLimits.vaultListUser.ttl,
    },
  })
  async getPendingInvites(@Req() req: AuthedRequest): Promise<PendingInvite[]> {
    return this.svc.getPendingInvitesForUser(req.user.id);
  }

  // ------------------------------------------------------------------ POST /invites/:inviteId/accept

  @Post("invites/:inviteId/accept")
  @HttpCode(HttpStatus.NO_CONTENT)
  async acceptInvite(
    @Req() req: AuthedRequest,
    @Param("inviteId", new ParseUUIDPipe()) inviteId: string,
  ): Promise<void> {
    await this.svc.acceptInvite(req.user.id, inviteId);
    AuditEventService.emit(this.logger, {
      action: AuditAction.VaultInviteAccepted,
      actorUserId: req.user.id,
      targetId: inviteId,
      outcome: "ok",
    });
  }

  // ------------------------------------------------------------------ POST /invites/:inviteId/decline

  @Post("invites/:inviteId/decline")
  @HttpCode(HttpStatus.NO_CONTENT)
  async declineInvite(
    @Req() req: AuthedRequest,
    @Param("inviteId", new ParseUUIDPipe()) inviteId: string,
  ): Promise<void> {
    await this.svc.declineInvite(req.user.id, inviteId);
    AuditEventService.emit(this.logger, {
      action: AuditAction.VaultInviteDeclined,
      actorUserId: req.user.id,
      targetId: inviteId,
      outcome: "ok",
    });
  }

  // ------------------------------------------------------------------ GET /vaults/:id/members

  @Get("vaults/:id/members")
  @Throttle({
    [RateLimits.vaultListUser.name]: {
      limit: RateLimits.vaultListUser.limit,
      ttl: RateLimits.vaultListUser.ttl,
    },
  })
  async listMembers(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe()) id: string,
  ): Promise<MemberSummary[]> {
    return this.svc.listActiveMembers(req.user.id, id);
  }

  // ------------------------------------------------------------------ DELETE /vaults/:id/members/:userId

  @Delete("vaults/:id/members/:userId")
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeMember(
    @Req() req: AuthedRequest,
    @Param("id", new ParseUUIDPipe()) id: string,
    @Param("userId", new ParseUUIDPipe()) userId: string,
  ): Promise<void> {
    await this.svc.removeMember(req.user.id, id, userId);
    AuditEventService.emit(this.logger, {
      action: AuditAction.VaultMemberRemoved,
      actorUserId: req.user.id,
      targetId: id,
      outcome: "ok",
      data: { removedUserId: userId, self: req.user.id === userId },
    });
  }
}
