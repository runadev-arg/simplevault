import { Injectable, Logger } from "@nestjs/common";
import type { SessionListItem } from "@simplevault/shared/zod";

import { SessionService } from "../auth/sessions/session.service.js";
import { AuditAction, AuditEventService } from "../common/audit-events.js";

/**
 * Phase 03 / Plan 05 — `/sessions` API surface.
 *
 * Distinct from `apps/api/src/auth/sessions/session.service.ts` (the
 * refresh-rotation primitive). This module owns the user-facing session
 * management endpoints (Truths 11–13):
 *
 *   - GET    /sessions             — list active sessions for `req.user.id`.
 *   - DELETE /sessions/:id         — family-revoke that one session.
 *   - POST   /sessions/revoke-all  — family-revoke ALL + bumpEpoch.
 *
 * Heavy lifting (DB queries, epoch bump) is delegated to `SessionService`;
 * this layer is just controller-side orchestration + audit emission.
 */
@Injectable()
export class SessionsService {
  private readonly logger = new Logger(SessionsService.name);

  constructor(private readonly sessions: SessionService) {}

  async list(userId: string, currentSessionId: string): Promise<SessionListItem[]> {
    return this.sessions.listForUser(userId, currentSessionId);
  }

  /**
   * Returns true on revoke; false when the row doesn't belong to `userId` (or
   * doesn't exist / is already-revoked). Anti-enumeration: callers MUST map
   * `false` to 404 — NEVER 403, NEVER 200 — so a probe can't distinguish
   * "exists but not yours" from "doesn't exist".
   */
  async revokeOne(
    userId: string,
    sessionId: string,
    audit: { ipHashB64?: string; uaFamily?: string; requestId?: string },
  ): Promise<boolean> {
    const result = await this.sessions.revokeOne(userId, sessionId);
    if (!result) {
      // No audit emit on the not-found path — emitting a `session.revoked`
      // fail row keyed off a probed sessionId would itself become an
      // enumeration oracle (the requestId is the same shape, the row count
      // would differ from a real cross-user probe). Standard request-log
      // line still fires.
      return false;
    }
    AuditEventService.emit(this.logger, {
      action: AuditAction.SessionRevoked,
      actorUserId: userId,
      targetId: sessionId,
      outcome: "ok",
      ...(audit.ipHashB64 !== undefined ? { ipHashB64: audit.ipHashB64 } : {}),
      ...(audit.uaFamily !== undefined ? { uaFamily: audit.uaFamily } : {}),
      ...(audit.requestId !== undefined ? { requestId: audit.requestId } : {}),
      data: { familyId: result.familyId, revokedRows: result.revokedCount },
    });
    return true;
  }

  // `revokeAll` lives on a follow-up commit (T2) along with the bumpEpoch
  // wiring + cookie-clear behaviour.
}
