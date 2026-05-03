import type { Logger } from "@nestjs/common";

/**
 * Frozen v1 audit-action enum.
 *
 * LOAD-BEARING for Phase 10 — the hash-chain implementation will append-only
 * link records of this exact shape. New v1 actions can be added; existing
 * field names + types are FROZEN. v2 must bump the `v` discriminator.
 *
 * Shape decision (from 02-09 plan + carry-overs §3):
 *   - `auth.<verb>.<outcome>` namespace for auth-domain events.
 *   - `invite.redeem.<outcome>` for the public invite-redeem-info endpoint.
 *   - `auth.refresh.reuse_detected` is its own action because Phase 10 will
 *     surface it as a high-severity row in the operator dashboard.
 *   - `rate_limit.exceeded` (Phase 13 hardening) is logged structurally so
 *     Phase 10 can pick it up without the action being in the v1 frozen
 *     enum. Treated as advisory; not chain-linked in v1.
 */
export const AuditAction = {
  SignupOk: "auth.signup.ok",
  SignupFail: "auth.signup.fail",
  LoginOk: "auth.login.ok",
  LoginFail: "auth.login.fail",
  Logout: "auth.logout",
  RefreshOk: "auth.refresh.ok",
  RefreshFail: "auth.refresh.fail",
  RefreshReuseDetected: "auth.refresh.reuse_detected",
  InviteRedeemOk: "invite.redeem.ok",
  InviteRedeemFail: "invite.redeem.fail",
  RateLimitExceeded: "rate_limit.exceeded",
  // Phase 03-02 — 2FA / WebAuthn ceremonies. The 11-action v1 enum extends
  // here per 03-INDEX (extension permitted within v1; field names + types
  // remain frozen).
  TwoFaWebauthnRegisterOk: "auth.2fa.webauthn.register.ok",
  TwoFaWebauthnRegisterFail: "auth.2fa.webauthn.register.fail",
  TwoFaWebauthnAuthOk: "auth.2fa.webauthn.auth.ok",
  TwoFaWebauthnAuthFail: "auth.2fa.webauthn.auth.fail",
  // Phase 03-03 — TOTP enrolment + verification (Key Links 3, 4).
  TwoFaTotpRegisterOk: "auth.2fa.totp.register.ok",
  TwoFaTotpRegisterFail: "auth.2fa.totp.register.fail",
  TwoFaTotpVerifyOk: "auth.2fa.totp.verify.ok",
  TwoFaTotpVerifyFail: "auth.2fa.totp.verify.fail",
  // Phase 03-06 — 2FA method management (Truth 10).
  // `data.kind` = "webauthn" | "totp" so the operator dashboard can
  // partition removals by authenticator type without re-querying.
  TwoFaMethodRemoved: "auth.2fa.method.removed",
  // Phase 03-05 — sessions API (Truths 12, 13). Both events follow the
  // `auth.<verb>.<outcome>` namespace established by Phase-02 events; targetId
  // is the sessionId (revoked) or userId (revoke_all).
  SessionRevoked: "auth.session.revoked",
  SessionRevokeAll: "auth.session.revoke_all",
} as const;

export type AuditActionValue = (typeof AuditAction)[keyof typeof AuditAction];

/**
 * Frozen v1 audit-event shape. Phase 10 will hash-chain-link records of this
 * type; do NOT add fields without bumping `v`.
 *
 * `data` is a flexible JSON object (free-form context for the row). It
 * MUST NOT contain any secret material — keys, ciphertexts, raw IPs,
 * passwords, tokens, etc. are forbidden. Free-form keys must be
 * non-PII-bearing or pre-hashed/derived.
 */
export interface AuditEvent {
  /** Schema version. Bumps require Phase 10 chain-bootstrap migration. */
  v: 1;
  ts: string; // ISO-8601
  action: AuditActionValue;
  actorUserId: string | null;
  targetId: string | null;
  outcome: "ok" | "fail";
  /** Bounded enum on failure (no PII). Optional otherwise. */
  reason?: string;
  /** HMAC of (SERVER_IP_HASH_SECRET, ip), base64 — NEVER raw IP. */
  ipHashB64?: string;
  /** Coarse UA family (Chrome/Firefox/Safari/Edge/Other-OS). NOT raw UA. */
  uaFamily?: string;
  /** Express request id for cross-log correlation. */
  requestId?: string;
  /** Free-form context — secret-free. */
  data?: Record<string, unknown>;
}

/**
 * Centralised emission point. v1 just writes a structured Pino info line
 * under the `audit` namespace. Phase 10 swaps this in-place for an
 * append-only hash-chain writer behind the same interface — call sites
 * MUST NOT log "audit-style" events directly.
 */
export class AuditEventService {
  static emit(
    logger: Pick<Logger, "log" | "warn">,
    event: {
      action: AuditActionValue;
      actorUserId: string | null;
      targetId: string | null;
      outcome: "ok" | "fail";
      ts?: string;
      reason?: string;
      ipHashB64?: string;
      uaFamily?: string;
      requestId?: string;
      data?: Record<string, unknown>;
    },
  ): void {
    const full: AuditEvent = {
      v: 1,
      ts: event.ts ?? new Date().toISOString(),
      action: event.action,
      actorUserId: event.actorUserId,
      targetId: event.targetId,
      outcome: event.outcome,
    };
    if (event.reason !== undefined) full.reason = event.reason;
    if (event.ipHashB64 !== undefined) full.ipHashB64 = event.ipHashB64;
    if (event.uaFamily !== undefined) full.uaFamily = event.uaFamily;
    if (event.requestId !== undefined) full.requestId = event.requestId;
    if (event.data !== undefined) full.data = event.data;
    const msg = full.action;
    // outcome=fail OR explicit reuse-detected escalates to warn for ops dashboards.
    if (full.outcome === "fail" || full.action === AuditAction.RefreshReuseDetected) {
      logger.warn({ audit: full }, msg);
    } else {
      logger.log({ audit: full }, msg);
    }
  }
}
