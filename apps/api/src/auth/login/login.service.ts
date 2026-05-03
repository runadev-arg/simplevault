import { Injectable, Logger } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { sql } from "drizzle-orm";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { constantTimeEqual32, dummyHash } from "../../common/timing-floor.js";
import { DbService } from "../../db/db.service.js";
import { JwtService } from "../jwt/jwt.service.js";
import { SessionService, type IssuedRefreshToken } from "../sessions/session.service.js";

import type { LoginDto, LoginResponseBody } from "./login.dto.js";

type UserRow = {
  id: string;
  email: string;
  argon2_secret_key_hash: Buffer;
  server_argon_salt: Buffer;
  argon2_params: { memoryKiB: number; iterations: number; parallelism: 1 };
  user_argon_salt: Buffer;
  wrapped_master_dek: Buffer;
  wrapped_master_dek_recovery: Buffer;
  user_pub_key: Buffer;
  wrapped_user_signing_sk: Buffer;
  wrapped_user_kx_sk: Buffer;
} & Record<string, unknown>;

export interface LoginOk {
  body: LoginResponseBody;
  refresh: IssuedRefreshToken;
}

/**
 * Login with timing-floor.
 *
 * Flow (REQ-CRYPTO-003-aware):
 *  1. Lookup user by lower(email).
 *  2. Pick verifier: row.argon2SecretKeyHash if present, else DUMMY_HASH.
 *  3. ALWAYS run constant-time compare (so the wall-time path is the same
 *     when the user doesn't exist as when the password is wrong).
 *  4. If user absent OR compare false -> 401 with the uniform error body.
 *  5. Otherwise -> SessionService.createOnLogin + JwtService.signAccessToken.
 *
 * Per Phase 02 INDEX (operator decision): /auth/params publishes the GLOBAL
 * argon2_params so the client can compute the verifier WITHOUT first calling
 * a per-user endpoint (anti-enumeration). The per-user `server_argon_salt`
 * is RETURNED IN THE 200 LOGIN RESPONSE BODY so the client can re-derive
 * the master_KEK locally — by definition, only a successful auth gets the
 * salt.
 */
@Injectable()
export class LoginService {
  private readonly logger = new Logger(LoginService.name);

  constructor(
    private readonly db: DbService,
    private readonly jwt: JwtService,
    private readonly sessions: SessionService,
  ) {}

  /** Returns null on auth failure (caller maps to 401 + emits failure log). */
  async login(input: LoginDto, ip: string, ua: string | undefined): Promise<LoginOk | null> {
    // Lookup by lower(email). Index `users_email_lower_idx` covers this.
    const rows = await this.db.db.execute<UserRow>(sql`
      SELECT id, email,
             argon2_secret_key_hash, server_argon_salt, argon2_params, user_argon_salt,
             wrapped_master_dek, wrapped_master_dek_recovery,
             user_pub_key, wrapped_user_signing_sk, wrapped_user_kx_sk
      FROM ${schema.users}
      WHERE lower(email) = lower(${input.email})
      LIMIT 1
    `);
    const user = rows.rows[0] ?? null;

    // Constant-time compare ALWAYS — DUMMY_HASH on miss to equalise wall-time.
    const verifier = user ? Buffer.from(user.argon2_secret_key_hash) : dummyHash();
    const candidate = input.argon2SecretKeyHash;
    const match = constantTimeEqual32(candidate, verifier);

    if (!user || !match) {
      // Failure log emitted by the controller (it has ip + ua context); the
      // service stays mute on failure to keep log lines from doubling.
      return null;
    }

    // Mint session + access token.
    const refresh = await this.sessions.createOnLogin(user.id, ip, ua);
    const accessToken = await this.jwt.signAccessToken({
      sub: user.id,
      sid: refresh.sessionId,
      fam: refresh.familyId,
      // Phase 03 hand-off: Plan 04 replaces this stub with the user's
      // current `users.session_epoch` (Redis-cached). Per Plan 03-02's
      // "Note for Plan 04 hand-off", surgical 3-line replacement.
      epoch: 0,
    });

    AuditEventService.emit(this.logger, {
      action: AuditAction.LoginOk,
      actorUserId: user.id,
      targetId: user.id,
      outcome: "ok",
      ipHashB64: this.sessions.hashIp(ip).toString("base64"),
      uaFamily: this.sessions.parseUaFamily(ua),
      data: { familyId: refresh.familyId },
    });

    const body: LoginResponseBody = {
      accessToken,
      expiresIn: this.jwt.accessTtlSeconds(),
      wrappedMasterDek: Buffer.from(user.wrapped_master_dek).toString("base64"),
      wrappedMasterDekRecovery: Buffer.from(user.wrapped_master_dek_recovery).toString("base64"),
      argon2Params: user.argon2_params,
      serverArgonSalt: Buffer.from(user.server_argon_salt).toString("base64"),
      userArgonSalt: Buffer.from(user.user_argon_salt).toString("base64"),
      userPubKey: Buffer.from(user.user_pub_key).toString("base64"),
      wrappedUserSigningSk: Buffer.from(user.wrapped_user_signing_sk).toString("base64"),
      wrappedUserKxSk: Buffer.from(user.wrapped_user_kx_sk).toString("base64"),
    };

    return { body, refresh };
  }
}
