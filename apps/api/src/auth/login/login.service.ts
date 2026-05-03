import { forwardRef, Inject, Injectable, Logger } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { sql } from "drizzle-orm";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { constantTimeEqual32, dummyHash } from "../../common/timing-floor.js";
import { DbService } from "../../db/db.service.js";
import { MethodsService } from "../../twofa/methods/methods.service.js";
import { StepUpJwtService } from "../../twofa/step-up/step-up-jwt.service.js";
import { JwtService } from "../jwt/jwt.service.js";
import { SessionService, type IssuedRefreshToken } from "../sessions/session.service.js";

import type { LoginDto, LoginResponseBody, LoginStepUpResponseBody } from "./login.dto.js";

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

/** Phase-02 happy path — full session minted, refresh cookie about to be set. */
export interface LoginOk {
  kind: "session";
  body: LoginResponseBody;
  refresh: IssuedRefreshToken;
}

/**
 * Phase 03 Plan 08 — 2FA-required branch (Truth 8).
 *
 * 1FA verified, but the user has ≥1 active 2FA method → no session minted.
 * Caller (`LoginController`) returns the step-up body WITHOUT setting the
 * `__Host-refresh` cookie. The user is still on the way to a session; that
 * happens on `/2fa/webauthn/finish-auth` or `/2fa/totp/verify`.
 */
export interface LoginStepUp {
  kind: "2fa-required";
  body: LoginStepUpResponseBody;
}

export type LoginResult = LoginOk | LoginStepUp;

/**
 * Login with timing-floor.
 *
 * Flow (REQ-CRYPTO-003-aware):
 *  1. Lookup user by lower(email).
 *  2. Pick verifier: row.argon2SecretKeyHash if present, else DUMMY_HASH.
 *  3. ALWAYS run constant-time compare (so the wall-time path is the same
 *     when the user doesn't exist as when the password is wrong).
 *  4. If user absent OR compare false -> 401 with the uniform error body.
 *  5. Otherwise — branch on whether the user has ≥1 active 2FA method:
 *      - 0 methods → Phase-02 behaviour (mint session + body unchanged).
 *      - ≥1 method → mint a step-up token, return the 2FA-required body.
 *        NO refresh family is created on this branch.
 *
 * The 2FA-vs-no-2FA branch HAPPENS AFTER 1FA verification. Pre-1FA paths
 * (wrong creds, unknown user) return the canonical 401 envelope byte-equal
 * across both 2FA-enrolled and 2FA-free users — preserves Phase-02 anti-
 * enumeration (Truth 8 + Key Link 5).
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
    // Phase 03 Plan 08 — both injected via forwardRef to break the
    // AuthModule ↔ TwoFaModule cycle. TwoFaModule already imports AuthModule
    // (for JwtService); now AuthModule's LoginService needs StepUpJwtService
    // + MethodsService for the 2FA branch. forwardRef makes the cycle a
    // resolution-time concern that NestJS handles via deferred provider
    // wiring, with zero runtime cost after bootstrap.
    @Inject(forwardRef(() => MethodsService))
    private readonly methods: MethodsService,
    @Inject(forwardRef(() => StepUpJwtService))
    private readonly stepUpJwt: StepUpJwtService,
  ) {}

  /** Returns null on auth failure (caller maps to 401 + emits failure log). */
  async login(input: LoginDto, ip: string, ua: string | undefined): Promise<LoginResult | null> {
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
      // CRITICAL (anti-enumeration, Truth 8): we have NOT yet looked up the
      // user's 2FA methods at this point. The wrong-creds path is byte-
      // identical across 2FA-enrolled and 2FA-free users.
      return null;
    }

    // 1FA verified. Branch on 2FA presence.
    //
    // `methods.countActive` = COUNT(webauthn_credentials WHERE user_id) +
    //                        COUNT(totp_credentials WHERE user_id).
    // Two SELECTs by indexed `user_id` — single-digit ms.
    const activeCount = await this.methods.countActive(user.id);
    const ipHashB64 = this.sessions.hashIp(ip).toString("base64");
    const uaFamily = this.sessions.parseUaFamily(ua);

    if (activeCount >= 1) {
      // ---- 2FA-required branch (Truth 8) ----
      // Per-kind counts so the response can advertise which ceremonies are
      // available (webauthnAvailable / totpAvailable) — UX hint for the web
      // client. The branch firing means at least one of them is true.
      const epoch = await this.sessions.getEpoch(user.id);
      const stepUpToken = await this.stepUpJwt.sign(user.id, epoch);
      const counts = await this.methods.countByKind(user.id);

      AuditEventService.emit(this.logger, {
        action: AuditAction.LoginStepUpIssued,
        actorUserId: user.id,
        targetId: user.id,
        outcome: "ok",
        ipHashB64,
        uaFamily,
        // `kind: "step-up"` — forensic marker per Truth 8 must-have. A
        // future operator dashboard can partition `auth.login.*` events by
        // outcome flavour (session vs step-up vs fail) without re-querying.
        data: { kind: "step-up" },
      });

      const body: LoginStepUpResponseBody = {
        kind: "2fa-required",
        stepUpToken,
        twoFa: {
          webauthnAvailable: counts.webauthn > 0,
          totpAvailable: counts.totp > 0,
        },
      };
      return { kind: "2fa-required", body };
    }

    // ---- 1FA-only branch (Phase-02 unchanged) ----
    // Mint session + access token.
    const refresh = await this.sessions.createOnLogin(user.id, ip, ua);
    const epoch = await this.sessions.getEpoch(user.id);
    const accessToken = await this.jwt.signAccessToken({
      sub: user.id,
      sid: refresh.sessionId,
      fam: refresh.familyId,
      // Phase 03 / Plan 04 — current `users.session_epoch` (Redis-cached
      // via SessionEpochCache, TTL 60s). Any subsequent revoke-all bumps
      // this column + busts the cache; this access token will be rejected
      // on its next request.
      epoch,
    });

    AuditEventService.emit(this.logger, {
      action: AuditAction.LoginOk,
      actorUserId: user.id,
      targetId: user.id,
      outcome: "ok",
      ipHashB64,
      uaFamily,
      // `kind: "session"` — Truth 8 must-have. Pairs with `kind: "step-up"`
      // on `LoginStepUpIssued`; together they let the operator dashboard
      // tell at a glance whether a successful login produced a full session
      // or only a step-up token.
      data: { familyId: refresh.familyId, kind: "session" },
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

    return { kind: "session", body, refresh };
  }
}
