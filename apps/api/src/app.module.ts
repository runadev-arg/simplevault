import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { APP_GUARD } from "@nestjs/core";
import { LoggerModule } from "nestjs-pino";

import { AuthModule } from "./auth/auth.module.js";
import { SimpleVaultThrottlerGuard, ThrottlerConfigModule } from "./common/throttler.config.js";
import { CryptoModule } from "./crypto/crypto.module.js";
import { DbModule } from "./db/db.module.js";
import { HealthModule } from "./health/health.module.js";
import { InviteModule } from "./invite/invite.module.js";
import { MeModule } from "./me/me.module.js";
import { RedisModule } from "./redis/redis.module.js";
import { SessionsModule } from "./sessions/sessions.module.js";
import { TwoFaModule } from "./twofa/twofa.module.js";

/**
 * Pino redaction list — comprehensive enumeration of every sensitive field
 * name surfaced anywhere in the app (req body, req headers, res body, res
 * headers). The CSP nonce header path (`x-nonce`) is INTENTIONALLY NOT
 * redacted — CSP nonces are per-request public values; redacting them would
 * just hide useful debug info without any security benefit.
 *
 * Path syntax follows pino: dotted paths + `*` wildcards. Field names
 * appearing in arbitrary nesting depth are covered by `*.field`.
 */
const PINO_REDACT_PATHS = [
  // -------- HTTP headers (always sensitive)
  "req.headers.authorization",
  "req.headers.Authorization",
  "req.headers.cookie",
  "req.headers.Cookie",
  "req.headers['set-cookie']",
  "req.headers['Set-Cookie']",
  "res.headers['set-cookie']",
  "res.headers['Set-Cookie']",
  // -------- Generic credentials in bodies
  "req.body.password",
  "req.body.secretKey",
  "req.body.secret_key",
  "req.body.recoveryPhrase",
  "req.body.recovery_phrase",
  "req.body.mnemonic",
  "req.body.recovery",
  "req.body.recovery_lookup_hash",
  "req.body.recoveryLookupHash",
  "req.body.jwt",
  "req.body.totpCode",
  "req.body.token",
  "req.body.code",
  // -------- Phase 02-07 signup body — every bytea field defence-in-depth.
  "req.body.argon2SecretKeyHash",
  "req.body.argon2_secret_key_hash",
  "req.body.wrappedMasterDek",
  "req.body.wrapped_master_dek",
  "req.body.wrappedMasterDekRecovery",
  "req.body.wrapped_master_dek_recovery",
  "req.body.wrappedUserSigningSk",
  "req.body.wrapped_user_signing_sk",
  "req.body.wrappedUserKxSk",
  "req.body.wrapped_user_kx_sk",
  "req.body.userPubKey",
  "req.body.user_pub_key",
  "req.body.recoveryInnerHash",
  "req.body.recovery_inner_hash",
  "req.body.userArgonSalt",
  "req.body.user_argon_salt",
  "req.body.serverArgonSalt",
  "req.body.server_argon_salt",
  // -------- Phase 02-08 login/refresh body
  "req.body.accessToken",
  "req.body.access_token",
  "req.body.refreshToken",
  "req.body.refresh_token",
  // -------- Response bodies (login/refresh emit wrapped material).
  "res.body.accessToken",
  "res.body.wrappedMasterDek",
  "res.body.wrappedMasterDekRecovery",
  "res.body.wrappedUserSigningSk",
  "res.body.wrappedUserKxSk",
  // -------- AEAD nonce — explicitly the body-level field, NOT the CSP
  // x-nonce header (CSP nonces are public per-request and fine to log).
  "req.body.nonce",
  "res.body.nonce",
  // -------- Wildcards for nested logger contexts (`logger.info({ data: { dek } })`).
  "*.dek",
  "*.kek",
  "*.master_kek",
  "*.masterKek",
  "*.recovery_kek",
  "*.recoveryKek",
  "*.argon2SecretKeyHash",
  "*.argon2_secret_key_hash",
  "*.wrappedMasterDek",
  "*.wrapped_master_dek",
  "*.wrappedMasterDekRecovery",
  "*.wrapped_master_dek_recovery",
  "*.wrappedUserSigningSk",
  "*.wrapped_user_signing_sk",
  "*.wrappedUserKxSk",
  "*.wrapped_user_kx_sk",
  "*.userPubKey",
  "*.user_pub_key",
  "*.serverArgonSalt",
  "*.server_argon_salt",
  "*.userArgonSalt",
  "*.user_argon_salt",
  "*.recoveryHmac",
  "*.recovery_hmac",
  "*.recoveryPhrase",
  "*.recovery_phrase",
  "*.mnemonic",
  "*.refreshToken",
  "*.refresh_token",
  "*.accessToken",
  "*.access_token",
  "*.password",
  "*.secretKey",
  "*.secret_key",
  "*.recovery_lookup_hash",
];

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.LOG_LEVEL ?? "info",
        redact: {
          paths: PINO_REDACT_PATHS,
          censor: "[REDACTED]",
        },
        autoLogging: { ignore: (req) => req.url === "/health" },
      },
    }),
    DbModule,
    RedisModule,
    CryptoModule,
    ThrottlerConfigModule,
    HealthModule,
    InviteModule,
    AuthModule,
    MeModule,
    TwoFaModule,
    // Phase 03 Plan 05 — `/sessions` user-facing API (list / revoke-one /
    // revoke-all). Distinct from `auth/sessions/SessionService` which is the
    // refresh-rotation primitive; this module is the controller surface.
    SessionsModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: SimpleVaultThrottlerGuard }],
})
export class AppModule {}
