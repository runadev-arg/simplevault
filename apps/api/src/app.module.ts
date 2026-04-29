import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { LoggerModule } from "nestjs-pino";

import { AuthModule } from "./auth/auth.module.js";
import { CryptoModule } from "./crypto/crypto.module.js";
import { DbModule } from "./db/db.module.js";
import { HealthModule } from "./health/health.module.js";
import { InviteModule } from "./invite/invite.module.js";
import { RedisModule } from "./redis/redis.module.js";

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.LOG_LEVEL ?? "info",
        redact: {
          paths: [
            "req.headers.authorization",
            "req.headers.cookie",
            "res.headers['set-cookie']",
            "req.body.password",
            "req.body.secretKey",
            "req.body.secret_key",
            "req.body.recoveryPhrase",
            "req.body.recovery_phrase",
            "req.body.recovery",
            "req.body.jwt",
            "req.body.totpCode",
            "req.body.token",
            // Plan 02-07 signup body — every bytea field is redacted defence-in-depth.
            "req.body.code",
            "req.body.argon2SecretKeyHash",
            "req.body.wrappedMasterDek",
            "req.body.wrappedMasterDekRecovery",
            "req.body.wrappedUserSigningSk",
            "req.body.wrappedUserKxSk",
            "req.body.userPubKey",
            "req.body.recoveryInnerHash",
            "req.body.userArgonSalt",
            "req.body.serverArgonSalt",
          ],
          censor: "[REDACTED]",
        },
        autoLogging: { ignore: (req) => req.url === "/health" },
      },
    }),
    DbModule,
    RedisModule,
    CryptoModule,
    HealthModule,
    InviteModule,
    AuthModule,
  ],
})
export class AppModule {}
