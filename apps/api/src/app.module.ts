import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { LoggerModule } from "nestjs-pino";

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
          ],
          censor: "[REDACTED]",
        },
        autoLogging: { ignore: (req) => req.url === "/health" },
      },
    }),
  ],
})
export class AppModule {}
