import { ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import express from "express";
import helmet from "helmet";
import { Logger } from "nestjs-pino";

import { AppModule } from "./app.module.js";
import { AllExceptionsFilter } from "./common/filters/all-exceptions.filter.js";
import { CREDENTIAL_BODY_MAX_BYTES } from "./credentials/credentials.constants.js";
import { PAGE_BODY_MAX_BYTES } from "./pages/pages.constants.js";

async function bootstrap(): Promise<void> {
  // Phase 04 Plan 03 — disable Nest's auto-mounted body parsers so we can
  // mount a route-scoped 64 KiB JSON cap for `/credentials/*` BEFORE the
  // default JSON parser. Express body-parser fires 413 above the cap; the
  // global filter maps `PayloadTooLargeError` → `CREDENTIAL_BODY_TOO_LARGE`.
  // FINDING-0015 partial closure: every other route keeps the Express
  // default (~100 KiB) — Phase 13 lands the global default cap.
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bufferLogs: true,
    bodyParser: false,
  });
  app.useLogger(app.get(Logger));

  // Route-scoped JSON body parser for `/credentials/*` (64 KiB cap).
  // Mount BEFORE the global parser so Express prefix-matches credentials
  // routes against this stricter limit first.
  app.use("/credentials", express.json({ limit: CREDENTIAL_BODY_MAX_BYTES }));
  // Phase 05 Plan 02 — route-scoped JSON body parser for `/pages/*` (256 KiB
  // default, env-tunable up to 1 MiB ceiling; see pages/pages.constants.ts).
  app.use("/pages", express.json({ limit: PAGE_BODY_MAX_BYTES }));
  // Default JSON + URL-encoded parsers for every other route — preserves
  // existing behaviour from when `{bodyParser: true}` was the default.
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Trust 1 proxy hop (Dokploy/Traefik). Adjust if multi-hop.
  app.set("trust proxy", 1);

  // Security headers (Helmet) — full CSP/HSTS managed here since Caddy is OUT.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "base-uri": ["'none'"],
          "frame-ancestors": ["'none'"],
          "object-src": ["'none'"],
          "script-src": ["'self'"],
          "style-src": ["'self'"],
          "connect-src": ["'self'"],
          "form-action": ["'self'"],
          "img-src": ["'self'", "data:", "blob:"],
          "upgrade-insecure-requests": [],
        },
      },
      crossOriginEmbedderPolicy: false,
      hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: "no-referrer" },
    }),
  );

  // CORS allowlist from env (CSV)
  const allowed = (process.env.CORS_ORIGINS ?? "http://localhost:3000").split(",").map((s) => s.trim());
  app.enableCors({
    origin: allowed,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "X-Request-Id"],
    exposedHeaders: ["X-Request-Id"],
    maxAge: 600,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: false },
    }),
  );
  app.useGlobalFilters(new AllExceptionsFilter());
  app.enableShutdownHooks();

  const port = Number(process.env.PORT ?? 3001);
  await app.listen(port, "0.0.0.0");
}

void bootstrap();
