import { createHash } from "node:crypto";

import { ThrottlerStorageRedisService } from "@nest-lab/throttler-storage-redis";
import { type ExecutionContext, Injectable, Logger } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import {
  ThrottlerGuard,
  ThrottlerModule,
  type ThrottlerLimitDetail,
  type ThrottlerModuleOptions,
} from "@nestjs/throttler";
import { Redis } from "ioredis";

// IMPORTANT (Phase 03 / Plan 09 — FINDING-0022 fix). The throttler runs
// BEFORE Nest's validation pipes (guards execute before pipes). That means
// any field this file reads from `req.body` is UNVALIDATED — an attacker can
// post arbitrary lengths or types. Every key derived from request input
// MUST be bounded to a fixed length BEFORE being used as a Redis key (e.g.
// hash + slice). Otherwise Redis memory grows linearly with attacker
// input — see FINDING-0022 for the original report. The defence-in-depth
// second layer is the storage cap on `users.email` (varchar 254, FINDING
// 0017 fix landed in Plan 01); the cap on the wire was added to LoginSchema
// + SignupSchema in Plan 01 too, but Zod runs AFTER guards, so we still
// can't trust it here.

/**
 * Throttler ceilings (REQ-RATELIMIT-001..006 + 02-09 plan).
 *
 * Module-level config declares ONE "default" coarse throttler that applies
 * to every route as the global anti-abuse ceiling. Per-route limits are
 * declared via `@Throttle({"<name>": {limit, ttl}})` using the constants
 * exported below — env-tunable for E2E (02-12 hammers them; production
 * leaves the env vars unset to use the safe defaults).
 *
 * NestJS throttler semantics: a route's `@Throttle({...})` ENTRIES merge
 * with the module-level "default" config keyed by name. We deliberately
 * give every per-route ceiling its OWN name so they don't collide with
 * "default" and so each appears as its own `x-ratelimit-*-<name>` header
 * for observability.
 */
function intEnv(v: string | undefined, fallback: number): number {
  if (!v) return fallback;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Per-route ceilings. Values resolved at module-load time (env-driven). */
export const RateLimits = {
  loginIp: { name: "login-ip", limit: intEnv(process.env.LOGIN_IP_RATE_LIMIT, 5), ttl: 60_000 },
  loginEmail: { name: "login-email", limit: intEnv(process.env.LOGIN_EMAIL_RATE_LIMIT, 10), ttl: 60 * 60_000 },
  signupIp: { name: "signup-ip", limit: intEnv(process.env.SIGNUP_RATE_LIMIT, 3), ttl: 60 * 60_000 },
  refreshIp: { name: "refresh-ip", limit: intEnv(process.env.REFRESH_IP_RATE_LIMIT, 60), ttl: 60_000 },
  logoutIp: { name: "logout-ip", limit: intEnv(process.env.LOGOUT_IP_RATE_LIMIT, 60), ttl: 60_000 },
  authParamsIp: { name: "auth-params-ip", limit: intEnv(process.env.AUTH_PARAMS_RATE_LIMIT, 100), ttl: 60_000 },
  inviteRedeemIp: { name: "invite-redeem-ip", limit: intEnv(process.env.INVITE_REDEEM_RATE_LIMIT, 30), ttl: 60 * 60_000 },
  meUser: { name: "me-user", limit: intEnv(process.env.ME_RATE_LIMIT, 100), ttl: 60_000 },
  // Phase 03-02 — 2FA enrolment + WebAuthn ceremony ceilings. User-keyed.
  twoFaRegisterUser: {
    name: "2fa-register-user",
    limit: intEnv(process.env.TWOFA_REGISTER_RATE_LIMIT, 10),
    ttl: 60_000,
  },
  twoFaWebauthnAuthIp: {
    name: "2fa-webauthn-auth-ip",
    limit: intEnv(process.env.TWOFA_WEBAUTHN_AUTH_RATE_LIMIT, 30),
    ttl: 60_000,
  },
  // Phase 03-03 — TOTP /verify ceiling. Step-up-token-bearer route (no
  // req.user yet); IP-keyed via the default getTracker.
  twoFaVerifyIp: {
    name: "2fa-verify-ip",
    limit: intEnv(process.env.TWOFA_VERIFY_RATE_LIMIT, 30),
    ttl: 60_000,
  },
  // Phase 03-05 — sessions API ceilings. User-keyed via `req.user.id`
  // (post-JwtAuthGuard). Until Plan 09 lands the APP_GUARD reorder, the
  // throttler runs BEFORE the JWT guard — `req.user.id` is undefined and
  // `generateKey` falls back to IP-keying for these names. That is tolerable
  // for the Plan-05↔Plan-09 lag because the absolute IP-keyed ceilings are
  // still tight (60/30 per minute is sub-abuse for any plausible IP); the
  // user-keying just becomes effective once Plan 09 reorders the guards.
  sessionsListUser: {
    name: "sessions-list-user",
    limit: intEnv(process.env.SESSIONS_LIST_RATE_LIMIT, 60),
    ttl: 60_000,
  },
  sessionsRevokeUser: {
    name: "sessions-revoke-user",
    limit: intEnv(process.env.SESSIONS_REVOKE_RATE_LIMIT, 30),
    ttl: 60_000,
  },
  sessionsRevokeAllUser: {
    name: "sessions-revoke-all-user",
    limit: intEnv(process.env.SESSIONS_REVOKE_ALL_RATE_LIMIT, 5),
    ttl: 60_000,
  },
  // Phase 03-06 — 2FA method management ceilings. User-keyed via `req.user.id`
  // (post-JwtAuthGuard). Same Plan-09 caveat as the sessions ceilings: the
  // throttler currently runs BEFORE the JWT guard so these silently fall back
  // to IP-keying until the APP_GUARD reorder lands.
  twoFaMethodsListUser: {
    name: "2fa-methods-list-user",
    limit: intEnv(process.env.TWOFA_METHODS_LIST_RATE_LIMIT, 60),
    ttl: 60_000,
  },
  twoFaMethodsDeleteUser: {
    name: "2fa-methods-delete-user",
    limit: intEnv(process.env.TWOFA_METHODS_DELETE_RATE_LIMIT, 30),
    ttl: 60_000,
  },
  // Phase 04 Plan 03 — credentials + vault-list ceilings. All user-keyed via
  // `req.user.id` (post-FINDING-0021 closure: APP_GUARD ordering in app.module
  // populates req.user before this guard runs). Names are referenced by
  // sibling Plan 04-02's `@Throttle({...})` decorators and by Plan 04-03's
  // VaultController — verify-grep at end-of-wave confirms exact matches.
  // Rationale:
  // - `credentials-write-user` 60/min: write-burst cap (REQ-RATELIMIT spirit).
  //   POST /credentials + PATCH /credentials/:id + DELETE /credentials/:id
  //   share this ceiling so a runaway client can't hammer all three at once.
  // - `credentials-read-user` 300/min: matches REQ-RATELIMIT-006 (vault-read
  //   user). Reads are cheap (one PK lookup) but still capped to bound the
  //   per-user request budget.
  // - `vault-list-user` 120/min: GET /vault/personal — list-page-load cap.
  //   Generous because the endpoint is a single SELECT + summary mapping;
  //   amplification is bounded by N credentials (≤low-thousands at v1 scale).
  credentialsWriteUser: {
    name: "credentials-write-user",
    limit: intEnv(process.env.CREDENTIALS_WRITE_RATE_LIMIT, 60),
    ttl: 60_000,
  },
  credentialsReadUser: {
    name: "credentials-read-user",
    limit: intEnv(process.env.CREDENTIALS_READ_RATE_LIMIT, 300),
    ttl: 60_000,
  },
  vaultListUser: {
    name: "vault-list-user",
    limit: intEnv(process.env.VAULT_LIST_RATE_LIMIT, 120),
    ttl: 60_000,
  },
} as const;

/**
 * `ThrottlerGuard` subclass that:
 *   - keys `me-user` by `req.user.id` (post-JWT-guard) — falls back to IP;
 *   - keys `login-email` by lowercased `req.body.email`;
 *   - everything else falls back to IP via the `getTracker` default.
 *
 * `Retry-After` (in seconds) header is set on every 429.
 *
 * Storage outage = fail OPEN with a warn-log (Phase 13 may decide to
 * tighten to fail-closed).
 */
@Injectable()
export class SimpleVaultThrottlerGuard extends ThrottlerGuard {
  private readonly storageLogger = new Logger(SimpleVaultThrottlerGuard.name);

  override async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      return await super.canActivate(context);
    } catch (err) {
      if (
        err instanceof Error &&
        /Stream isn't writeable|ECONNREFUSED|ENOTFOUND|Connection is closed/i.test(err.message)
      ) {
        this.storageLogger.warn({ err: err.message }, "throttler storage unavailable; allowing request");
        return true;
      }
      throw err;
    }
  }

  protected override generateKey(context: ExecutionContext, suffix: string, name: string): string {
    const req = context.switchToHttp().getRequest<{
      user?: { id?: string };
      body?: Record<string, unknown>;
    }>();
    let tracker = suffix;
    const userKeyed =
      name === "me-user" ||
      name === "2fa-register-user" ||
      name === "sessions-list-user" ||
      name === "sessions-revoke-user" ||
      name === "sessions-revoke-all-user" ||
      name === "2fa-methods-list-user" ||
      name === "2fa-methods-delete-user" ||
      // Phase 04 Plan 03 — credentials + vault-list ceilings (all user-keyed).
      name === "credentials-write-user" ||
      name === "credentials-read-user" ||
      name === "vault-list-user";
    if (userKeyed && typeof req.user?.id === "string") {
      tracker = `user:${req.user.id}`;
    } else if (name === "login-email") {
      const body = req.body;
      const email = typeof body?.email === "string" ? body.email.toLowerCase() : "no-email";
      // FINDING-0022 fix (Plan 09): hash + slice to bound the Redis key
      // length and remove the lowercased-email PII from the key. 16 hex chars
      // = 64 bits of collision resistance — at our ≤50-user scale, accidental
      // collisions are negligible AND the throttle would only be tightened by
      // a colliding pair (false-positive 429), never loosened. Length is fixed
      // at 16 regardless of input — caps Redis memory growth from a flood of
      // arbitrary-length email values.
      const hashed = createHash("sha256").update(email).digest("hex").slice(0, 16);
      tracker = `em:${hashed}`;
    }
    return `${name}:${tracker}`;
  }

  protected override async throwThrottlingException(
    context: ExecutionContext,
    throttlerLimitDetail: ThrottlerLimitDetail,
  ): Promise<void> {
    const res = context.switchToHttp().getResponse<{
      setHeader?: (k: string, v: string | number) => void;
    }>();
    const ttlSec = Math.max(1, Math.ceil(throttlerLimitDetail.ttl / 1000));
    res.setHeader?.("Retry-After", ttlSec);
    return super.throwThrottlingException(context, throttlerLimitDetail);
  }
}

/**
 * Async `ThrottlerModule` factory using Redis storage so all replicas share
 * counters. Module-level config has only the "default" coarse global
 * ceiling; per-route limits come from `RateLimits.*` consumed by
 * `@Throttle(...)` decorators on each controller method.
 */
export const ThrottlerConfigModule = ThrottlerModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService): ThrottlerModuleOptions => {
    const url = config.get<string>("REDIS_URL") ?? process.env.REDIS_URL ?? "redis://localhost:6379";
    const redis = new Redis(url, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
    });
    redis.on("error", () => {
      /* swallow; storage outage is fail-open via SimpleVaultThrottlerGuard */
    });
    return {
      throttlers: [
        {
          name: "default",
          ttl: 15 * 60_000,
          limit: intEnv(process.env.GLOBAL_RATE_LIMIT, 1000),
        },
      ],
      storage: new ThrottlerStorageRedisService(redis),
      // Skip throttling for the health endpoint (Dokploy/k8s probes).
      skipIf: (ctx) => {
        const req = ctx.switchToHttp().getRequest<{ url?: string }>();
        return req.url === "/health";
      },
    };
  },
});
