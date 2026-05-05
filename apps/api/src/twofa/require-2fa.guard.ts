import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
} from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { eq, sql } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * Minimal contract for the 2FA-method counter consumed by `Require2FAGuard`.
 *
 * Lives as an interface (not a hard `MethodsService` import) so that:
 *
 * 1. The guard can be unit-tested with a stub (see `test/2fa-required-guard.spec.ts`)
 *    without standing up a real DbService + Redis.
 * 2. Plan 06's `MethodsService.countActive(userId)` is the natural production
 *    binding — it implements this same shape via two `count()` queries — but
 *    until Plan 06 lands, the default `DbBackedRequire2FACountReader` (below)
 *    runs the same query inline. Either provider satisfies the contract; the
 *    guard does not care which is wired.
 */
export interface Require2FACountReader {
  countActive(userId: string): Promise<number>;
}

/**
 * Injection token for the count reader. Bound in `TwoFaModule` to either
 * `MethodsService` (Plan 06) or `DbBackedRequire2FACountReader` (Plan 07
 * fallback — single source of the count query so swapping providers in
 * Plan 06 is purely a `useExisting` change).
 */
export const REQUIRE_2FA_COUNT_READER = Symbol("REQUIRE_2FA_COUNT_READER");

/**
 * Default DB-backed reader used by `Require2FAGuard` when no other provider
 * is bound. Single round trip via `UNION ALL` of two 1-row count selects
 * (Phase 03 INDEX Truth 15: "Single round trip preferred").
 *
 * Plan 06 ships a `MethodsService.countActive` that does the same thing as
 * part of the `/2fa/methods` controller surface; once that lands the
 * provider binding can switch to `useExisting: MethodsService` without any
 * change to this guard.
 */
@Injectable()
export class DbBackedRequire2FACountReader implements Require2FACountReader {
  constructor(private readonly db: DbService) {}

  async countActive(userId: string): Promise<number> {
    // Single round trip: UNION ALL of the two cardinality probes. Postgres
    // executes both `count(*)` subselects in one statement and returns two
    // rows; we sum them in JS. Avoids two RTTs and keeps the guard's hot
    // path cheap.
    const wa = schema.webauthnCredentials;
    const totp = schema.totpCredentials;
    const rows = await this.db.db.execute<{ n: number }>(sql`
      SELECT COUNT(*)::int AS n FROM ${wa} WHERE ${eq(wa.userId, userId)}
      UNION ALL
      SELECT COUNT(*)::int AS n FROM ${totp} WHERE ${eq(totp.userId, userId)}
    `);
    let total = 0;
    // drizzle's pg driver returns `{ rows: [...] }` for raw SQL; normalise.
    const list = (rows as unknown as { rows?: { n: number }[] }).rows ?? (rows as unknown as { n: number }[]);
    for (const r of list) {
      const n = typeof r.n === "number" ? r.n : Number(r.n);
      total += Number.isFinite(n) ? n : 0;
    }
    return total;
  }
}

/**
 * `Require2FAGuard` — Phase 03 INDEX Truth 15 + Key Link 8.
 *
 * Asserts the request's authenticated user has ≥1 active 2FA method (webauthn
 * or totp). Reserved for the future `vault.create` / `vault.join` routes
 * (Phase 07 — `/shared-vaults/*`). The Phase-03 stub probe route under
 * `/vault/...` was retired in Plan 04-01 once the real personal-vault routes
 * became imminent; this guard implementation stays put for that Phase-07
 * reuse.
 *
 * MUST be stacked AFTER `JwtAuthGuard` so `req.user.id` is populated. If the
 * principal is missing the guard fails closed with 401 (defence-in-depth —
 * an unauthed request reaching this guard is a routing bug, not a 2FA gap).
 *
 * Phase 06 (Plan 06) reuses this exact guard via the same module export; the
 * removal-guard's `userHasSharedVaultDependency(userId)` helper lives in a
 * sibling file `two-fa-guard.ts` and is unrelated to this class.
 */
@Injectable()
export class Require2FAGuard implements CanActivate {
  private readonly logger = new Logger(Require2FAGuard.name);

  constructor(
    @Inject(REQUIRE_2FA_COUNT_READER)
    private readonly counts: Require2FACountReader,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context
      .switchToHttp()
      .getRequest<{ user?: { id?: string } }>();
    const userId = req.user?.id;
    if (!userId) {
      // Defence-in-depth — JwtAuthGuard should have run before us. If it
      // didn't, treat as unauthenticated and emit the same uniform 401 the
      // access-token guard would emit.
      this.logger.warn(
        { evt: "require2fa.guard.deny", reason: "missing_principal" },
        "require2fa.guard.deny",
      );
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
        HttpStatus.UNAUTHORIZED,
      );
    }

    const n = await this.counts.countActive(userId);
    if (n < 1) {
      this.logger.debug(
        { evt: "require2fa.guard.deny", reason: "no_2fa_method", userId },
        "require2fa.guard.deny",
      );
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_2FA_REQUIRED, message: "2FA enrollment required" } },
        HttpStatus.FORBIDDEN,
      );
    }
    return true;
  }
}
