import { SetMetadata } from "@nestjs/common";

/**
 * Phase 03 / Plan 09 — opt-out marker for the global `JwtAuthGuard`
 * (registered as APP_GUARD in `app.module.ts`).
 *
 * `JwtAuthGuard.canActivate` reads this metadata via `Reflector` and short-
 * circuits to `true` when present, allowing unauthenticated routes (e.g.
 * /health, /auth/login, /auth/refresh) to coexist with the global auth
 * guard. Step-up routes that authenticate via `Require2FAStepUpGuard` also
 * use `@Public()` to opt out of `JwtAuthGuard`'s access-token check (their
 * step-up tokens carry `purpose:"2fa-stepup"`, which `JwtAuthGuard`
 * deliberately rejects — see Key Link 5 in 03-INDEX).
 *
 * Usage:
 *   ```ts
 *   @Public()
 *   @Get("health")
 *   health() { ... }
 *   ```
 */
export const IS_PUBLIC_KEY = "isPublic";
export const Public = (): MethodDecorator & ClassDecorator => SetMetadata(IS_PUBLIC_KEY, true);
