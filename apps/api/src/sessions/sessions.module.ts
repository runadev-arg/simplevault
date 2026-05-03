import { Module } from "@nestjs/common";

import { AuthModule } from "../auth/auth.module.js";

import { SessionsController } from "./sessions.controller.js";
import { SessionsService } from "./sessions.service.js";

/**
 * Phase 03 / Plan 05 — `/sessions` API module.
 *
 * Distinct from `apps/api/src/auth/sessions/` which owns the refresh-rotation
 * primitive (`SessionService`). This module is the user-facing CRUD surface:
 *   - `GET /sessions`
 *   - `DELETE /sessions/:id`
 *   - `POST /sessions/revoke-all`
 *
 * Imports `AuthModule` for `JwtAuthGuard` + `SessionService` (which exports
 * `listForUser`, `revokeOne`, `revokeAllForUser`).
 */
@Module({
  imports: [AuthModule],
  controllers: [SessionsController],
  providers: [SessionsService],
})
export class SessionsModule {}
