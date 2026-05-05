import { Module } from "@nestjs/common";

import { AuthModule } from "../auth/auth.module.js";

import { VaultController } from "./vault.controller.js";
import { VaultService } from "./vault.service.js";

/**
 * Phase 04 / Plan 03 — `VaultModule`.
 *
 * Exposes `GET /vault/personal` (auth required). DbService is global, so the
 * service depends on it via DI without explicit imports.
 */
@Module({
  imports: [AuthModule],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
