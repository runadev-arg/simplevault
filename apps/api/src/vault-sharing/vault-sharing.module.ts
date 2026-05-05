import { Module } from "@nestjs/common";

import { TwoFaModule } from "../twofa/twofa.module.js";

import { VaultSharingController } from "./vault-sharing.controller.js";
import { VaultSharingService } from "./vault-sharing.service.js";

/**
 * Phase 07 / Plan 02 — VaultSharingModule.
 *
 * Exposes all shared-vault management routes (create, list, invite, accept,
 * decline, members). Imports TwoFaModule to provide Require2FAGuard (enforced
 * at the controller level for all routes — REQ-2FA-003 / Phase 07 mandate).
 *
 * DbService is global, so no explicit DbModule import is needed.
 */
@Module({
  imports: [TwoFaModule],
  providers: [VaultSharingService],
  controllers: [VaultSharingController],
})
export class VaultSharingModule {}
