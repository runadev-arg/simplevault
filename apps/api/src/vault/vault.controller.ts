import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";

import { JwtAuthGuard, type AuthedRequest } from "../auth/jwt/jwt-auth.guard.js";

import { VaultService, type PersonalVaultSummary } from "./vault.service.js";

/**
 * Phase 04 / Plan 03 — `GET /vault/personal`.
 *
 * Returns `{vaultId, credentialIds: [{id, version, updatedAt}]}` — METADATA
 * ONLY (no ciphertext, no nonce, no AAD params). The web client fans out a
 * `GET /credentials/:id` per visible card via intersection-observer-driven
 * lazy load (handoff to Plan 04-09).
 *
 * Anti-IDOR: no `:id` parameter; service SELECTs `WHERE owner_user_id =
 * req.user.id AND kind = 'personal'` — cross-user lookup is impossible by
 * construction (Truth 19 / vaults_owner_personal_uidx).
 *
 * NO audit-event emit (Truth 17 — list-page-loads are not auditable
 * actions, and emitting on every poll would amplify the audit log).
 *
 * Throttler: keyed by `req.user.id` via the `vault-list-user` ceiling
 * (declared in `apps/api/src/common/throttler.config.ts`, Plan 04-03 T3).
 */
@Controller("vault")
@UseGuards(JwtAuthGuard)
export class VaultController {
  constructor(private readonly svc: VaultService) {}

  @Get("personal")
  @Throttle({ "vault-list-user": { limit: 120, ttl: 60_000 } })
  async getPersonal(@Req() req: AuthedRequest): Promise<PersonalVaultSummary> {
    return this.svc.getPersonal(req.user.id);
  }
}
