import { Injectable } from "@nestjs/common";
import { sql } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * Phase 04 / Plan 03 — `VaultService.getPersonal`.
 *
 * Returns the authenticated user's personal vault id PLUS a metadata-ONLY
 * summary list of the credentials it owns. The list endpoint NEVER returns
 * `ciphertext`, `nonce`, or `aad_params_json` — Truth 1 (INDEX-adjusted)
 * deliberately constrains the wire shape to `{id, version, updatedAt}` so a
 * simple list-page-load never streams encrypted blobs the user can't see.
 *
 * IDOR is impossible by construction (Truth 19, vaults schema): the SELECT
 * is keyed on `(owner_user_id = req.user.id, kind = 'personal')` and the
 * partial-unique index `vaults_owner_personal_uidx` guarantees at most one
 * row per user. There is no `:id` parameter on the route.
 *
 * Defensive auto-heal: if Plan-04-01's signup-time backfill missed (legacy
 * row created pre-Plan-01), the missing personal vault row is INSERTed
 * inside the same transaction. Should never trigger in v1+ but keeps the
 * endpoint a non-throwing source of truth.
 */
type VaultSummaryRow = { id: string };
type CredentialSummaryRow = { id: string; version: number; updated_at: Date };

export interface PersonalVaultSummary {
  vaultId: string;
  credentialIds: Array<{ id: string; version: number; updatedAt: string }>;
}

@Injectable()
export class VaultService {
  constructor(private readonly db: DbService) {}

  async getPersonal(userId: string): Promise<PersonalVaultSummary> {
    return this.db.db.transaction(async (tx) => {
      const v = await tx.execute<VaultSummaryRow>(sql`
        SELECT id FROM vaults
        WHERE owner_user_id = ${userId} AND kind = 'personal'
        LIMIT 1
      `);
      const existing = v.rows[0];
      if (!existing) {
        // Should never happen post-Plan-04-01 backfill; defensive auto-heal.
        const inserted = await tx.execute<VaultSummaryRow>(sql`
          INSERT INTO vaults (owner_user_id, kind)
          VALUES (${userId}, 'personal')
          RETURNING id
        `);
        const newRow = inserted.rows[0];
        if (!newRow) throw new Error("vault insert returned no row");
        return { vaultId: newRow.id, credentialIds: [] };
      }
      const vaultId = existing.id;
      const creds = await tx.execute<CredentialSummaryRow>(sql`
        SELECT id, version, updated_at
        FROM credentials
        WHERE vault_id = ${vaultId}
        ORDER BY updated_at DESC
      `);
      return {
        vaultId,
        credentialIds: creds.rows.map((r) => ({
          id: r.id,
          version: r.version,
          updatedAt: r.updated_at instanceof Date ? r.updated_at.toISOString() : String(r.updated_at),
        })),
      };
    });
  }
}
