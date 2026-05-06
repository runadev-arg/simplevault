import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import { sql } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * Phase 04 / Plan 02 — credentials CRUD service.
 *
 * GREEN (T2). The CAS-PATCH is the load-bearing primitive that ties the
 * AAD `version` field to anti-rollback (Key Link 2 of 04-INDEX). Every
 * mutation goes through ONE atomic SQL statement that joins on
 * `vaults.owner_user_id = $userId` — IDOR is impossible by construction
 * because the query has no row to update unless the caller owns it.
 *
 * Failure-disambiguation on PATCH (the only load-bearing branch — load it
 * carefully):
 *   1. Try the atomic CAS UPDATE. Zero rows means EITHER (a) the row
 *      doesn't exist or belongs to another user, OR (b) the row exists
 *      for this user but the `version` witness was stale.
 *   2. To choose 404 vs 409, run a follow-up SELECT joined on
 *      `owner_user_id = $userId`. If the row is invisible to the caller
 *      (cross-user or non-existent) → uniform 404. If visible → 409.
 *
 * The follow-up SELECT cannot leak existence cross-user because it itself
 * filters by `owner_user_id`. This is what makes the uniform-404 anti-
 * enum invariant (Truth 3) hold even on the failure branch.
 *
 * NO `@simplevault/crypto` imports anywhere — the server NEVER touches
 * plaintext (Truth 7b — server-storage invariant; verify-grep is run as
 * part of T3's done-criteria).
 */
export interface CreateCredentialDto {
  vaultId: string;
  /** Optional client-supplied uuid (Plan 04-10 cross-dep — keeps AAD self-consistent on POST). */
  credentialId?: string | undefined;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  version: 1;
}

export interface UpdateCredentialDto {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  /** CAS-witness: caller's known-current version. Server bumps to `version + 1` on success. */
  version: number;
}

export interface CredentialResponse {
  id: string;
  vaultId: string;
  version: number;
  ciphertext?: Uint8Array;
  nonce?: Uint8Array;
  aadParamsJson?: string;
  /** ISO 8601 string. */
  updatedAt: string;
}

interface CredentialRow {
  id: string;
  vault_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  updated_at: Date | string;
  [k: string]: unknown;
}

const notFound = (): HttpException =>
  new HttpException(
    { error: { code: ErrorCodes.CREDENTIAL_NOT_FOUND, message: "Credential not found" } },
    HttpStatus.NOT_FOUND,
  );

const versionConflict = (): HttpException =>
  new HttpException(
    { error: { code: ErrorCodes.CREDENTIAL_VERSION_CONFLICT, message: "Stale version" } },
    HttpStatus.CONFLICT,
  );

function shape(row: CredentialRow, includeBlob: boolean): CredentialResponse {
  const updatedAt = row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at);
  const base: CredentialResponse = {
    id: row.id,
    vaultId: row.vault_id,
    version: row.version,
    updatedAt,
  };
  if (includeBlob) {
    base.ciphertext = row.ciphertext;
    base.nonce = row.nonce;
    base.aadParamsJson = row.aad_params_json;
  }
  return base;
}

@Injectable()
export class CredentialsService {
  constructor(private readonly dbSvc: DbService) {}

  /**
   * INSERT ... SELECT — the joined SELECT is what enforces ownership
   * atomically: if the vault doesn't belong to the user, zero rows are
   * inserted and the service returns the uniform 404. The
   * `COALESCE($credentialId, gen_random_uuid())` accepts an optional
   * client-supplied id so the AAD can be self-consistent on POST
   * (Plan 04-10 cross-dep).
   */
  async create(userId: string, dto: CreateCredentialDto): Promise<CredentialResponse> {
    const credId: string | null = dto.credentialId ?? null;
    const r = await this.dbSvc.db.execute<CredentialRow>(sql`
      INSERT INTO credentials (id, vault_id, version, ciphertext, nonce, aad_params_json)
      SELECT COALESCE(${credId}::uuid, gen_random_uuid()),
             v.id,
             1,
             ${dto.ciphertext},
             ${dto.nonce},
             ${dto.aadParamsJson}
      FROM vaults v
      WHERE v.id = ${dto.vaultId}
        AND (
          v.owner_user_id = ${userId}
          OR EXISTS (
            SELECT 1 FROM vault_memberships vm
            WHERE vm.vault_id = v.id AND vm.user_id = ${userId} AND vm.status = 'active'
          )
        )
      RETURNING id, vault_id, version, ciphertext, nonce, aad_params_json, updated_at
    `);
    if (r.rows.length === 0) throw notFound();
    return shape(r.rows[0] as CredentialRow, false);
  }

  /**
   * Single SELECT joined on `vaults.owner_user_id = $userId`. Cross-user
   * → empty rowset → uniform 404 (Truth 3). NEVER 403.
   */
  async getById(userId: string, id: string): Promise<CredentialResponse> {
    const r = await this.dbSvc.db.execute<CredentialRow>(sql`
      SELECT c.id, c.vault_id, c.version, c.ciphertext, c.nonce, c.aad_params_json, c.updated_at
      FROM credentials c JOIN vaults v ON v.id = c.vault_id
      WHERE c.id = ${id}
        AND (
          v.owner_user_id = ${userId}
          OR EXISTS (
            SELECT 1 FROM vault_memberships vm
            WHERE vm.vault_id = v.id AND vm.user_id = ${userId} AND vm.status = 'active'
          )
        )
    `);
    if (r.rows.length === 0) throw notFound();
    return shape(r.rows[0] as CredentialRow, true);
  }

  /**
   * Atomic CAS UPDATE — `version = $witness` is the row-lock-equivalent
   * predicate. Concurrent updaters with the same witness race to ONE
   * winner (rowCount=1, version → witness+1); the loser sees rowCount=0
   * and gets disambiguated 404-vs-409 by the follow-up ownership SELECT.
   */
  async update(
    userId: string,
    id: string,
    dto: UpdateCredentialDto,
  ): Promise<CredentialResponse> {
    const r = await this.dbSvc.db.execute<CredentialRow>(sql`
      UPDATE credentials c
      SET ciphertext = ${dto.ciphertext},
          nonce = ${dto.nonce},
          aad_params_json = ${dto.aadParamsJson},
          version = c.version + 1,
          updated_at = now()
      FROM vaults v
      WHERE c.id = ${id}
        AND v.id = c.vault_id
        AND c.version = ${dto.version}
        AND (
          v.owner_user_id = ${userId}
          OR EXISTS (
            SELECT 1 FROM vault_memberships vm
            WHERE vm.vault_id = v.id AND vm.user_id = ${userId} AND vm.status = 'active'
          )
        )
      RETURNING c.id, c.vault_id, c.version, c.ciphertext, c.nonce, c.aad_params_json, c.updated_at
    `);
    if (r.rows.length === 0) {
      const exists = await this.dbSvc.db.execute<{ id: string }>(sql`
        SELECT c.id FROM credentials c JOIN vaults v ON v.id = c.vault_id
        WHERE c.id = ${id}
          AND (
            v.owner_user_id = ${userId}
            OR EXISTS (
              SELECT 1 FROM vault_memberships vm
              WHERE vm.vault_id = v.id AND vm.user_id = ${userId} AND vm.status = 'active'
            )
          )
      `);
      throw exists.rows.length === 0 ? notFound() : versionConflict();
    }
    return shape(r.rows[0] as CredentialRow, false);
  }

  /**
   * DELETE ... USING vaults — same ownership join. `rowCount=0` covers
   * both "doesn't exist" and "belongs to another user" with a uniform 404.
   */
  async delete(userId: string, id: string): Promise<void> {
    const r = await this.dbSvc.db.execute<{ id: string }>(sql`
      DELETE FROM credentials c USING vaults v
      WHERE c.id = ${id}
        AND v.id = c.vault_id
        AND (
          v.owner_user_id = ${userId}
          OR EXISTS (
            SELECT 1 FROM vault_memberships vm
            WHERE vm.vault_id = v.id AND vm.user_id = ${userId} AND vm.status = 'active'
          )
        )
      RETURNING c.id
    `);
    if (r.rows.length === 0) throw notFound();
  }
}
