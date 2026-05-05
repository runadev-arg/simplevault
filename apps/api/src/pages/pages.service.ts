import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import { sql } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * Phase 05 / Plan 02 — pages CRUD service with atomic CAS PATCH and
 * history rotation.
 *
 * Mirrors `credentials.service.ts` for ownership joins (single SELECT/
 * UPDATE/DELETE joined on `vaults.owner_user_id = $userId`), so IDOR is
 * impossible by construction. The PATCH method is the only nontrivial
 * piece — it runs ONE transaction that:
 *   1. SELECTs the current row FOR UPDATE (joined on ownership).
 *   2. INSERTs the PRE-update snapshot into `page_versions`.
 *   3. UPDATEs `pages` with the new ciphertext + bumped version.
 *   4. Trims `page_versions` to the top-10 by version DESC.
 *
 * Failure-disambiguation matches credentials: zero rows on the CAS UPDATE
 * → follow-up ownership SELECT chooses 404 (cross-user / not-found) vs 409
 * (stale witness). The follow-up SELECT itself filters on
 * `owner_user_id = $userId`, so it cannot leak existence cross-user
 * (Truth 3 anti-enum).
 *
 * NO `@simplevault/crypto` imports anywhere — the server NEVER touches
 * page plaintext (REQ-CRYPTO-003 server-storage invariant; verify-grep
 * runs at end-of-T3).
 */
export interface CreatePageDto {
  vaultId: string;
  pageId?: string | undefined;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  titleSearchToken: Uint8Array;
  version: 1;
}

export interface UpdatePageDto {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  titleSearchToken: Uint8Array;
  /** CAS-witness: caller's known-current version. Server bumps to `version + 1` on success. */
  version: number;
}

export interface PageResponse {
  id: string;
  vaultId: string;
  version: number;
  ciphertext?: Uint8Array;
  nonce?: Uint8Array;
  aadParamsJson?: string;
  titleSearchToken?: Uint8Array;
  isLocked: boolean;
  updatedAt: string;
}

export interface PageListItem {
  id: string;
  vaultId: string;
  version: number;
  titleSearchToken: Uint8Array;
  isLocked: boolean;
  updatedAt: string;
}

export interface PageHistoryEntry {
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  createdAt: string;
}

interface PageRow {
  id: string;
  vault_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  title_search_token: Uint8Array;
  is_locked: boolean;
  updated_at: Date | string;
  [k: string]: unknown;
}

interface PageVersionRow {
  page_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  created_at: Date | string;
  [k: string]: unknown;
}

const notFound = (): HttpException =>
  new HttpException(
    { error: { code: ErrorCodes.PAGE_NOT_FOUND, message: "Page not found" } },
    HttpStatus.NOT_FOUND,
  );

const versionConflict = (): HttpException =>
  new HttpException(
    { error: { code: ErrorCodes.PAGE_VERSION_CONFLICT, message: "Stale version" } },
    HttpStatus.CONFLICT,
  );

function toIso(v: Date | string): string {
  return v instanceof Date ? v.toISOString() : String(v);
}

function shape(row: PageRow, includeBlob: boolean): PageResponse {
  const base: PageResponse = {
    id: row.id,
    vaultId: row.vault_id,
    version: row.version,
    isLocked: row.is_locked,
    updatedAt: toIso(row.updated_at),
  };
  if (includeBlob) {
    base.ciphertext = row.ciphertext;
    base.nonce = row.nonce;
    base.aadParamsJson = row.aad_params_json;
    base.titleSearchToken = row.title_search_token;
  }
  return base;
}

function shapeList(row: PageRow): PageListItem {
  return {
    id: row.id,
    vaultId: row.vault_id,
    version: row.version,
    titleSearchToken: row.title_search_token,
    isLocked: row.is_locked,
    updatedAt: toIso(row.updated_at),
  };
}

/**
 * Bytea range for a hex prefix: `[prefix || 00...,  prefix+1 || 00...)`.
 * Equivalent to `WHERE token >= $low AND token < $high` — index-friendly.
 */
function prefixRange(prefixHex: string): { low: Uint8Array; high: Uint8Array } | null {
  if (!/^[0-9a-fA-F]+$/.test(prefixHex)) return null;
  // Round odd-length hex up — half-byte prefixes are not meaningful at the
  // bytea layer (we'd need a bitmask). Caller already validates length.
  const even = prefixHex.length % 2 === 0 ? prefixHex : prefixHex + "0";
  const buf = Buffer.from(even, "hex");
  const low = new Uint8Array(8);
  low.set(buf.subarray(0, Math.min(buf.length, 8)), 0);
  // high = increment low (treat as big-endian) and zero-pad to 8 bytes.
  const high = new Uint8Array(8);
  high.set(low, 0);
  // Increment from the LAST non-zero bound byte at position `prefixBytes-1`.
  const boundary = Math.min(Math.ceil(prefixHex.length / 2), 8);
  let i = boundary - 1;
  while (i >= 0) {
    const v = (high[i] ?? 0) + 1;
    if (v <= 0xff) {
      high[i] = v;
      // zero out everything after boundary (already 0 in low; preserve)
      for (let j = boundary; j < 8; j++) high[j] = 0;
      return { low, high };
    }
    high[i] = 0;
    i--;
  }
  // overflow — high becomes "infinity"; use 0xff*8 as the upper bound.
  return { low, high: new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) };
}

@Injectable()
export class PagesService {
  constructor(private readonly dbSvc: DbService) {}

  // ---------------------------------------------------------------- create

  async create(userId: string, dto: CreatePageDto): Promise<PageResponse> {
    const pageId: string | null = dto.pageId ?? null;
    const r = await this.dbSvc.db.execute<PageRow>(sql`
      INSERT INTO pages (id, vault_id, version, ciphertext, nonce, aad_params_json, title_search_token)
      SELECT COALESCE(${pageId}::uuid, gen_random_uuid()),
             v.id,
             1,
             ${dto.ciphertext},
             ${dto.nonce},
             ${dto.aadParamsJson},
             ${dto.titleSearchToken}
      FROM vaults v
      WHERE v.id = ${dto.vaultId} AND v.owner_user_id = ${userId}
      RETURNING id, vault_id, version, ciphertext, nonce, aad_params_json, title_search_token, is_locked, updated_at
    `);
    if (r.rows.length === 0) throw notFound();
    return shape(r.rows[0] as PageRow, false);
  }

  // ---------------------------------------------------------------- read

  async getById(userId: string, id: string): Promise<PageResponse> {
    const r = await this.dbSvc.db.execute<PageRow>(sql`
      SELECT p.id, p.vault_id, p.version, p.ciphertext, p.nonce, p.aad_params_json, p.title_search_token, p.is_locked, p.updated_at
      FROM pages p JOIN vaults v ON v.id = p.vault_id
      WHERE p.id = ${id} AND v.owner_user_id = ${userId}
    `);
    if (r.rows.length === 0) throw notFound();
    return shape(r.rows[0] as PageRow, true);
  }

  // ---------------------------------------------------------------- list / search

  /**
   * `q` absent → all pages owned by the user (metadata-only, no ciphertext).
   * `q` present → 1..16 hex chars (= up to 8-byte prefix), bytea range scan
   * on the indexed `title_search_token` column.
   */
  async list(userId: string, q: string | undefined): Promise<PageListItem[]> {
    if (q !== undefined) {
      const range = prefixRange(q);
      if (!range) return [];
      const r = await this.dbSvc.db.execute<PageRow>(sql`
        SELECT p.id, p.vault_id, p.version, p.title_search_token, p.is_locked, p.updated_at
        FROM pages p JOIN vaults v ON v.id = p.vault_id
        WHERE v.owner_user_id = ${userId}
          AND p.title_search_token >= ${range.low}
          AND p.title_search_token < ${range.high}
        ORDER BY p.updated_at DESC
      `);
      return r.rows.map((row) => shapeList(row as PageRow));
    }
    const r = await this.dbSvc.db.execute<PageRow>(sql`
      SELECT p.id, p.vault_id, p.version, p.title_search_token, p.is_locked, p.updated_at
      FROM pages p JOIN vaults v ON v.id = p.vault_id
      WHERE v.owner_user_id = ${userId}
      ORDER BY p.updated_at DESC
    `);
    return r.rows.map((row) => shapeList(row as PageRow));
  }

  // ---------------------------------------------------------------- update (CAS + rotation)

  /**
   * Atomic CAS UPDATE inside a transaction with history rotation.
   *
   * Step order (load-bearing for atomicity):
   *   1. Read current row joined on ownership.
   *   2. INSERT the pre-update snapshot into `page_versions`.
   *   3. UPDATE `pages` to the new ciphertext + bump version.
   *   4. DELETE history rows beyond the top-10 by version DESC.
   *
   * Failure inside ANY step rolls the whole transaction back (Postgres
   * default REPEATABLE READ semantics not required — the SELECT FOR UPDATE
   * is enough; concurrent updaters block until commit / rollback).
   *
   * 404 vs 409 disambiguation: zero-row-affected from the SELECT means the
   * caller doesn't own the row → 404. Otherwise, version mismatch → 409.
   */
  async update(
    userId: string,
    id: string,
    dto: UpdatePageDto,
  ): Promise<PageResponse> {
    type Tx = { execute: <T>(s: unknown) => Promise<{ rows: T[]; rowCount?: number }> };
    const db = this.dbSvc.db as unknown as {
      transaction: <T>(cb: (tx: Tx) => Promise<T>) => Promise<T>;
    };
    return db.transaction<PageResponse>(async (tx) => {
      // 1. Read current row joined on ownership (FOR UPDATE row-lock).
      const cur = await tx.execute<PageRow>(sql`
        SELECT p.id, p.vault_id, p.version, p.ciphertext, p.nonce, p.aad_params_json, p.title_search_token, p.is_locked, p.updated_at
        FROM pages p JOIN vaults v ON v.id = p.vault_id
        WHERE p.id = ${id} AND v.owner_user_id = ${userId}
        FOR UPDATE OF p
      `);
      if (cur.rows.length === 0) throw notFound();
      const row = cur.rows[0] as PageRow;
      if (row.version !== dto.version) throw versionConflict();

      // 2. INSERT pre-update snapshot into page_versions.
      await tx.execute(sql`
        INSERT INTO page_versions (page_id, version, ciphertext, nonce, aad_params_json)
        VALUES (${id}, ${row.version}, ${row.ciphertext}, ${row.nonce}, ${row.aad_params_json})
      `);

      // 3. UPDATE pages with new ciphertext + bumped version.
      const upd = await tx.execute<PageRow>(sql`
        UPDATE pages
        SET ciphertext = ${dto.ciphertext},
            nonce = ${dto.nonce},
            aad_params_json = ${dto.aadParamsJson},
            title_search_token = ${dto.titleSearchToken},
            version = version + 1,
            updated_at = now()
        WHERE id = ${id} AND version = ${dto.version}
        RETURNING id, vault_id, version, ciphertext, nonce, aad_params_json, title_search_token, is_locked, updated_at
      `);
      if (upd.rows.length === 0) {
        // Lost the race against a concurrent updater between SELECT FOR UPDATE
        // and UPDATE — treat as 409 (witness no longer current).
        throw versionConflict();
      }

      // 4. Trim history to top-10 by version DESC.
      await tx.execute(sql`
        DELETE FROM page_versions
        WHERE page_id = ${id}
          AND id NOT IN (
            SELECT id FROM page_versions
            WHERE page_id = ${id}
            ORDER BY version DESC
            LIMIT 10
          )
      `);

      return shape(upd.rows[0] as PageRow, false);
    });
  }

  // ---------------------------------------------------------------- delete

  async delete(userId: string, id: string): Promise<void> {
    const r = await this.dbSvc.db.execute<{ id: string }>(sql`
      DELETE FROM pages p USING vaults v
      WHERE p.id = ${id} AND v.id = p.vault_id AND v.owner_user_id = ${userId}
      RETURNING p.id
    `);
    if (r.rows.length === 0) throw notFound();
  }

  // ---------------------------------------------------------------- history

  async history(userId: string, id: string): Promise<PageHistoryEntry[]> {
    const r = await this.dbSvc.db.execute<PageVersionRow>(sql`
      SELECT pv.page_id, pv.version, pv.ciphertext, pv.nonce, pv.aad_params_json, pv.created_at
      FROM page_versions pv
      WHERE pv.page_id = ${id}
        AND EXISTS (
          SELECT 1 FROM pages p JOIN vaults v ON v.id = p.vault_id
          WHERE p.id = ${id} AND v.owner_user_id = ${userId}
        )
      ORDER BY pv.version DESC
      LIMIT 10
    `);
    if (r.rows.length === 0) {
      // Distinguish "page exists for user but has no history" vs "page does
      // not exist / cross-user". The latter must surface uniform-404; the
      // former returns an empty list.
      const exists = await this.dbSvc.db.execute<{ id: string }>(sql`
        SELECT p.id FROM pages p JOIN vaults v ON v.id = p.vault_id
        WHERE p.id = ${id} AND v.owner_user_id = ${userId}
      `);
      if (exists.rows.length === 0) throw notFound();
      return [];
    }
    return r.rows.map((row) => ({
      version: row.version,
      ciphertext: row.ciphertext,
      nonce: row.nonce,
      aadParamsJson: row.aad_params_json,
      createdAt: toIso(row.created_at),
    }));
  }
}
