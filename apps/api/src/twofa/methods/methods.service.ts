import { Injectable } from "@nestjs/common";
import { schema } from "@simplevault/db";
import type { TwoFaMethod } from "@simplevault/shared/zod";
import { and, asc, count, eq } from "drizzle-orm";

import { DbService } from "../../db/db.service.js";

/**
 * Phase 03 Plan 06 — 2FA method management primitives.
 *
 * SECURITY INVARIANTS (LOAD-BEARING):
 *
 * 1. **Strict allowlist on output (Truth 9).** `list` SELECTs only the five
 *    fields the caller is allowed to see (`id`, `name`, `createdAt`,
 *    `lastUsedAt` + the synthesised `kind` discriminator). It NEVER touches
 *    `credentialId` / `publicKey` / `counter` / `aaguid` / `transports`
 *    (webauthn) or `wrappedSecret` / `encryptedSecretAad` / `lastUsedStep`
 *    (totp). The downstream Zod parse in the controller is defence-in-depth.
 *
 * 2. **Anti-enumeration on remove (Truth 10).** Every DELETE is gated on
 *    `WHERE user_id = $authedUserId AND id = $methodId`. Cross-user attempts
 *    return zero rows → caller maps to 404 (NOT 403 — a 403 would confirm
 *    the id exists). Same posture as `DELETE /sessions/:id`.
 *
 * 3. **Cross-table id collision** (per Plan 06 key link): both
 *    `webauthn_credentials.id` and `totp_credentials.id` are UUID-v4 from
 *    `defaultRandom()` — collision probability is negligible. `remove` tries
 *    webauthn first; on miss, tries totp; on miss, returns null (404).
 *
 * 4. **Order discipline (Truth 9).** `list` returns webauthn first, then
 *    totp, then by `createdAt` asc within each group. The controller's
 *    Zod schema doesn't enforce ordering — this method does.
 */
@Injectable()
export class MethodsService {
  constructor(private readonly db: DbService) {}

  /**
   * Return the user's active 2FA methods. Strict-allowlist output: only the
   * five public fields (Truth 9 — never returns secret material, public-key
   * bytes, raw counters, transports, or wrapped blobs).
   */
  async list(userId: string): Promise<TwoFaMethod[]> {
    const wa = await this.db.db
      .select({
        id: schema.webauthnCredentials.id,
        name: schema.webauthnCredentials.name,
        createdAt: schema.webauthnCredentials.createdAt,
        lastUsedAt: schema.webauthnCredentials.lastUsedAt,
      })
      .from(schema.webauthnCredentials)
      .where(eq(schema.webauthnCredentials.userId, userId))
      .orderBy(asc(schema.webauthnCredentials.createdAt));

    const totp = await this.db.db
      .select({
        id: schema.totpCredentials.id,
        name: schema.totpCredentials.name,
        createdAt: schema.totpCredentials.createdAt,
        lastUsedAt: schema.totpCredentials.lastUsedAt,
      })
      .from(schema.totpCredentials)
      .where(eq(schema.totpCredentials.userId, userId))
      .orderBy(asc(schema.totpCredentials.createdAt));

    const out: TwoFaMethod[] = [];
    for (const c of wa) {
      out.push({
        id: c.id,
        kind: "webauthn",
        name: c.name,
        createdAt: c.createdAt.toISOString(),
        lastUsedAt: c.lastUsedAt ? c.lastUsedAt.toISOString() : null,
      });
    }
    for (const c of totp) {
      out.push({
        id: c.id,
        kind: "totp",
        name: c.name,
        createdAt: c.createdAt.toISOString(),
        lastUsedAt: c.lastUsedAt ? c.lastUsedAt.toISOString() : null,
      });
    }
    return out;
  }

  /**
   * Count the user's active 2FA methods across both tables. Used by the
   * removal-guard (Plan 06 Truth 10) and by `Require2FAGuard` (Plan 07
   * hand-off seam).
   */
  async countActive(userId: string): Promise<number> {
    const [waRow] = await this.db.db
      .select({ c: count() })
      .from(schema.webauthnCredentials)
      .where(eq(schema.webauthnCredentials.userId, userId));
    const [totpRow] = await this.db.db
      .select({ c: count() })
      .from(schema.totpCredentials)
      .where(eq(schema.totpCredentials.userId, userId));
    return Number(waRow?.c ?? 0) + Number(totpRow?.c ?? 0);
  }

  /**
   * Delete the named method (looking it up across both tables by `id`
   * scoped to `user_id`). Anti-enumeration: cross-user attempts return
   * `null` (caller maps to 404, NOT 403 — Truth 10).
   *
   * Returns `{ kind }` on success so the caller can audit-log the kind
   * without an extra round-trip.
   */
  async remove(
    userId: string,
    methodId: string,
  ): Promise<{ kind: "webauthn" | "totp" } | null> {
    const wa = await this.db.db
      .delete(schema.webauthnCredentials)
      .where(
        and(
          eq(schema.webauthnCredentials.id, methodId),
          eq(schema.webauthnCredentials.userId, userId),
        ),
      )
      .returning({ id: schema.webauthnCredentials.id });
    if (wa.length > 0) return { kind: "webauthn" };

    const totp = await this.db.db
      .delete(schema.totpCredentials)
      .where(
        and(
          eq(schema.totpCredentials.id, methodId),
          eq(schema.totpCredentials.userId, userId),
        ),
      )
      .returning({ id: schema.totpCredentials.id });
    if (totp.length > 0) return { kind: "totp" };

    return null;
  }
}
