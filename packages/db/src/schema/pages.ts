import { boolean, index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { vaults } from "./vaults.js";

/**
 * `pages` — Phase 05 per-vault encrypted page (Markdown-style note) blob.
 *
 * SECURITY INVARIANT (REQ-CRYPTO-003 — server-storage invariant):
 * The server NEVER sees page plaintext. Each row is an XChaCha20-Poly1305
 * AEAD blob, opaque to the API:
 *
 *   ciphertext = XChaCha20-Poly1305(
 *     plaintext = utf8(canonicalJson({ title, body })),
 *     key       = vault_DEK,
 *     nonce     = 24B random,
 *     aad       = utf8(AAD_LABEL_VAULT_PAGE)        // "sv:vault-page:v1|"
 *              || sha256(lower(email))
 *              || canonicalJson({ vaultId, pageId, version })
 *   )
 *
 * Plan 05-03 implements `buildVaultPageAad` which imports
 * `AAD_LABEL_VAULT_PAGE` from `apps/web/src/lib/crypto/aad-labels.ts`
 * (single source of truth — sibling parity with vault-credential).
 *
 * `titleSearchToken` (8 bytes) is a deterministic per-vault title token —
 * HMAC-SHA256(deriveTitleSearchKey(vault_DEK), normalize(title)).slice(0,8).
 * Indexed for prefix/eq lookup; collisions are tolerated (2^-32 per pair).
 *
 * `is_locked` is a Phase-06 forward-compat hook (per-page lock for shared
 * vaults / co-edit guards). Phase 05 only writes `false`; the column lands
 * here so the Phase-06 migration is a no-op DDL change.
 */
export const pages = pgTable(
  "pages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    vaultId: uuid("vault_id")
      .notNull()
      .references(() => vaults.id, { onDelete: "cascade" }),
    version: integer("version").notNull().default(1),
    /** XChaCha20-Poly1305 ciphertext of canonical-JSON `{title, body}`. */
    ciphertext: bytea("ciphertext").notNull(),
    /** 24-byte XChaCha20 nonce (random per write). */
    nonce: bytea("nonce").notNull(),
    /** Canonical-JSON of the AAD parameter object (vaultId, pageId, version). */
    aadParamsJson: text("aad_params_json").notNull(),
    /**
     * 8-byte deterministic title token (HMAC-SHA256 truncated). Length is
     * enforced at the Zod boundary, NOT at the column type — bytea has no
     * length constraint, so a stray write would slip past the DB.
     */
    titleSearchToken: bytea("title_search_token").notNull(),
    /** Phase-06 forward-compat. Phase 05 only writes false. */
    isLocked: boolean("is_locked").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    vaultIdx: index("pages_vault_idx").on(t.vaultId),
    titleTokenIdx: index("pages_title_token_idx").on(t.titleSearchToken),
  }),
);

export type Page = typeof pages.$inferSelect;
export type NewPage = typeof pages.$inferInsert;
