import { index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { vaults } from "./vaults.js";

/**
 * `credentials` — Phase 04 per-vault encrypted credential blob.
 *
 * SECURITY INVARIANT (REQ-CRYPTO-003 — server-storage invariant):
 * The server NEVER sees credential plaintext. Each row is an XChaCha20-Poly1305
 * AEAD blob, opaque to the API:
 *
 *   ciphertext = XChaCha20-Poly1305(
 *     plaintext = utf8(canonicalJson(credentialFields)),
 *     key       = vault_DEK,
 *     nonce     = 24B random,
 *     aad       = utf8("sv:vault-credential:v1|")
 *              || sha256(lower(email))
 *              || canonicalJson({ vaultId, credentialId, version })
 *   )
 *
 * Plan 04-04 builds `aad` via `buildVaultCredentialAad` which imports
 * `AAD_LABEL_VAULT_CREDENTIAL` from `apps/web/src/lib/crypto/aad-labels.ts`
 * (single source of truth — closes FINDING-0026 by construction).
 */
export const credentials = pgTable(
  "credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    vaultId: uuid("vault_id")
      .notNull()
      .references(() => vaults.id, { onDelete: "cascade" }),
    version: integer("version").notNull().default(1),
    /** XChaCha20-Poly1305 ciphertext of canonical-JSON plaintext. */
    ciphertext: bytea("ciphertext").notNull(),
    /** 24-byte XChaCha20 nonce (random per write). */
    nonce: bytea("nonce").notNull(),
    /** Canonical-JSON of the AAD parameter object (vaultId, credentialId, version). */
    aadParamsJson: text("aad_params_json").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    vaultIdx: index("credentials_vault_idx").on(t.vaultId),
  }),
);

export type Credential = typeof credentials.$inferSelect;
export type NewCredential = typeof credentials.$inferInsert;
