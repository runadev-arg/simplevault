import { bigint, index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { users } from "./users.js";

/**
 * `totp_credentials` — per-user TOTP enrolment.
 *
 * SECURITY INVARIANT (REQ-CRYPTO-003 / Phase 03 Key Link 3):
 * The TOTP secret is generated, displayed (QR + provisioning URL), wrapped,
 * and verified ENTIRELY in the browser. The server NEVER sees the plaintext
 * 20-byte secret — only the AEAD-wrapped blob and its AAD bytes.
 *
 * Wrap scheme:
 *   ciphertext = XChaCha20-Poly1305(plaintext = totp_secret_20B,
 *                                   key       = master_DEK,
 *                                   nonce     = 24B random,
 *                                   aad       = "sv:user-totp:v1|" || sha256(lower(email)))
 *
 * Replay guard (Phase 03 Key Link 4):
 *   `last_used_step` advances via atomic compare-and-swap:
 *     UPDATE totp_credentials
 *        SET last_used_step = $cs, last_used_at = now()
 *      WHERE id = $cid AND last_used_step < $cs
 *      RETURNING *;
 *   Zero rows returned -> 401 AUTH_2FA_TOTP_REPLAY (the candidate step was
 *   already burned). Drift tolerance ±1 step is enforced by the verifier
 *   before this UPDATE.
 */
export const totpCredentials = pgTable(
  "totp_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** XChaCha20-Poly1305 wrap of the 20-byte TOTP secret. AAD label "sv:user-totp:v1|". */
    wrappedSecret: bytea("wrapped_secret").notNull(),
    /** AAD bytes used at wrap time, persisted so the client can re-derive on verify. */
    encryptedSecretAad: bytea("encrypted_secret_aad").notNull(),
    /** Last RFC 6238 step accepted. Atomic CAS guards against replay. */
    lastUsedStep: bigint("last_used_step", { mode: "number" }).notNull().default(0),
    /** User-chosen name e.g. "1Password" / "Aegis on Pixel 8". 1..64 chars. */
    name: text("name").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (t) => ({
    userIdx: index("totp_credentials_user_idx").on(t.userId),
  }),
);

export type TotpCredential = typeof totpCredentials.$inferSelect;
export type NewTotpCredential = typeof totpCredentials.$inferInsert;
