import { sql } from "drizzle-orm";
import {
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";

/**
 * `users` — the only auth-bearing row per account.
 *
 * SECURITY INVARIANT (REQ-CRYPTO-003 — server-storage invariant):
 * The server NEVER stores any of these:
 *   - the master password
 *   - the per-user `secret_key`
 *   - the recovery phrase (BIP-39 mnemonic)
 *   - any KEK or DEK in plaintext
 *
 * The ONLY auth-related secret stored here is the Argon2id `verifier`:
 *   argon2_secret_key_hash = Argon2id(secret_key, server_argon_salt, argon2_params)
 *
 * Login compares the verifier in constant time, after a timing-floor dummy
 * Argon2 derivation when the row is absent. The `secret_key` itself stays
 * client-side and is reconstructed from `master_password + email` via the
 * key-hierarchy spec in CRYPTO-STACK §3.
 *
 * Recovery: only `recovery_hmac` is stored — an HMAC of sha256-of-normalised
 * phrase under SERVER_RECOVERY_HMAC_SECRET. The phrase itself never reaches
 * the server. Recovery flow looks the user up by `recovery_hmac` (UNIQUE),
 * decrypts `wrapped_master_dek_recovery` with a key derived from the phrase.
 */
export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    // Stored lower-cased on insert/update; case-insensitive uniqueness is
    // enforced via a functional UNIQUE INDEX on lower(email) below.
    email: text("email").notNull(),

    // --- Auth verifier (REQ-CRYPTO-003) ---
    /** Argon2id(secret_key, server_argon_salt). NOT the secret_key itself. */
    argon2SecretKeyHash: bytea("argon2_secret_key_hash").notNull(),
    /** Per-user random salt for the verifier above. */
    serverArgonSalt: bytea("server_argon_salt").notNull(),
    /** Per-user Argon2id parameters used for the verifier — JSON for forward-compat re-tuning. */
    argon2Params: jsonb("argon2_params")
      .$type<{ memoryKiB: number; iterations: number; parallelism: 1 }>()
      .notNull(),
    /** Per-user salt bound into the client-side master_KEK derivation (CRYPTO-STACK §3). */
    userArgonSalt: bytea("user_argon_salt").notNull(),

    // --- Wrapped key material (ciphertexts only — never plaintext keys) ---
    /** master_DEK encrypted to the user's master_KEK (XChaCha20-Poly1305 AEAD blob). */
    wrappedMasterDek: bytea("wrapped_master_dek").notNull(),
    /** master_DEK encrypted to a recovery key derived from the BIP-39 phrase. */
    wrappedMasterDekRecovery: bytea("wrapped_master_dek_recovery").notNull(),
    /** HMAC-SHA256(SERVER_RECOVERY_HMAC_SECRET, sha256(normalised_phrase)). Lookup key for recovery. */
    recoveryHmac: bytea("recovery_hmac").notNull(),

    // --- Session-epoch (Phase 03 — REQ-AUTH-004) ---
    /**
     * Bumped by `POST /sessions/revoke-all` and `DELETE /sessions/:id`. Every
     * issued access JWT carries an `epoch` claim; `JwtAuthGuard` rejects
     * tokens whose `epoch` ≠ this column with 401 AUTH_SESSION_REVOKED, giving
     * us per-user revocation within ≤ next-request latency without per-token
     * Redis lookups. Cached in Redis (TTL 60s, busted on every write here).
     */
    sessionEpoch: integer("session_epoch").notNull().default(0),

    // --- Per-user keypair material ---
    /** X25519 public key (32 B). Plaintext — public by design. */
    userPubKey: bytea("user_pub_key").notNull(),
    /** Ed25519 signing private key, wrapped under master_KEK (AEAD blob). */
    wrappedUserSigningSk: bytea("wrapped_user_signing_sk").notNull(),
    /** X25519 key-exchange private key, wrapped under master_KEK (AEAD blob). */
    wrappedUserKxSk: bytea("wrapped_user_kx_sk").notNull(),

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    /** Case-insensitive email uniqueness via functional index on lower(email). */
    emailLowerIdx: uniqueIndex("users_email_lower_idx").on(sql`lower(${t.email})`),
    /** Recovery lookup — find the user from the HMAC of their recovery phrase. */
    recoveryHmacIdx: uniqueIndex("users_recovery_hmac_idx").on(t.recoveryHmac),
  }),
);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
