/**
 * Static seed data for E2E specs. NOT loaded into the DB — these are
 * deterministic helpers used by the specs themselves.
 *
 * The "happy path" credentials are CHOSEN by each spec at runtime
 * (because secret_key + mnemonic are generated client-side). What lives
 * here is shared constants like the master password used across specs.
 */

export const HAPPY_PASSWORD = "Sup3rSecur3-Vault-2026!";
export const SAD_PASSWORD = "Som3-Other-Pa55word!!";

/** A clearly-invalid invite code that matches the format regex but
 * cannot exist in the DB (HMAC won't resolve). */
export const BOGUS_INVITE = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA";
