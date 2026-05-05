/**
 * Per-blob AAD label prefixes (LOAD-BEARING — frozen by 02-10 SUMMARY §3).
 *
 * These exact byte strings are baked into every wrapped key on disk via
 * the AAD of XChaCha20-Poly1305. ANY drift here means tag mismatch on
 * unwrap and a soft-bricked vault. Pull from this module — never repeat
 * literals.
 *
 * The AAD is then composed by `aadFor(label, params, emailHash)` where
 * `emailHash = SHA256(lower(email))` (32 fixed bytes). See 02-10 SUMMARY
 * §2 for why `email` (not `user_id`) is the per-user binder at signup.
 */

export const AAD_LABEL_MASTER = "sv:user-master:v1|" as const;
export const AAD_LABEL_RECOVERY = "sv:user-recovery:v1|" as const;
export const AAD_LABEL_SIGN_SK = "sv:user-sign-sk:v1|" as const;
export const AAD_LABEL_KX_SK = "sv:user-kx-sk:v1|" as const;
/**
 * Phase 03 Plan 10 — wraps the TOTP secret under master_DEK. Same scheme
 * as the master/sign/kx labels (label || SHA256(lower(email)) → encodeAad
 * with argon2Params). The server stores the wrapped blob opaquely
 * (`totp_credentials.wrapped_secret` + `.encrypted_secret_aad` bytea).
 * Server NEVER sees the plaintext secret.
 */
export const AAD_LABEL_TOTP = "sv:user-totp:v1|" as const;
/**
 * Phase 04 — vault credential blob AAD label. FROZEN.
 *
 * Per-credential AAD =
 *   utf8(AAD_LABEL_VAULT_CREDENTIAL)
 *   || sha256(lower(email))
 *   || canonicalJson({ vaultId, credentialId, version })
 *
 * Plan 04-04 builds the AAD via `buildVaultCredentialAad` which imports
 * THIS constant — never re-declares the literal (closes FINDING-0026 by
 * construction). Bumping the v-suffix is a data-migration event: every
 * existing credential blob fails AEAD-unwrap until re-wrapped with the
 * new label.
 */
export const AAD_LABEL_VAULT_CREDENTIAL = "sv:vault-credential:v1|" as const;
/**
 * Phase 05 — vault page blob AAD label. FROZEN.
 *
 * Per-page AAD =
 *   utf8(AAD_LABEL_VAULT_PAGE)
 *   || sha256(lower(email))
 *   || canonicalJson({ pageId, vaultId, version })
 *
 * Plan 05-03 builds the AAD via `buildVaultPageAad` which imports THIS
 * constant — never re-declares the literal (sibling parity with
 * AAD_LABEL_VAULT_CREDENTIAL; closes FINDING-0026 for pages by
 * construction). Bumping the v-suffix is a data-migration event:
 * every existing page blob fails AEAD-unwrap until re-wrapped.
 */
export const AAD_LABEL_VAULT_PAGE = "sv:vault-page:v1|" as const;
/**
 * Phase 05 — HKDF-Expand info string for the per-vault title-search key.
 *
 * `titleSearchKey = HKDF-Expand-SHA256(masterDek, info=TITLE_SEARCH_HKDF_INFO,
 *                                      L=32)`
 *
 * `titleSearchToken = HMAC-SHA256(titleSearchKey, normalize(title)).slice(0,8)`
 *
 * FROZEN: the info string is baked into every persisted titleSearchToken on
 * disk. Bumping the v-suffix invalidates every existing token (tokens become
 * unsearchable until re-derived + re-written — a data-migration event).
 * Lives next to AAD_LABEL_VAULT_PAGE because both are FROZEN constants
 * consumed by the same Plan 05-03 helpers in `@simplevault/crypto`.
 */
export const TITLE_SEARCH_HKDF_INFO = "sv:title-search:v1" as const;

export type AadLabel =
  | typeof AAD_LABEL_MASTER
  | typeof AAD_LABEL_RECOVERY
  | typeof AAD_LABEL_SIGN_SK
  | typeof AAD_LABEL_KX_SK
  | typeof AAD_LABEL_TOTP
  | typeof AAD_LABEL_VAULT_CREDENTIAL
  | typeof AAD_LABEL_VAULT_PAGE;
