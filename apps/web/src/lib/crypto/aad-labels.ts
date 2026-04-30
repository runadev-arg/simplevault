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

export type AadLabel =
  | typeof AAD_LABEL_MASTER
  | typeof AAD_LABEL_RECOVERY
  | typeof AAD_LABEL_SIGN_SK
  | typeof AAD_LABEL_KX_SK;
