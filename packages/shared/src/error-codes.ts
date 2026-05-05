export const ErrorCodes = {
  // Auth (E1xxx)
  AUTH_INVALID_CREDENTIALS: "E1001",
  AUTH_2FA_REQUIRED: "E1002",
  AUTH_2FA_INVALID: "E1003",
  AUTH_SESSION_EXPIRED: "E1004",
  AUTH_REFRESH_REUSE_DETECTED: "E1005",
  AUTH_INVITE_INVALID: "E1006",
  AUTH_RATE_LIMITED: "E1007",
  AUTH_INVITE_EXPIRED: "E1008",
  AUTH_INVITE_ALREADY_REDEEMED: "E1009",
  AUTH_SIGNUP_DUPLICATE_EMAIL: "E1010",
  // Phase 03 — 2FA + sessions (this plan: 03-02 owns step-up + WebAuthn errors)
  AUTH_STEP_UP_REQUIRED: "E1011",
  WEBAUTHN_CHALLENGE_INVALID: "E1012",
  WEBAUTHN_VERIFICATION_FAILED: "E1013",
  AUTH_2FA_NO_METHOD: "E1014",
  // Phase 03 Plan 03 — TOTP replay-guard violation (Key Link 4).
  AUTH_2FA_TOTP_REPLAY: "E1015",
  // Phase 03 Plan 03 — TOTP issuance-nonce missing/expired/wrong-user.
  AUTH_2FA_TOTP_ISSUANCE_INVALID: "E1016",
  // Phase 03 Plan 04 — JWT epoch mismatch (revoke-all bumped users.session_epoch).
  AUTH_SESSION_REVOKED: "E1017",
  // Phase 03 Plan 06 — DELETE /2fa/methods/:id would leave the user with 0
  // active 2FA methods AND `userHasSharedVaultDependency(userId)` returns
  // true (Phase 07 hand-off seam — currently always false).
  AUTH_2FA_REMOVAL_BLOCKED: "E1018",

  // Vault (E2xxx)
  VAULT_NOT_FOUND: "E2001",
  VAULT_FORBIDDEN: "E2002",
  VAULT_QUOTA_EXCEEDED: "E2003",
  VAULT_INVITE_EXPIRED: "E2004",
  VAULT_DELETE_VOTE_DEADLOCK: "E2005",
  // Phase 04 Plan 02 — credentials CRUD + atomic CAS PATCH (Key Link 2 of
  // 04-INDEX). `CREDENTIAL_NOT_FOUND` is the uniform-404 anti-enumeration
  // surface for cross-user / non-existent GET/PATCH/DELETE (Truth 3); the
  // plan specifies "E2001" but that slot is already taken by
  // `VAULT_NOT_FOUND` from Phase 04 Plan 01, so we allocate the next free
  // E2xxx slots — a Rule-2 adaptation that preserves the semantic intent
  // (next free in the vault range) without colliding with prior allocations.
  CREDENTIAL_NOT_FOUND: "E2006",
  CREDENTIAL_VERSION_CONFLICT: "E2007",
  // Phase 04 Plan 03 — body-size cap on /credentials/* (FINDING-0015 partial).
  // Express body-parser fires 413 BEFORE Zod runs; AllExceptionsFilter maps
  // PayloadTooLargeError → this code. Plan specified "E2003" but that slot
  // is taken by VAULT_QUOTA_EXCEEDED from a prior phase; next-free E2xxx
  // (Rule-2 adaptation, same as the sibling 04-02 allocation note above).
  CREDENTIAL_BODY_TOO_LARGE: "E2008",
  // Phase 05 Plan 01..05 — vault-page CRUD + atomic CAS PATCH (Wave 1
  // schema; Wave 2 service). Sibling parity with the credentials triplet
  // above (E2006/E2007/E2008). PAGE_NOT_FOUND is the uniform-404 anti-
  // enumeration surface; PAGE_VERSION_CONFLICT is the CAS witness 409;
  // PAGE_BODY_TOO_LARGE is the body-parser 413 mapping. Allocated next-
  // free in E2xxx range (Rule-2 adaptation, same pattern as E2006..E2008).
  PAGE_NOT_FOUND: "E2009",
  PAGE_VERSION_CONFLICT: "E2010",
  PAGE_BODY_TOO_LARGE: "E2011",

  // Phase 07 — shared vaults
  VAULT_SHARING_NOT_FOUND: "E2012",
  VAULT_INVITE_NOT_FOUND: "E2013",
  VAULT_ALREADY_MEMBER: "E2014",
  VAULT_SHARING_ACCESS_DENIED: "E2015",
  VAULT_USER_NOT_FOUND: "E2016",

  // Crypto (E3xxx)
  CRYPTO_DECRYPT_FAILED: "E3001",
  CRYPTO_KDF_DOWNGRADE_DETECTED: "E3002",
  CRYPTO_CHAIN_BREAK: "E3003",

  // Validation (E4xxx)
  VALIDATION_FAILED: "E4001",

  // Server (E5xxx)
  SERVER_INTERNAL: "E5001",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
