import { z } from "zod";

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded", "down"]),
  db: z.enum(["ok", "down"]),
  redis: z.enum(["ok", "down"]),
  timestamp: z.string().datetime(),
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

/**
 * `GET /me` strict-allow-list response.
 *
 * LOAD-BEARING: this is the only output schema for /me. Phase 02-11 (web)
 * consumes it; Phase 03+ (sessions, settings) MAY add fields but only via
 * an explicit `.extend(...)` here — never by ad-hoc additions in the API
 * controller. The server-side serialiser MUST `.parse(...)` against this
 * schema as a defence-in-depth check before responding (so a future ORM
 * hydration leak surfaces as a 500, not a silent data exfil).
 *
 * Explicitly NOT in the v1 shape (per 02-09 plan):
 *  - `argon2_secret_key_hash` (the verifier — never leaked, even to owner)
 *  - `wrapped_master_dek*` / `wrapped_user_*` / `user_pub_key`
 *    (returned in the 200 login response, not /me; SPA caches them in memory
 *    after login. /me is for "who am I" — not key-material refetch.)
 *  - `recovery_hmac` / `wrapped_master_dek_recovery` (recovery flow only)
 *  - any session metadata (Phase 03 owns sessions UI).
 */
/**
 * Phase 03 Plan 03 — TOTP enrolment + verification request schemas.
 *
 * SECURITY (Key Link 3 — TOTP secret is BROWSER-ONLY):
 * - `wrappedSecret` is the AEAD-wrapped 20-byte TOTP secret (XChaCha20-
 *   Poly1305 with key=master_DEK, AAD label "sv:user-totp:v1|" +
 *   sha256(lower(email))). The server NEVER decrypts it.
 * - `candidateStep` is the RFC 6238 step the client computed locally
 *   AFTER unwrapping the secret in-browser. The server only does an
 *   atomic CAS replay-guard UPDATE — it never runs HMAC-SHA-1.
 *
 * `issuanceNonce` (begin-register output, finish-register input) is a
 * 32-byte random base64url string the server signs into a Redis
 * single-use cache so finish-register can prove the begin-register
 * preceded it.
 */
const boundedB64 = (min: number, max: number) =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      const buf = Buffer.from(v, "base64");
      if (buf.length < min || buf.length > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `expected ${min.toString()}..${max.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return buf;
    });

/** Output of POST /2fa/totp/begin-register. */
export const TotpBeginRegisterResponseSchema = z
  .object({
    /** 32-byte random, base64url. Single-use, TTL 120s, bound to user_id. */
    issuanceNonce: z.string().min(1).max(128),
  })
  .strict();
export type TotpBeginRegisterResponse = z.infer<typeof TotpBeginRegisterResponseSchema>;

/** Input of POST /2fa/totp/finish-register. */
export const TotpFinishRegisterSchema = z
  .object({
    issuanceNonce: z.string().min(1).max(128),
    // 20-byte TOTP secret + 16-byte Poly1305 tag = 36 bytes; allow up to 64
    // to leave headroom for any future scheme bump that lands in the same wrap.
    wrappedSecret: boundedB64(36, 128),
    // AAD bytes used at wrap time. Per Phase 02 + CRYPTO-STACK §3:
    // "sv:user-totp:v1|" (16 bytes) + sha256(lower(email)) (32 bytes) = 48 bytes,
    // plus a 24-byte random nonce stored alongside the ciphertext = 72 bytes total.
    // Bound generously to 16..256.
    encryptedSecretAad: boundedB64(16, 256),
    name: z.string().trim().min(1).max(64),
    /** Step the client verified locally to prove it knows the plaintext. */
    candidateStep: z.number().int().nonnegative(),
  })
  .strict();
export type TotpFinishRegisterDto = z.infer<typeof TotpFinishRegisterSchema>;

/** Output of POST /2fa/totp/finish-register. */
export const TotpFinishRegisterResponseSchema = z
  .object({
    id: z.string().uuid(),
    name: z.string(),
  })
  .strict();
export type TotpFinishRegisterResponse = z.infer<typeof TotpFinishRegisterResponseSchema>;

/** Input of POST /2fa/totp/verify (called by step-up-token holders). */
export const TotpVerifySchema = z
  .object({
    credentialId: z.string().uuid(),
    candidateStep: z.number().int().nonnegative(),
  })
  .strict();
export type TotpVerifyDto = z.infer<typeof TotpVerifySchema>;

/**
 * Phase 03 Plan 06 — `GET /2fa/methods` strict-allowlist response.
 *
 * LOAD-BEARING (Truth 9): the server MUST `.parse(...)` this schema before
 * responding so a future ORM hydration leak surfaces as a 500, not a silent
 * exfil of secret material. Explicitly NOT in the shape:
 *   - `credentialId` / `publicKey` / `counter` / `aaguid` / `transports`
 *     (webauthn — opaque to the user, leaks authenticator details).
 *   - `wrappedSecret` / `encryptedSecretAad` / `lastUsedStep` (totp —
 *     would leak the wrap envelope or the replay-guard cursor).
 *
 * Order convention (Truth 9): webauthn first, then totp, then by createdAt
 * asc. Enforced server-side in MethodsService.list.
 */
export const TwoFaMethodSchema = z
  .object({
    id: z.string().uuid(),
    kind: z.enum(["webauthn", "totp"]),
    name: z.string().min(1).max(64),
    createdAt: z.string().datetime(),
    /** ISO 8601 or null when the method has never been used. */
    lastUsedAt: z.string().datetime().nullable(),
  })
  .strict();
export type TwoFaMethod = z.infer<typeof TwoFaMethodSchema>;

/** `GET /2fa/methods` returns an array (possibly empty). */
export const TwoFaMethodsListSchema = z.array(TwoFaMethodSchema);
export type TwoFaMethodsList = z.infer<typeof TwoFaMethodsListSchema>;

/**
 * Phase 03 Plan 05 — `GET /sessions` response item.
 *
 * Truth 11: list one row per active session family (rotation chain
 * collapsed). The shape is INTENTIONALLY narrow — anything not on this
 * schema MUST NOT appear in the response. In particular the schema does
 * NOT include: full ip_hash, raw IP, full user-agent, refresh_token_hash,
 * family_id, prev_token_id, expires_at. The server `.parse(...)` against
 * this schema is a defence-in-depth check against ORM-hydration leaks.
 *
 * `ipHashB64Prefix` is the first 6 chars of base64(ip_hash) — enough for
 * the user to recognise "same network" without leaking the full hash to
 * JS (where an XSS could exfiltrate it). 36 bits of entropy, collisions
 * tolerated; this is UX context, not authn.
 */
export const SessionListItemSchema = z
  .object({
    id: z.string().uuid(),
    createdAt: z.string().datetime(),
    lastUsedAt: z.string().datetime(),
    current: z.boolean(),
    userAgentFamily: z.string().min(1).max(64),
    ipHashB64Prefix: z.string().max(6),
  })
  .strict();
export type SessionListItem = z.infer<typeof SessionListItemSchema>;

export const SessionListResponseSchema = z.array(SessionListItemSchema);
export type SessionListResponse = z.infer<typeof SessionListResponseSchema>;

/**
 * Phase 03 Plan 08 — `/auth/login` 2FA-required response (Truth 8).
 *
 * The 2FA branch returns this discriminated body when the verified user has
 * ≥1 active 2FA method. The 1FA-only branch keeps the legacy Phase-02 body
 * (no `kind` field — regression-free for existing callers). Web clients
 * branch on `"kind" in body` OR `"stepUpToken" in body` to distinguish.
 *
 * SECURITY (Truth 8 + Key Link 5):
 *   - The step-up token's `purpose` claim is `"2fa-stepup"`. `JwtAuthGuard`
 *     refuses any token with `purpose !== undefined`, so this token cannot
 *     impersonate an access token.
 *   - exp = iat + STEP_UP_TOKEN_TTL (default 120s).
 *   - NO `__Host-refresh` cookie is set on this branch — the user has no
 *     refresh family yet.
 */
export const LoginStepUpResponseSchema = z
  .object({
    kind: z.literal("2fa-required"),
    stepUpToken: z.string().min(1),
    twoFa: z
      .object({
        webauthnAvailable: z.boolean(),
        totpAvailable: z.boolean(),
      })
      .strict(),
  })
  .strict();
export type LoginStepUpResponse = z.infer<typeof LoginStepUpResponseSchema>;

export const MeResponseSchema = z
  .object({
    id: z.string().uuid(),
    // RFC 5321 ceiling — mirrors users.email varchar(254) (FINDING-0017 fold).
    email: z.string().email().max(254),
    createdAt: z.string().datetime(),
    argon2Params: z.object({
      memoryKiB: z.number().int().positive(),
      iterations: z.number().int().positive(),
      parallelism: z.literal(1),
    }),
  })
  .strict();
export type MeResponse = z.infer<typeof MeResponseSchema>;

/**
 * Phase 05 Plan 01 — vault-page request/response schemas.
 *
 * Sibling parity with `apps/api/src/credentials/credentials.dto.ts`. Lives
 * in `@simplevault/shared` (not in apps/api) because Phase 05 has the web
 * client construct + validate the same shapes for optimistic round-trips.
 * Bytea handling: bodies arrive as JSON with base64-encoded `ciphertext`,
 * `nonce`, `titleSearchToken`; the transform decodes into `Uint8Array`
 * after validating post-decode length.
 *
 * `.strict()` (Truth 18 system-wide) rejects unknown keys outright — a
 * forward-compat client adding a new field surfaces as a 400 instead of a
 * silent strip.
 *
 * AEAD field caps:
 *   - PAGE_CIPHERTEXT_MAX_BYTES = 256 KiB (defence-in-depth above the
 *     body-parser cap; final cap finalised in Plan 05-04 service).
 *   - PAGE_AAD_PARAMS_JSON_MAX_BYTES = 2048 (per plan).
 *   - Nonce = 24 bytes (XChaCha20).
 *   - Title-search token = 8 bytes (HMAC-SHA256 truncated).
 */
const PAGE_NONCE_BYTES = 24;
const PAGE_TITLE_SEARCH_TOKEN_BYTES = 8;
export const PAGE_CIPHERTEXT_MAX_BYTES = 256 * 1024;
export const PAGE_AAD_PARAMS_JSON_MAX_BYTES = 2048;

const pageBase64ToBytesBounded = (
  min: number,
  max: number,
  label: string,
): z.ZodType<Uint8Array, z.ZodTypeDef, unknown> =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      const buf = Buffer.from(v, "base64");
      if (buf.length < min || buf.length > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${label}: expected ${min.toString()}..${max.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return new Uint8Array(buf);
    });

/**
 * `POST /pages` request body.
 *
 * `version` is `literal(1)` because every newly-created page begins life
 * at version 1. Cross-dep with Plan 05-04: the client supplies the page id
 * as part of `aadParamsJson` (canonical-JSON `{pageId, vaultId, version}`)
 * so the AEAD it just encrypted is self-consistent on POST.
 */
export const PageCreateSchema = z
  .object({
    vaultId: z.string().uuid(),
    ciphertext: pageBase64ToBytesBounded(
      1,
      PAGE_CIPHERTEXT_MAX_BYTES,
      "ciphertext",
    ),
    nonce: pageBase64ToBytesBounded(
      PAGE_NONCE_BYTES,
      PAGE_NONCE_BYTES,
      "nonce",
    ),
    aadParamsJson: z.string().min(1).max(PAGE_AAD_PARAMS_JSON_MAX_BYTES),
    titleSearchToken: pageBase64ToBytesBounded(
      PAGE_TITLE_SEARCH_TOKEN_BYTES,
      PAGE_TITLE_SEARCH_TOKEN_BYTES,
      "titleSearchToken",
    ),
    version: z.literal(1),
  })
  .strict();
export type PageCreateDto = z.infer<typeof PageCreateSchema>;

/**
 * `PATCH /pages/:id` request body. `version` is the CAS-witness (caller's
 * known-current value, NOT the new value). Server CAS bumps the row to
 * `version + 1`. Stale witness → 409 `PAGE_VERSION_CONFLICT`.
 */
export const PageUpdateSchema = z
  .object({
    ciphertext: pageBase64ToBytesBounded(
      1,
      PAGE_CIPHERTEXT_MAX_BYTES,
      "ciphertext",
    ),
    nonce: pageBase64ToBytesBounded(
      PAGE_NONCE_BYTES,
      PAGE_NONCE_BYTES,
      "nonce",
    ),
    aadParamsJson: z.string().min(1).max(PAGE_AAD_PARAMS_JSON_MAX_BYTES),
    titleSearchToken: pageBase64ToBytesBounded(
      PAGE_TITLE_SEARCH_TOKEN_BYTES,
      PAGE_TITLE_SEARCH_TOKEN_BYTES,
      "titleSearchToken",
    ),
    version: z.number().int().min(1),
  })
  .strict();
export type PageUpdateDto = z.infer<typeof PageUpdateSchema>;

/**
 * `GET /pages/:id` response. Server `.parse(...)` against this schema is
 * the defence-in-depth check against ORM hydration leaks (Truth 9 sibling).
 * The bytea fields are emitted as base64 strings on the wire.
 */
export const PageResponseSchema = z
  .object({
    id: z.string().uuid(),
    vaultId: z.string().uuid(),
    version: z.number().int().min(1),
    ciphertext: z.string().min(1),
    nonce: z.string().min(1),
    aadParamsJson: z.string().min(1).max(PAGE_AAD_PARAMS_JSON_MAX_BYTES),
    titleSearchToken: z.string().min(1),
    isLocked: z.boolean(),
    updatedAt: z.string().datetime(),
  })
  .strict();
export type PageResponse = z.infer<typeof PageResponseSchema>;

/**
 * `GET /pages/:id/history` response — last 10 ciphertext snapshots,
 * newest first (ordered by `(pageId, version DESC)` index). Plan 05-04
 * trims to 10 in the PATCH transaction.
 */
export const PageHistoryItemSchema = z
  .object({
    version: z.number().int().min(1),
    ciphertext: z.string().min(1),
    nonce: z.string().min(1),
    aadParamsJson: z.string().min(1).max(PAGE_AAD_PARAMS_JSON_MAX_BYTES),
    createdAt: z.string().datetime(),
  })
  .strict();
export type PageHistoryItem = z.infer<typeof PageHistoryItemSchema>;

export const PageHistoryResponseSchema = z.array(PageHistoryItemSchema);
export type PageHistoryResponse = z.infer<typeof PageHistoryResponseSchema>;
