/**
 * Phase 04 Plan 03 — body-size cap on `/credentials/*` (FINDING-0015 partial).
 *
 * Express body-parser is mounted with this limit ONLY for the `/credentials`
 * route prefix in `apps/api/src/main.ts`. Above the cap, Express raises
 * `PayloadTooLargeError` BEFORE Zod runs; `AllExceptionsFilter` maps that to
 * `413 + {error.code: CREDENTIAL_BODY_TOO_LARGE}`. The global default for
 * every other route remains the Express default (~100 KiB) — Phase 13
 * closes the global default; this plan closes the credentials slice only.
 *
 * Field-level caps (defence-in-depth alongside the body-parser cap) are
 * enforced inside the Zod schema in `packages/shared/src/zod` (Plan 04-02).
 */

/** Default Express body-parser cap for `/credentials/*` (64 KiB). */
export const CREDENTIAL_BODY_MAX_BYTES = 64 * 1024;

/**
 * Hard ceiling enforced at the controller layer (Zod refine + post-parse
 * length check) — only fires if the body-parser cap is bypassed somehow.
 * Keeps the runtime guard tight even if main.ts is misconfigured.
 */
export const CREDENTIAL_BODY_HARD_CEILING = 128 * 1024;

/** Single-field max sizes (defence-in-depth alongside the body cap). */
export const CIPHERTEXT_MAX_BYTES = 64 * 1024;
export const AAD_PARAMS_JSON_MAX_BYTES = 2048;
