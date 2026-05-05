/**
 * Phase 05 / Plan 02 — body-size cap on `/pages/*` (FINDING-0015 partial).
 *
 * Express body-parser is mounted with this limit ONLY for the `/pages` route
 * prefix in `apps/api/src/main.ts`. Above the cap, Express raises
 * `PayloadTooLargeError` BEFORE Zod runs; `AllExceptionsFilter` maps that to
 * `413 + {error.code: PAGE_BODY_TOO_LARGE}`.
 *
 * Default 256 KiB (env `PAGE_BODY_MAX_BYTES`); ceiling 1 MiB (env-tunable
 * but capped — defence-in-depth so a misconfigured env doesn't open a gigantic
 * body window). Larger pages are an explicit anti-feature at v1 scale: pages
 * are notes, not file attachments.
 */

const KIB = 1024;
const MIB = 1024 * KIB;

function intEnv(v: string | undefined, fallback: number, ceiling: number): number {
  if (!v) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, ceiling);
}

/** Hard ceiling — 1 MiB. */
export const PAGE_BODY_HARD_CEILING_BYTES = 1 * MIB;

/** Default Express body-parser cap for `/pages/*` (256 KiB, env-tunable up to 1 MiB). */
export const PAGE_BODY_MAX_BYTES = intEnv(
  process.env.PAGE_BODY_MAX_BYTES,
  256 * KIB,
  PAGE_BODY_HARD_CEILING_BYTES,
);
