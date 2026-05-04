import {
  SessionListResponseSchema,
  type SessionListItem,
} from "@simplevault/shared/zod";
import { z } from "zod";

import { request } from "./auth-client";

/**
 * Phase 03 Plan 11 — `/sessions` API wrappers consumed by
 * `(authed)/settings/sessions/`. Reuses the shared `request` helper from
 * `auth-client.ts` so fetch / Zod-validate / error-envelope plumbing stays
 * single-source.
 *
 * Schemas are imported from `@simplevault/shared/zod` so the wire shape stays
 * in lock-step with the server controller.
 */

const RevokeAllResponseSchema = z.object({
  revokedCount: z.number().int().nonnegative(),
});
export type RevokeAllResponse = z.infer<typeof RevokeAllResponseSchema>;

export type Session = SessionListItem;

export async function listSessions(accessToken: string): Promise<Session[]> {
  return request("/sessions", {
    method: "GET",
    schema: SessionListResponseSchema,
    accessToken,
  });
}

/**
 * 204 No Content on success. Cross-user / unknown id collapses to a uniform
 * 404 server-side (anti-enumeration — Truth 12); surfaces as
 * `AuthClientError` with status 404.
 */
export async function revokeSession(
  accessToken: string,
  sessionId: string,
): Promise<void> {
  await request(`/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
    schema: z.unknown(),
    accessToken,
  });
}

/**
 * Family-revokes EVERY non-revoked session for the caller AND bumps
 * `users.session_epoch` server-side. The caller's own access token dies on
 * its next request (Plan 04 epoch check); the server also clears the
 * `__Host-refresh` cookie. UI MUST wipe local state and redirect immediately.
 */
export async function revokeAllSessions(
  accessToken: string,
): Promise<RevokeAllResponse> {
  return request("/sessions/revoke-all", {
    method: "POST",
    body: {},
    schema: RevokeAllResponseSchema,
    accessToken,
  });
}
