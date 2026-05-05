import { AuthClientError } from "./auth-client";

/**
 * Phase 04 / Plan 06 — typed error subclasses for the credentials surface.
 *
 * The Phase-02 `AuthClientError` is the project-wide base for any non-2xx
 * error envelope (`{error: {code, message}}`). Plan 04-06 layers typed
 * subclasses on top so consumers (Plan 04-09 / 04-10 UI, Plan 04-12
 * Cypress) can `instanceof`-discriminate the three credential-specific
 * error codes that the server controller emits:
 *
 *   - `CREDENTIAL_VERSION_CONFLICT` (E2007, HTTP 409) — stale CAS witness.
 *     Carries the `credentialId` so Plan 04-10's edit form can re-fetch
 *     via `getCredential(id)` and re-apply local edits before retry.
 *   - `CREDENTIAL_NOT_FOUND` (E2006, HTTP 404) — uniform anti-enumeration
 *     404 for cross-user / unknown id.
 *   - `CREDENTIAL_BODY_TOO_LARGE` (E2008, HTTP 413) — body-parser cap
 *     fired (>64 KiB).
 *
 * `ApiError` is re-exported as a name-stable alias for `AuthClientError`
 * so the Plan-04-06 must-haves' `instanceof ApiError` pattern works
 * without breaking Phase-02 callers that already import
 * `AuthClientError`.
 */

export { AuthClientError as ApiError } from "./auth-client";

const ERR_VERSION_CONFLICT = "CREDENTIAL_VERSION_CONFLICT";
const ERR_NOT_FOUND = "CREDENTIAL_NOT_FOUND";
const ERR_BODY_TOO_LARGE = "CREDENTIAL_BODY_TOO_LARGE";

export class VersionConflictError extends AuthClientError {
  readonly credentialId: string;

  constructor(credentialId: string, message = "Credential version conflict") {
    super({ code: ERR_VERSION_CONFLICT, message, status: 409 });
    this.name = "VersionConflictError";
    this.credentialId = credentialId;
  }
}

export class CredentialNotFoundError extends AuthClientError {
  constructor(message = "Credential not found") {
    super({ code: ERR_NOT_FOUND, message, status: 404 });
    this.name = "CredentialNotFoundError";
  }
}

export class CredentialBodyTooLargeError extends AuthClientError {
  constructor(message = "Credential body exceeds 64 KiB") {
    super({ code: ERR_BODY_TOO_LARGE, message, status: 413 });
    this.name = "CredentialBodyTooLargeError";
  }
}

/**
 * Map a generic `AuthClientError` to its credentials-specific subclass when
 * applicable. Consumers wrap their `request(...)` call:
 *
 * ```ts
 * try { return await request(...); }
 * catch (e) { throw mapCredentialError(e, { credentialId: id }); }
 * ```
 *
 * Why wrap-and-rethrow rather than extend the central `request` helper:
 * keeps Phase-02 / Phase-03 callers unaffected, and lets the wrap site
 * inject the credential id into `VersionConflictError` (the URL-bound
 * datum that the central helper has no clean way to know about).
 */
export function mapCredentialError(
  e: unknown,
  ctx: { credentialId?: string } = {},
): unknown {
  if (!(e instanceof AuthClientError)) return e;
  switch (e.code) {
    case ERR_VERSION_CONFLICT:
      return new VersionConflictError(ctx.credentialId ?? "", e.message);
    case ERR_NOT_FOUND:
      return new CredentialNotFoundError(e.message);
    case ERR_BODY_TOO_LARGE:
      return new CredentialBodyTooLargeError(e.message);
    default:
      return e;
  }
}
