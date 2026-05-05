import { z } from "zod";

import { AuthClientError, request } from "./auth-client";
import { b64UrlToBytes, bytesToB64Url } from "./base64url";

/**
 * Phase 05 / Plan 05-05 — typed wrappers for the pages REST surface.
 *
 * Sibling parity with `credentials-client.ts`. All requests go through the
 * shared Phase-02 `request` helper from `auth-client.ts` (fetch + Zod +
 * uniform error-envelope plumbing). NO duplicate fetch logic here.
 *
 * Wire shape (matches `@simplevault/shared` Page* DTOs):
 *   - `ciphertext`, `nonce`, `titleSearchToken` travel as base64url strings.
 *   - On send: callers pass `Uint8Array`; wrapper encodes via `bytesToB64Url`.
 *   - On receive: wrapper decodes via `b64UrlToBytes` → `Uint8Array`.
 *
 * Server error codes mapped to typed subclasses:
 *   - `PAGE_VERSION_CONFLICT` (E2010, 409) → `PageVersionConflictError`
 *     — the editor surfaces a typed retry-or-cancel UX (NOT silent).
 *   - `PAGE_NOT_FOUND` (E2009, 404) → `PageNotFoundError` — uniform
 *     anti-enumeration 404 (cross-user / unknown id).
 *   - `PAGE_BODY_TOO_LARGE` (E2011, 413) → `PageBodyTooLargeError`.
 */

// --- error subclasses ---------------------------------------------------

const ERR_PAGE_VERSION_CONFLICT = "PAGE_VERSION_CONFLICT";
const ERR_PAGE_NOT_FOUND = "PAGE_NOT_FOUND";
const ERR_PAGE_BODY_TOO_LARGE = "PAGE_BODY_TOO_LARGE";

export class PageVersionConflictError extends AuthClientError {
  readonly pageId: string;

  constructor(pageId: string, message = "Page version conflict") {
    super({ code: ERR_PAGE_VERSION_CONFLICT, message, status: 409 });
    this.name = "PageVersionConflictError";
    this.pageId = pageId;
  }
}

export class PageNotFoundError extends AuthClientError {
  constructor(message = "Page not found") {
    super({ code: ERR_PAGE_NOT_FOUND, message, status: 404 });
    this.name = "PageNotFoundError";
  }
}

export class PageBodyTooLargeError extends AuthClientError {
  constructor(message = "Page body exceeds limit") {
    super({ code: ERR_PAGE_BODY_TOO_LARGE, message, status: 413 });
    this.name = "PageBodyTooLargeError";
  }
}

function mapPageError(e: unknown, ctx: { pageId?: string } = {}): unknown {
  if (!(e instanceof AuthClientError)) return e;
  switch (e.code) {
    case ERR_PAGE_VERSION_CONFLICT:
      return new PageVersionConflictError(ctx.pageId ?? "", e.message);
    case ERR_PAGE_NOT_FOUND:
      return new PageNotFoundError(e.message);
    case ERR_PAGE_BODY_TOO_LARGE:
      return new PageBodyTooLargeError(e.message);
    default:
      return e;
  }
}

// --- response wire schemas ----------------------------------------------

/**
 * `GET /pages` (list) — metadata + titleSearchToken (so the client can
 * reconcile its prefix-bucket grouping). NO ciphertext on the list to keep
 * payloads light; clients fan out `getPage(id)` per visible card.
 */
const PageListItemWireSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().min(1),
  titleSearchToken: z.string().min(1),
  isLocked: z.boolean(),
  updatedAt: z.string(),
});

const PageListResponseWireSchema = z.array(PageListItemWireSchema);

const PageResponseWireSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().min(1),
  ciphertext: z.string().min(1),
  nonce: z.string().min(1),
  aadParamsJson: z.string().min(1),
  titleSearchToken: z.string().min(1),
  isLocked: z.boolean(),
  updatedAt: z.string(),
});

const PageSummaryWireSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().min(1),
  titleSearchToken: z.string().min(1),
  isLocked: z.boolean(),
  updatedAt: z.string(),
});

const PageHistoryItemWireSchema = z.object({
  version: z.number().int().min(1),
  ciphertext: z.string().min(1),
  nonce: z.string().min(1),
  aadParamsJson: z.string().min(1),
  createdAt: z.string(),
});

const PageHistoryResponseWireSchema = z.array(PageHistoryItemWireSchema);

// --- public types --------------------------------------------------------

export interface PageBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  titleSearchToken: Uint8Array;
}

export interface PageResponse extends PageBlob {
  id: string;
  vaultId: string;
  version: number;
  isLocked: boolean;
  updatedAt: string;
}

export interface PageSummary {
  id: string;
  vaultId: string;
  version: number;
  titleSearchToken: Uint8Array;
  isLocked: boolean;
  updatedAt: string;
}

export interface PageHistoryItem {
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  createdAt: string;
}

export interface CreatePageInput {
  vaultId: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  titleSearchToken: Uint8Array;
}

export interface UpdatePageInput {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  titleSearchToken: Uint8Array;
  /** CAS-witness: caller's known-current version. Stale → 409. */
  version: number;
}

// --- helpers -------------------------------------------------------------

/**
 * Hex prefix validator for `?q=`. Server (Plan 05-02) accepts 1-16 hex
 * chars (0.5-8 bytes prefix). The web client always sends a power-of-2-byte
 * prefix (8 bytes = 16 hex), but the wrapper itself is permissive.
 */
const HEX_PREFIX_RE = /^[0-9a-f]{1,16}$/i;

// --- wrappers ------------------------------------------------------------

/**
 * `GET /pages?q=<hex>` — list user's personal-vault pages. When `qPrefixHex`
 * is supplied, server filters by `title_search_token` byte-range matching
 * the prefix; absent → all pages. Returns metadata + titleSearchToken; the
 * UI fans out `getPage(id)` per visible card to fetch the full envelope.
 */
export async function listPages(
  accessToken: string,
  qPrefixHex?: string,
): Promise<PageSummary[]> {
  let path = "/pages";
  if (qPrefixHex !== undefined && qPrefixHex.length > 0) {
    if (!HEX_PREFIX_RE.test(qPrefixHex)) {
      throw new AuthClientError({
        code: "E4001",
        message: "qPrefixHex must be 1-16 hex chars",
        status: 400,
      });
    }
    path += `?q=${encodeURIComponent(qPrefixHex)}`;
  }
  const raw = await request(path, {
    method: "GET",
    schema: PageListResponseWireSchema,
    accessToken,
  });
  return raw.map((r) => ({
    id: r.id,
    vaultId: r.vaultId,
    version: r.version,
    titleSearchToken: b64UrlToBytes(r.titleSearchToken),
    isLocked: r.isLocked,
    updatedAt: r.updatedAt,
  }));
}

/**
 * Convenience alias that signals intent at the call site. The client first
 * computes the 8-byte HMAC token via `computeTitleSearchToken(key,
 * normalize(query))`, hex-encodes it, and passes here.
 */
export async function searchPagesByTitlePrefix(
  accessToken: string,
  prefixHex: string,
): Promise<PageSummary[]> {
  return listPages(accessToken, prefixHex);
}

/**
 * `POST /pages` — create at version 1.
 */
export async function createPage(
  accessToken: string,
  input: CreatePageInput,
): Promise<PageSummary> {
  let raw;
  try {
    raw = await request("/pages", {
      method: "POST",
      body: {
        vaultId: input.vaultId,
        ciphertext: bytesToB64Url(input.ciphertext),
        nonce: bytesToB64Url(input.nonce),
        aadParamsJson: input.aadParamsJson,
        titleSearchToken: bytesToB64Url(input.titleSearchToken),
        version: 1,
      },
      schema: PageSummaryWireSchema,
      accessToken,
    });
  } catch (e) {
    throw mapPageError(e);
  }
  return {
    id: raw.id,
    vaultId: raw.vaultId,
    version: raw.version,
    titleSearchToken: b64UrlToBytes(raw.titleSearchToken),
    isLocked: raw.isLocked,
    updatedAt: raw.updatedAt,
  };
}

/**
 * `GET /pages/:id` — full envelope. Cross-user / unknown id → uniform 404
 * `PageNotFoundError` (Truth 3 anti-enumeration).
 */
export async function getPage(
  accessToken: string,
  id: string,
): Promise<PageResponse> {
  let raw;
  try {
    raw = await request(`/pages/${encodeURIComponent(id)}`, {
      method: "GET",
      schema: PageResponseWireSchema,
      accessToken,
    });
  } catch (e) {
    throw mapPageError(e, { pageId: id });
  }
  return {
    id: raw.id,
    vaultId: raw.vaultId,
    version: raw.version,
    ciphertext: b64UrlToBytes(raw.ciphertext),
    nonce: b64UrlToBytes(raw.nonce),
    aadParamsJson: raw.aadParamsJson,
    titleSearchToken: b64UrlToBytes(raw.titleSearchToken),
    isLocked: raw.isLocked,
    updatedAt: raw.updatedAt,
  };
}

/**
 * `PATCH /pages/:id` — atomic CAS update. `input.version` is the caller's
 * known-current value; stale → 409 → typed `PageVersionConflictError`
 * carrying `pageId` for the editor's retry-or-cancel UX.
 */
export async function patchPage(
  accessToken: string,
  id: string,
  input: UpdatePageInput,
): Promise<PageSummary> {
  let raw;
  try {
    raw = await request(`/pages/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: {
        ciphertext: bytesToB64Url(input.ciphertext),
        nonce: bytesToB64Url(input.nonce),
        aadParamsJson: input.aadParamsJson,
        titleSearchToken: bytesToB64Url(input.titleSearchToken),
        version: input.version,
      },
      schema: PageSummaryWireSchema,
      accessToken,
    });
  } catch (e) {
    throw mapPageError(e, { pageId: id });
  }
  return {
    id: raw.id,
    vaultId: raw.vaultId,
    version: raw.version,
    titleSearchToken: b64UrlToBytes(raw.titleSearchToken),
    isLocked: raw.isLocked,
    updatedAt: raw.updatedAt,
  };
}

/** Alias for `patchPage` — naming convenience (mirrors prompt). */
export const updatePage = patchPage;

/**
 * `DELETE /pages/:id` — 204 on success. Cross-user / unknown id → 404
 * (anti-enumeration).
 */
export async function deletePage(
  accessToken: string,
  id: string,
): Promise<void> {
  try {
    await request(`/pages/${encodeURIComponent(id)}`, {
      method: "DELETE",
      schema: z.unknown(),
      accessToken,
    });
  } catch (e) {
    throw mapPageError(e, { pageId: id });
  }
}

/**
 * `GET /pages/:id/history` — last 10 ciphertext snapshots, newest first.
 * Client decrypts each on demand (lazy in the version-history side panel).
 */
export async function getPageHistory(
  accessToken: string,
  id: string,
): Promise<PageHistoryItem[]> {
  let raw;
  try {
    raw = await request(`/pages/${encodeURIComponent(id)}/history`, {
      method: "GET",
      schema: PageHistoryResponseWireSchema,
      accessToken,
    });
  } catch (e) {
    throw mapPageError(e, { pageId: id });
  }
  return raw.map((r) => ({
    version: r.version,
    ciphertext: b64UrlToBytes(r.ciphertext),
    nonce: b64UrlToBytes(r.nonce),
    aadParamsJson: r.aadParamsJson,
    createdAt: r.createdAt,
  }));
}
