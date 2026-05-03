/**
 * TOTP DTO re-exports — server-side surface.
 *
 * The Zod schemas live in `@simplevault/shared/zod` so the web client
 * can import the same shapes (request bodies + response bodies). This
 * module re-exports them for convenience inside the API package.
 *
 * SECURITY (Phase 03 Key Link 3 — server NEVER sees the TOTP plaintext):
 * The schemas accept the AEAD-wrapped secret + AAD bytes; they DO NOT
 * accept the plaintext 20-byte secret. Any future schema field that
 * accepts a "secret" or "code" payload would be a regression.
 */

export {
  TotpBeginRegisterResponseSchema,
  TotpFinishRegisterResponseSchema,
  TotpFinishRegisterSchema,
  TotpVerifySchema,
} from "@simplevault/shared/zod";
export type {
  TotpBeginRegisterResponse,
  TotpFinishRegisterDto,
  TotpFinishRegisterResponse,
  TotpVerifyDto,
} from "@simplevault/shared/zod";
