import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { type ErrorCode, ErrorCodes } from "@simplevault/shared/errors";
import type { Request, Response } from "express";

/**
 * Express body-parser raises `PayloadTooLargeError` (subclass of Error with
 * `type === "entity.too.large"` and `status === 413`) BEFORE Nest pipes/
 * guards run. Detect it via duck-typing rather than instanceof to avoid
 * importing body-parser internals (the constructor is not exported in a
 * stable way across versions).
 */
function isPayloadTooLargeError(exception: unknown): boolean {
  if (typeof exception !== "object" || exception === null) return false;
  const e = exception as { type?: unknown; status?: unknown; statusCode?: unknown; name?: unknown };
  if (e.type === "entity.too.large") return true;
  if (e.status === 413 || e.statusCode === 413) return true;
  if (e.name === "PayloadTooLargeError") return true;
  return false;
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();
    const rawId: unknown = (req as unknown as { id?: unknown }).id;
    let requestId = "unknown";
    if (typeof rawId === "string") requestId = rawId;
    else if (typeof rawId === "number") requestId = rawId.toString();

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let code: ErrorCode = ErrorCodes.SERVER_INTERNAL;
    let message = "Internal server error";

    // Phase 04 Plan 03 — body-parser 413 lands here BEFORE any Nest pipe.
    // Map to the stable `CREDENTIAL_BODY_TOO_LARGE` code so the web client
    // can render a deterministic error message.
    if (isPayloadTooLargeError(exception)) {
      const url = typeof req.url === "string" ? req.url : "";
      const onCredentials = url.startsWith("/credentials");
      const onPages = url.startsWith("/pages");
      res.setHeader("X-Request-Id", requestId);
      let mappedCode: ErrorCode = ErrorCodes.VALIDATION_FAILED;
      let mappedMsg = "Request body too large";
      if (onCredentials) {
        mappedCode = ErrorCodes.CREDENTIAL_BODY_TOO_LARGE;
        mappedMsg = "Credential body exceeds 64 KiB";
      } else if (onPages) {
        mappedCode = ErrorCodes.PAGE_BODY_TOO_LARGE;
        mappedMsg = "Page body exceeds size limit";
      }
      res.status(HttpStatus.PAYLOAD_TOO_LARGE).json({
        error: { code: mappedCode, message: mappedMsg },
      });
      return;
    }

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const r: unknown = exception.getResponse();
      // Honor `{ error: { code, message } }` embedded by services so the
      // exception filter doesn't collapse domain errors (e.g. INVITE_INVALID)
      // back to the generic status-code map.
      if (typeof r === "object" && r !== null && "error" in r) {
        const e = (r as { error?: unknown }).error;
        if (typeof e === "object" && e !== null) {
          const ec = (e as { code?: unknown }).code;
          const em = (e as { message?: unknown }).message;
          if (typeof ec === "string") code = ec as ErrorCode;
          if (typeof em === "string") message = em;
        }
      } else if (typeof r === "string") {
        message = r;
      } else if (typeof r === "object" && r !== null && "message" in r) {
        const m = (r as { message?: unknown }).message;
        if (typeof m === "string") message = m;
        else if (Array.isArray(m)) message = m.join(", ");
      }
      // Status-code default fallback only if no domain code was provided.
      if (code === ErrorCodes.SERVER_INTERNAL) {
        const statusMap: Record<number, ErrorCode> = {
          [HttpStatus.UNAUTHORIZED]: ErrorCodes.AUTH_INVALID_CREDENTIALS,
          [HttpStatus.FORBIDDEN]: ErrorCodes.VAULT_FORBIDDEN,
          [HttpStatus.BAD_REQUEST]: ErrorCodes.VALIDATION_FAILED,
          [HttpStatus.TOO_MANY_REQUESTS]: ErrorCodes.AUTH_RATE_LIMITED,
        };
        const mapped = statusMap[status];
        if (mapped) code = mapped;
      }
    } else {
      this.logger.error({ requestId, err: exception }, "unhandled exception");
    }

    res.setHeader("X-Request-Id", requestId);
    res.status(status).json({ error: { code, message } });
  }
}
