import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { type ErrorCode, ErrorCodes } from "@simplevault/shared/errors";
import type { Request, Response } from "express";

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

    res.status(status).json({ error: { code, message, requestId } });
  }
}
