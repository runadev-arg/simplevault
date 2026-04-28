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
      if (typeof r === "string") {
        message = r;
      } else if (typeof r === "object" && r !== null && "message" in r) {
        const m = (r as { message?: unknown }).message;
        if (typeof m === "string") message = m;
        else if (Array.isArray(m)) message = m.join(", ");
      }
      const statusMap: Record<number, ErrorCode> = {
        [HttpStatus.UNAUTHORIZED]: ErrorCodes.AUTH_INVALID_CREDENTIALS,
        [HttpStatus.FORBIDDEN]: ErrorCodes.VAULT_FORBIDDEN,
        [HttpStatus.BAD_REQUEST]: ErrorCodes.VALIDATION_FAILED,
        [HttpStatus.TOO_MANY_REQUESTS]: ErrorCodes.AUTH_RATE_LIMITED,
      };
      const mapped = statusMap[status];
      if (mapped) code = mapped;
    } else {
      this.logger.error({ requestId, err: exception }, "unhandled exception");
    }

    res.status(status).json({ error: { code, message, requestId } });
  }
}
