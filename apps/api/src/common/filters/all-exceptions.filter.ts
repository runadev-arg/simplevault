import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { type ErrorCode, ErrorCodes } from "@simplevault/shared/errors";
import type { Request, Response } from "express";

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request & { id?: string }>();
    const requestId = req.id ?? "unknown";

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let code: ErrorCode = ErrorCodes.SERVER_INTERNAL;
    let message = "Internal server error";

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const r = exception.getResponse();
      if (typeof r === "string") {
        message = r;
      } else if (typeof r === "object" && r !== null && "message" in r) {
        const m = (r as { message?: unknown }).message;
        if (typeof m === "string") message = m;
        else if (Array.isArray(m)) message = m.join(", ");
      }
      if (status === (HttpStatus.UNAUTHORIZED as number)) code = ErrorCodes.AUTH_INVALID_CREDENTIALS;
      else if (status === (HttpStatus.FORBIDDEN as number)) code = ErrorCodes.VAULT_FORBIDDEN;
      else if (status === (HttpStatus.BAD_REQUEST as number)) code = ErrorCodes.VALIDATION_FAILED;
      else if (status === (HttpStatus.TOO_MANY_REQUESTS as number)) code = ErrorCodes.AUTH_RATE_LIMITED;
    } else {
      this.logger.error({ requestId, err: exception }, "unhandled exception");
    }

    res.status(status).json({ error: { code, message, requestId } });
  }
}
