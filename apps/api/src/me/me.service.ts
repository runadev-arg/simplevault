import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { MeResponseSchema, type MeResponse } from "@simplevault/shared/zod";
import { eq } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * `MeService` — server-side provider for `GET /me`.
 *
 * Allow-list invariant: after building the candidate response, the schema is
 * parsed via `MeResponseSchema.parse(...)`. Any extra key (future ORM
 * hydration leak, accidental spread of a row object, etc.) raises and is
 * mapped to a generic 500 by `AllExceptionsFilter` — defence in depth against
 * schema-evolution leaks.
 */
@Injectable()
export class MeService {
  constructor(private readonly db: DbService) {}

  async get(userId: string): Promise<MeResponse> {
    const rows = await this.db.db
      .select({
        id: schema.users.id,
        email: schema.users.email,
        createdAt: schema.users.createdAt,
        argon2Params: schema.users.argon2Params,
      })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    const row = rows[0];
    if (!row) {
      // The JWT verified but the row is gone (deleted / impossible-in-v1).
      // Treat as auth failure to avoid leaking existence.
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
        HttpStatus.UNAUTHORIZED,
      );
    }

    const candidate = {
      id: row.id,
      email: row.email,
      createdAt: row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
      argon2Params: row.argon2Params,
    };

    // STRICT allow-list parse — extra keys throw.
    const parsed = MeResponseSchema.parse(candidate);
    return parsed;
  }
}
