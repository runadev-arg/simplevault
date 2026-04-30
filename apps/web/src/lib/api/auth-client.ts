import { z } from "zod";

/**
 * Thin fetch wrapper around the SimpleVault API auth surface.
 *
 * Base URL via `NEXT_PUBLIC_API_URL` (set in docker-compose / .env). All
 * calls use `credentials: "include"` so the `__Host-refresh` cookie set
 * by /auth/login follows along for /auth/refresh — but the SPA NEVER
 * reads it (HttpOnly).
 *
 * Response shapes are validated with Zod; mismatched shapes throw
 * `AuthClientResponseError` so a backend-rename surfaces instantly
 * instead of corrupting downstream state.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001";

// --- response shapes (frozen by 02-07 + 02-08 SUMMARYs) ------------------

const Argon2ParamsSchema = z.object({
  memoryKiB: z.number().int().positive(),
  iterations: z.number().int().positive(),
  parallelism: z.literal(1),
});

export const InviteRedeemResponseSchema = z.object({
  inviteId: z.string().uuid(),
  email: z.string().email(),
  argon2Params: Argon2ParamsSchema,
  serverArgonSalt: z.string().min(1), // base64, 16 B
});

export const SignupResponseSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().email(),
  createdAt: z.string(),
});

const ErrorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    requestId: z.union([z.string(), z.number()]).optional(),
  }),
});

export type InviteRedeemResponse = z.infer<typeof InviteRedeemResponseSchema>;
export type SignupResponse = z.infer<typeof SignupResponseSchema>;
export type Argon2Params = z.infer<typeof Argon2ParamsSchema>;

// --- error class ----------------------------------------------------------

export class AuthClientError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId: string | number | undefined;

  constructor(opts: {
    code: string;
    message: string;
    status: number;
    requestId?: string | number;
  }) {
    super(opts.message);
    this.name = "AuthClientError";
    this.code = opts.code;
    this.status = opts.status;
    this.requestId = opts.requestId;
  }
}

export class AuthClientResponseError extends Error {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "AuthClientResponseError";
    if (cause !== undefined) this.cause = cause;
  }
}

async function postJson<T>(
  path: string,
  body: unknown,
  schema: z.ZodSchema<T>,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body),
    });
  } catch (e) {
    throw new AuthClientResponseError("network error", e);
  }

  let parsedBody: unknown = null;
  try {
    parsedBody = await res.json();
  } catch {
    parsedBody = null;
  }

  if (!res.ok) {
    const env = ErrorEnvelopeSchema.safeParse(parsedBody);
    if (env.success) {
        const opts: ConstructorParameters<typeof AuthClientError>[0] = {
        code: env.data.error.code,
        message: env.data.error.message,
        status: res.status,
      };
      if (env.data.error.requestId !== undefined) {
        opts.requestId = env.data.error.requestId;
      }
      throw new AuthClientError(opts);
    }
    throw new AuthClientError({
      code: "E5001",
      message: `Request failed: ${String(res.status)}`,
      status: res.status,
    });
  }

  const ok = schema.safeParse(parsedBody);
  if (!ok.success) {
    throw new AuthClientResponseError(
      `Response shape mismatch on ${path}: ${ok.error.message}`,
    );
  }
  return ok.data;
}

// --- public API -----------------------------------------------------------

export async function redeemInvite(code: string): Promise<InviteRedeemResponse> {
  return postJson("/invite/redeem", { code }, InviteRedeemResponseSchema);
}

export interface SignupEnvelope {
  inviteId: string;
  argon2SecretKeyHash: string; // base64, 32 B
  argon2Params: Argon2Params;
  userArgonSalt: string; // base64, 16 B
  wrappedMasterDek: string; // base64
  wrappedMasterDekRecovery: string; // base64
  recoveryInnerHash: string; // base64, 32 B
  userPubKey: string; // base64, 32 B (X25519)
  wrappedUserSigningSk: string; // base64
  wrappedUserKxSk: string; // base64
}

export async function signup(envelope: SignupEnvelope): Promise<SignupResponse> {
  return postJson("/auth/signup", envelope, SignupResponseSchema);
}

export const authClient = { redeemInvite, signup };
