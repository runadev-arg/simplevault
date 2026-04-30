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

/**
 * GET /auth/params — global Argon2id profile + global server-argon-salt
 * (anti-enumeration: identical body for every caller, no email parameter).
 *
 * The client uses (argon2Params, serverArgonSalt) to compute the
 * `argon2_secret_key_hash` verifier locally; the server byte-compares
 * against the per-user row stored at signup.
 */
export const AuthParamsResponseSchema = z.object({
  argon2Params: Argon2ParamsSchema,
  serverArgonSalt: z.string().min(1), // base64, 16 B
});

export const LoginResponseSchema = z.object({
  accessToken: z.string().min(1),
  expiresIn: z.number().int().positive(),
  wrappedMasterDek: z.string().min(1),
  wrappedMasterDekRecovery: z.string().min(1),
  argon2Params: Argon2ParamsSchema,
  serverArgonSalt: z.string().min(1), // base64, 16 B
  userArgonSalt: z.string().min(1), // base64, 16 B
  userPubKey: z.string().min(1),
  wrappedUserSigningSk: z.string().min(1),
  wrappedUserKxSk: z.string().min(1),
});

export const RefreshResponseSchema = z.object({
  accessToken: z.string().min(1),
  expiresIn: z.number().int().positive(),
});

export const MeResponseSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  createdAt: z.string(),
  argon2Params: Argon2ParamsSchema,
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
export type AuthParamsResponse = z.infer<typeof AuthParamsResponseSchema>;
export type LoginResponse = z.infer<typeof LoginResponseSchema>;
export type RefreshResponse = z.infer<typeof RefreshResponseSchema>;
export type MeResponse = z.infer<typeof MeResponseSchema>;

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

async function request<T>(
  path: string,
  opts: {
    method: "GET" | "POST";
    body?: unknown;
    schema: z.ZodSchema<T>;
    accessToken?: string | null;
  },
): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.accessToken) {
    headers["authorization"] = `Bearer ${opts.accessToken}`;
  }
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: opts.method,
      headers,
      credentials: "include",
      ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
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
      const errOpts: ConstructorParameters<typeof AuthClientError>[0] = {
        code: env.data.error.code,
        message: env.data.error.message,
        status: res.status,
      };
      if (env.data.error.requestId !== undefined) {
        errOpts.requestId = env.data.error.requestId;
      }
      throw new AuthClientError(errOpts);
    }
    throw new AuthClientError({
      code: "E5001",
      message: `Request failed: ${String(res.status)}`,
      status: res.status,
    });
  }

  // Allow callers to pass a void-ish schema for 204 responses
  if (res.status === 204) {
    return undefined as unknown as T;
  }

  const ok = opts.schema.safeParse(parsedBody);
  if (!ok.success) {
    throw new AuthClientResponseError(
      `Response shape mismatch on ${path}: ${ok.error.message}`,
    );
  }
  return ok.data;
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

// --- Phase 02-11 surface --------------------------------------------------

export async function getAuthParams(): Promise<AuthParamsResponse> {
  return request("/auth/params", {
    method: "GET",
    schema: AuthParamsResponseSchema,
  });
}

export interface LoginRequest {
  email: string;
  argon2SecretKeyHash: string; // base64, 32 B
}

export async function login(req: LoginRequest): Promise<LoginResponse> {
  return request("/auth/login", {
    method: "POST",
    body: req,
    schema: LoginResponseSchema,
  });
}

export async function refresh(): Promise<RefreshResponse> {
  return request("/auth/refresh", {
    method: "POST",
    body: {}, // server reads cookie, body is ignored but include for content-type
    schema: RefreshResponseSchema,
  });
}

export async function logout(): Promise<void> {
  // Server returns 204 No Content; the request helper short-circuits.
  await request("/auth/logout", {
    method: "POST",
    body: {},
    schema: z.unknown(),
  });
}

export async function me(accessToken: string): Promise<MeResponse> {
  return request("/me", {
    method: "GET",
    schema: MeResponseSchema,
    accessToken,
  });
}

export const authClient = {
  redeemInvite,
  signup,
  getAuthParams,
  login,
  refresh,
  logout,
  me,
};
