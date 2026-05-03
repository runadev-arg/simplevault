/**
 * Phase 03 Plan 08 — `/auth/login` branches on 2FA presence (Truth 8).
 *
 * Mock-based unit spec — no real Postgres, no real Redis, no @nestjs/testing
 * bootstrap. Mirrors the `jwt-epoch.spec.ts` + `2fa-removal.spec.ts` pattern;
 * end-to-end coverage with a real DB lives in Plan 12.
 *
 * Invariants exercised:
 *   1. Wrong creds → null (caller maps to 401 byte-equal envelope) regardless
 *      of whether the user has 2FA enrolled. Anti-enumeration: pre-1FA paths
 *      are identical for 2FA-free vs 2FA-enrolled users.
 *   2. Correct creds + 0 active 2FA methods → `{kind:"session"}` with the
 *      Phase-02 body intact (regression-free). Refresh token issued.
 *   3. Correct creds + ≥1 active 2FA method → `{kind:"2fa-required"}` with
 *      a step-up token, NO refresh issued, NO accessToken in body.
 *   4. Step-up token carries `purpose:"2fa-stepup"` + `epoch` (current value)
 *      and is signed with the SAME `JWT_SECRET` (Key Link 5).
 *   5. Step-up token is rejected by `JwtService.verifyAccessToken` (defence
 *      against forging an access token from a step-up). Conceptual analogue
 *      of `JwtAuthGuard`'s purpose-claim rejection — the guard enforces this
 *      via a pre-decode check.
 *   6. `twoFa.{webauthnAvailable, totpAvailable}` reflect actual per-kind
 *      counts (Truth 8).
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

import { JwtService } from "../src/auth/jwt/jwt.service.js";
import { LoginService } from "../src/auth/login/login.service.js";
import type { LoginDto } from "../src/auth/login/login.dto.js";
import { StepUpJwtService } from "../src/twofa/step-up/step-up-jwt.service.js";

const TEST_JWT_SECRET = "U".repeat(48); // ≥32 raw utf8 bytes — JwtService accepts.
const USER_2FA_FREE = "11111111-1111-1111-1111-111111111111";
const USER_2FA_ENROLLED = "22222222-2222-2222-2222-222222222222";

/** Minimal ConfigService stub. */
function makeConfig(env: Record<string, string>): { get: (k: string) => string | undefined } {
  return {
    get(k: string) {
      return env[k];
    },
  };
}

interface UserFixture {
  id: string;
  email: string;
  argon2_secret_key_hash: Buffer;
  server_argon_salt: Buffer;
  argon2_params: { memoryKiB: number; iterations: number; parallelism: 1 };
  user_argon_salt: Buffer;
  wrapped_master_dek: Buffer;
  wrapped_master_dek_recovery: Buffer;
  user_pub_key: Buffer;
  wrapped_user_signing_sk: Buffer;
  wrapped_user_kx_sk: Buffer;
}

function makeUser(id: string, email: string, hashByte: number): UserFixture {
  return {
    id,
    email,
    argon2_secret_key_hash: Buffer.alloc(32, hashByte),
    server_argon_salt: Buffer.alloc(16, 0xaa),
    argon2_params: { memoryKiB: 65536, iterations: 3, parallelism: 1 },
    user_argon_salt: Buffer.alloc(16, 0xbb),
    wrapped_master_dek: Buffer.from("wmdek"),
    wrapped_master_dek_recovery: Buffer.from("wmdek-rec"),
    user_pub_key: Buffer.from("upub"),
    wrapped_user_signing_sk: Buffer.from("wusk"),
    wrapped_user_kx_sk: Buffer.from("wkxk"),
  };
}

function extractEmailFromSqlChunks(q: unknown): string | null {
  // Drizzle's `sql` tagged template builds an SQL object whose query-chunks
  // include `Param` instances carrying the bound values. We walk all
  // properties looking for the first string that contains "@". Robust to
  // minor drizzle version drift.
  const seen = new Set<unknown>();
  function walk(v: unknown): string | null {
    if (v == null) return null;
    if (typeof v === "string") return v.includes("@") ? v : null;
    if (typeof v !== "object") return null;
    if (seen.has(v)) return null;
    seen.add(v);
    for (const key of Object.keys(v)) {
      const r = walk((v as Record<string, unknown>)[key]);
      if (r !== null) return r;
    }
    return null;
  }
  return walk(q);
}

function makeDb(users: Map<string, UserFixture>): {
  db: { execute: (q: unknown) => Promise<{ rows: UserFixture[] }> };
} {
  return {
    db: {
      async execute(q): Promise<{ rows: UserFixture[] }> {
        const email = extractEmailFromSqlChunks(q);
        if (email === null) return { rows: [] };
        const lower = email.toLowerCase();
        const found = [...users.values()].find((u) => u.email.toLowerCase() === lower);
        return { rows: found ? [found] : [] };
      },
    },
  };
}

interface SessionsStub {
  hashIp: (ip: string) => Buffer;
  parseUaFamily: (ua: string | undefined) => string;
  getEpoch: (userId: string) => Promise<number>;
  createOnLogin: (userId: string, ip: string, ua: string | undefined) => Promise<{
    rawToken: string;
    sessionId: string;
    familyId: string;
    userId: string;
    expiresAt: Date;
  }>;
  refreshTtlSeconds: () => number;
}

function makeSessions(epochs: Map<string, number>): SessionsStub {
  return {
    hashIp: (_ip: string) => Buffer.alloc(32, 0xcc),
    parseUaFamily: (_ua: string | undefined) => "Other",
    async getEpoch(userId: string): Promise<number> {
      return epochs.get(userId) ?? 0;
    },
    async createOnLogin(userId: string, _ip: string, _ua: string | undefined) {
      return {
        rawToken: "raw-refresh-token",
        sessionId: "00000000-0000-0000-0000-0000000000aa",
        familyId: "00000000-0000-0000-0000-0000000000bb",
        userId,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      };
    },
    refreshTtlSeconds: () => 30 * 24 * 60 * 60,
  };
}

interface MethodsStub {
  countActive: (userId: string) => Promise<number>;
  countByKind: (userId: string) => Promise<{ webauthn: number; totp: number }>;
}

function makeMethods(perUser: Map<string, { webauthn: number; totp: number }>): MethodsStub {
  return {
    async countActive(userId: string): Promise<number> {
      const c = perUser.get(userId) ?? { webauthn: 0, totp: 0 };
      return c.webauthn + c.totp;
    },
    async countByKind(userId: string): Promise<{ webauthn: number; totp: number }> {
      return perUser.get(userId) ?? { webauthn: 0, totp: 0 };
    },
  };
}

describe("LoginService — Phase 03 Plan 08 (Truth 8: branch on 2FA presence)", () => {
  let jwt: JwtService;
  let stepUp: StepUpJwtService;
  let svc: LoginService;
  let users: Map<string, UserFixture>;
  let methodCounts: Map<string, { webauthn: number; totp: number }>;
  let epochs: Map<string, number>;
  let sessions: SessionsStub;

  beforeEach(() => {
    process.env.JWT_SECRET = TEST_JWT_SECRET;
    jwt = new JwtService(makeConfig({ JWT_SECRET: TEST_JWT_SECRET, ACCESS_TOKEN_TTL: "900" }) as never);
    jwt.onModuleInit();

    stepUp = new StepUpJwtService(jwt, makeConfig({ STEP_UP_TOKEN_TTL: "120" }) as never);
    stepUp.onModuleInit();

    users = new Map<string, UserFixture>([
      [USER_2FA_FREE, makeUser(USER_2FA_FREE, "free@example.com", 0x11)],
      [USER_2FA_ENROLLED, makeUser(USER_2FA_ENROLLED, "enrolled@example.com", 0x22)],
    ]);
    methodCounts = new Map<string, { webauthn: number; totp: number }>([
      [USER_2FA_FREE, { webauthn: 0, totp: 0 }],
      [USER_2FA_ENROLLED, { webauthn: 1, totp: 0 }],
    ]);
    epochs = new Map<string, number>([
      [USER_2FA_FREE, 0],
      [USER_2FA_ENROLLED, 7], // distinct so we can verify it lands in the step-up token
    ]);

    const db = makeDb(users);
    sessions = makeSessions(epochs);
    const methods = makeMethods(methodCounts);

    svc = new LoginService(
      db as never,
      jwt,
      sessions as never,
      methods as never,
      stepUp,
    );
  });

  function dtoFor(user: UserFixture, hashByte: number): LoginDto {
    return {
      email: user.email,
      argon2SecretKeyHash: Buffer.alloc(32, hashByte),
    };
  }

  // ----------------------- anti-enumeration -----------------------

  it("(1) wrong creds against a 2FA-free user → null (no oracle)", async () => {
    const u = users.get(USER_2FA_FREE)!;
    const result = await svc.login(dtoFor(u, 0x99), "1.2.3.4", "ua");
    expect(result).toBeNull();
  });

  it("(1') wrong creds against a 2FA-ENROLLED user → null — byte-equal to (1)", async () => {
    const u = users.get(USER_2FA_ENROLLED)!;
    const result = await svc.login(dtoFor(u, 0x99), "1.2.3.4", "ua");
    expect(result).toBeNull();
    // Combined with the `auth.login.fail` envelope being uniform on the
    // controller (single throw site, no per-user branching), the wrong-creds
    // response body is byte-equal across the two paths. Verified at the
    // service level: both return null with no side channel.
  });

  it("(1'') unknown email → null (same as wrong creds)", async () => {
    const result = await svc.login(
      { email: "ghost@example.com", argon2SecretKeyHash: Buffer.alloc(32, 0x77) },
      "1.2.3.4",
      "ua",
    );
    expect(result).toBeNull();
  });

  // ------------------- happy path: no 2FA, full session ------------------

  it("(2) correct creds + 0 active methods → kind:'session' with Phase-02 body intact", async () => {
    const u = users.get(USER_2FA_FREE)!;
    const sessSpy = vi.spyOn(sessions, "createOnLogin");

    const result = await svc.login(dtoFor(u, 0x11), "1.2.3.4", "ua");
    expect(result).not.toBeNull();
    if (!result) throw new Error("unreachable");
    expect(result.kind).toBe("session");
    if (result.kind !== "session") throw new Error("unreachable");

    // Phase-02 body shape — every legacy field present, no `kind` discriminator.
    expect(result.body).toMatchObject({
      accessToken: expect.any(String) as unknown,
      expiresIn: 900,
      wrappedMasterDek: expect.any(String) as unknown,
      wrappedMasterDekRecovery: expect.any(String) as unknown,
      argon2Params: { memoryKiB: 65536, iterations: 3, parallelism: 1 },
      serverArgonSalt: expect.any(String) as unknown,
      userArgonSalt: expect.any(String) as unknown,
      userPubKey: expect.any(String) as unknown,
      wrappedUserSigningSk: expect.any(String) as unknown,
      wrappedUserKxSk: expect.any(String) as unknown,
    });
    expect(Object.keys(result.body)).not.toContain("kind");
    expect(Object.keys(result.body)).not.toContain("stepUpToken");

    // Refresh family WAS created.
    expect(sessSpy).toHaveBeenCalledOnce();
    expect(result.refresh.rawToken).toBe("raw-refresh-token");
  });

  // ------------------- happy path: 2FA enrolled, step-up branch ------------------

  it("(3) correct creds + ≥1 active method → kind:'2fa-required'; NO refresh issued; NO accessToken", async () => {
    const u = users.get(USER_2FA_ENROLLED)!;
    const sessSpy = vi.spyOn(sessions, "createOnLogin");

    const result = await svc.login(dtoFor(u, 0x22), "1.2.3.4", "ua");
    expect(result).not.toBeNull();
    if (!result) throw new Error("unreachable");
    expect(result.kind).toBe("2fa-required");
    if (result.kind !== "2fa-required") throw new Error("unreachable");

    // Body shape: discriminator + step-up token + per-kind availability.
    expect(result.body.kind).toBe("2fa-required");
    expect(typeof result.body.stepUpToken).toBe("string");
    expect(result.body.stepUpToken.length).toBeGreaterThan(0);
    expect(result.body.twoFa).toEqual({ webauthnAvailable: true, totpAvailable: false });

    // No accessToken / wrappedMaterial / refresh — the user has no session yet.
    const bodyKeys = Object.keys(result.body);
    expect(bodyKeys).not.toContain("accessToken");
    expect(bodyKeys).not.toContain("wrappedMasterDek");
    expect(bodyKeys).not.toContain("expiresIn");

    // No refresh family was created.
    expect(sessSpy).not.toHaveBeenCalled();
  });

  it("(4) step-up token carries purpose:'2fa-stepup' + the current epoch", async () => {
    const u = users.get(USER_2FA_ENROLLED)!;
    const result = await svc.login(dtoFor(u, 0x22), "1.2.3.4", "ua");
    if (!result || result.kind !== "2fa-required") throw new Error("expected 2fa-required");

    const claims = await stepUp.verify(result.body.stepUpToken);
    expect(claims.sub).toBe(USER_2FA_ENROLLED);
    expect(claims.purpose).toBe("2fa-stepup");
    expect(claims.epoch).toBe(7); // matches the seeded epoch for the user
    expect(claims.exp - claims.iat).toBe(120); // exp = iat + STEP_UP_TOKEN_TTL
  });

  it("(5) step-up token is REJECTED by the access-token verifier (Key Link 5 dual)", async () => {
    // The step-up signer shares JWT_SECRET with the access-token signer
    // (single secret-rotation surface). The `purpose` claim is the only
    // discriminator. JwtService.verifyAccessToken refuses anything missing
    // sid/fam/epoch in the access-token shape — and the production
    // JwtAuthGuard adds a pre-decode `purpose !== undefined` rejection on
    // top (see jwt-auth.guard.ts). Either way, a step-up token cannot
    // impersonate an access token.
    const u = users.get(USER_2FA_ENROLLED)!;
    const result = await svc.login(dtoFor(u, 0x22), "1.2.3.4", "ua");
    if (!result || result.kind !== "2fa-required") throw new Error("expected 2fa-required");

    await expect(jwt.verifyAccessToken(result.body.stepUpToken)).rejects.toThrow(/access token claims/);
  });

  it("(6) twoFa availability flags reflect per-kind counts", async () => {
    // Set the enrolled user to TOTP-only.
    methodCounts.set(USER_2FA_ENROLLED, { webauthn: 0, totp: 1 });
    const u = users.get(USER_2FA_ENROLLED)!;
    const result = await svc.login(dtoFor(u, 0x22), "1.2.3.4", "ua");
    if (!result || result.kind !== "2fa-required") throw new Error("expected 2fa-required");
    expect(result.body.twoFa).toEqual({ webauthnAvailable: false, totpAvailable: true });

    // Both enrolled.
    methodCounts.set(USER_2FA_ENROLLED, { webauthn: 2, totp: 1 });
    const r2 = await svc.login(dtoFor(u, 0x22), "1.2.3.4", "ua");
    if (!r2 || r2.kind !== "2fa-required") throw new Error("expected 2fa-required");
    expect(r2.body.twoFa).toEqual({ webauthnAvailable: true, totpAvailable: true });
  });
});
