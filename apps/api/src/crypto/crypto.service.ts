import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

export interface Argon2Params {
  memoryKiB: number;
  iterations: number;
  parallelism: 1;
}

const ARGON2_DEFAULT_PARAMS: Argon2Params = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
};

const ARGON2_FLOOR_PARAMS: Argon2Params = {
  memoryKiB: 19456,
  iterations: 2,
  parallelism: 1,
};

/**
 * Decode a string secret accepting base64, hex, or raw utf8 — pick the
 * longest interpretation that yields >= `minBytes` bytes. This mirrors the
 * CLI's `readInviteSecret` so operators can paste any reasonable form.
 */
function decodeSecret(raw: string, minBytes: number, name: string): Buffer {
  const candidates: Buffer[] = [];
  // base64
  try {
    const b = Buffer.from(raw, "base64");
    if (b.length >= minBytes && Buffer.from(b.toString("base64").replace(/=+$/, ""), "base64").equals(b)) {
      candidates.push(b);
    }
  } catch {
    /* ignore */
  }
  // hex
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    const b = Buffer.from(raw, "hex");
    if (b.length >= minBytes) candidates.push(b);
  }
  // utf8
  const u = Buffer.from(raw, "utf8");
  if (u.length >= minBytes) candidates.push(u);

  if (candidates.length === 0) {
    throw new Error(`${name} must decode to at least ${minBytes.toString()} bytes (base64/hex/utf8)`);
  }
  // pick longest
  return candidates.reduce((a, b) => (b.length > a.length ? b : a));
}

/**
 * Decode SERVER_ARGON_SALT to EXACTLY `crypto_pwhash_SALTBYTES` (16 bytes).
 *
 * Argon2id requires a fixed 16-byte salt: the client runs libsodium
 * `crypto_pwhash` over `from_base64(serverArgonSalt)` and that call throws
 * ("invalid input") for any other length, which surfaces as an opaque
 * "network/unexpected error" during signup.
 *
 * We CANNOT reuse `decodeSecret` here: its "pick longest" heuristic selects
 * the 24-byte utf8 view of a base64-encoded 16-byte salt (e.g.
 * `openssl rand -base64 16` → `"…=="`, 24 chars) over the correct 16-byte
 * base64 decoding. So we try base64 → hex → utf8 and accept the FIRST that
 * yields exactly 16 bytes.
 */
function decodeArgonSalt(raw: string): Buffer {
  const candidates: Buffer[] = [];
  try {
    const b = Buffer.from(raw, "base64");
    if (Buffer.from(b.toString("base64").replace(/=+$/, ""), "base64").equals(b)) {
      candidates.push(b);
    }
  } catch {
    /* ignore */
  }
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    candidates.push(Buffer.from(raw, "hex"));
  }
  candidates.push(Buffer.from(raw, "utf8"));

  const exact = candidates.find((b) => b.length === 16);
  if (!exact) {
    throw new Error(
      `SERVER_ARGON_SALT must decode to exactly 16 bytes (base64/hex/utf8); ` +
        `candidate lengths were ${candidates.map((c) => c.length.toString()).join("/")}. ` +
        `Generate with \`openssl rand -base64 16\`.`,
    );
  }
  return exact;
}

@Injectable()
export class CryptoService implements OnModuleInit {
  private readonly logger = new Logger(CryptoService.name);
  private inviteSecret!: Buffer;
  private recoveryHmacSecret!: Buffer;
  private serverArgonSalt!: Buffer;
  private params!: Argon2Params;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const inviteRaw = this.config.get<string>("SERVER_INVITE_SECRET") ?? process.env.SERVER_INVITE_SECRET;
    const recoveryRaw =
      this.config.get<string>("SERVER_RECOVERY_HMAC_SECRET") ?? process.env.SERVER_RECOVERY_HMAC_SECRET;
    const argonSaltRaw = this.config.get<string>("SERVER_ARGON_SALT") ?? process.env.SERVER_ARGON_SALT;

    if (!inviteRaw) throw new Error("SERVER_INVITE_SECRET is not set");
    if (!recoveryRaw) throw new Error("SERVER_RECOVERY_HMAC_SECRET is not set");

    this.inviteSecret = decodeSecret(inviteRaw, 32, "SERVER_INVITE_SECRET");
    this.recoveryHmacSecret = decodeSecret(recoveryRaw, 32, "SERVER_RECOVERY_HMAC_SECRET");

    if (argonSaltRaw) {
      // EXACTLY 16 bytes — Argon2id (libsodium crypto_pwhash) rejects any other
      // length. `decodeSecret`'s pick-longest heuristic would wrongly yield the
      // 24-byte utf8 view of a base64-encoded 16-byte salt; use the dedicated
      // exact-length decoder instead.
      this.serverArgonSalt = decodeArgonSalt(argonSaltRaw);
    } else {
      this.logger.warn(
        "SERVER_ARGON_SALT is not set — using a random in-memory salt (auth verifiers will not survive restarts; set in prod)",
      );
      // Random 16B; warn-only for dev convenience. Production .env.example documents this.
      this.serverArgonSalt = randomBytes(16);
    }

    const memoryKiB = parseIntEnv(this.config.get<string>("ARGON2_MEMORY_KIB") ?? process.env.ARGON2_MEMORY_KIB);
    const iterations = parseIntEnv(this.config.get<string>("ARGON2_ITERATIONS") ?? process.env.ARGON2_ITERATIONS);
    const parallelism = parseIntEnv(
      this.config.get<string>("ARGON2_PARALLELISM") ?? process.env.ARGON2_PARALLELISM,
    );

    if (memoryKiB && iterations && parallelism === 1) {
      this.params = { memoryKiB, iterations, parallelism: 1 };
    } else {
      this.logger.warn(
        "ARGON2_* env not fully set — falling back to defaults; run `pnpm cli argon2 calibrate` on the prod VPS",
      );
      this.params = ARGON2_DEFAULT_PARAMS;
    }

    if (
      this.params.memoryKiB < ARGON2_FLOOR_PARAMS.memoryKiB ||
      this.params.iterations < ARGON2_FLOOR_PARAMS.iterations
    ) {
      throw new Error(
        `Argon2 params below floor (m=${this.params.memoryKiB.toString()},t=${this.params.iterations.toString()}); floor is m=${ARGON2_FLOOR_PARAMS.memoryKiB.toString()},t=${ARGON2_FLOOR_PARAMS.iterations.toString()}`,
      );
    }
  }

  /** HMAC-SHA256(SERVER_INVITE_SECRET, raw_code_utf8_bytes). */
  inviteCodeHmac(rawCodeUtf8: Buffer): Buffer {
    return createHmac("sha256", this.inviteSecret).update(rawCodeUtf8).digest();
  }

  /** HMAC-SHA256(SERVER_RECOVERY_HMAC_SECRET, client-computed sha256(phrase)). */
  outerRecoveryHmac(innerSha256: Buffer): Buffer {
    return createHmac("sha256", this.recoveryHmacSecret).update(innerSha256).digest();
  }

  /** Per-deployment argon2 params (operator-tuned via `pnpm cli argon2 calibrate`). */
  argon2Params(): Argon2Params {
    return { ...this.params };
  }

  /** Server-side default Argon2 salt (16 B). Stored per-user at signup. */
  defaultServerArgonSalt(): Buffer {
    return Buffer.from(this.serverArgonSalt);
  }

  /** Constant-time bytea equality (returns false for length mismatches). */
  constantTimeEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  /** Per-plan: validate signed-in argon2 params are at-or-above the floor (KDF-downgrade defence). */
  validateArgon2ParamsAboveFloor(p: { memoryKiB: number; iterations: number; parallelism: number }): boolean {
    return (
      p.memoryKiB >= ARGON2_FLOOR_PARAMS.memoryKiB &&
      p.iterations >= ARGON2_FLOOR_PARAMS.iterations &&
      p.parallelism === 1
    );
  }
}

function parseIntEnv(v: string | undefined): number {
  if (!v) return 0;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
