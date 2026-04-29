import { HttpException, HttpStatus, Logger } from "@nestjs/common";
import type { Request } from "express";

/**
 * Coarse in-memory per-IP rate limiter — placeholder until 02-09 lands a
 * Redis-backed @nestjs/throttler config. Process-local, fixed-window.
 *
 * Thread-safe in Node (single-threaded event loop). When the API runs
 * multi-replica each replica gets its own window, so the effective ceiling
 * is `limit * replicas` — acceptable for v1 anti-DB-spam (see 02-07
 * carry-overs §8). Phase 02-09 supersedes.
 */
export class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();
  private readonly logger = new Logger(FixedWindowRateLimiter.name);

  constructor(
    private readonly name: string,
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  /** Throws 429 if `key` (typically client IP) exceeds the per-window quota. */
  consume(key: string): void {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + this.windowMs });
      this.maybeGc(now);
      return;
    }
    bucket.count += 1;
    if (bucket.count > this.limit) {
      const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      this.logger.warn(
        { limiter: this.name, key_hash_prefix: hashPrefix(key), count: bucket.count, retryAfterSec },
        "rate-limit hit",
      );
      throw new HttpException(
        { message: "Too many requests", retryAfter: retryAfterSec },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  /** Best-effort GC — sweep when bucket count is high. */
  private maybeGc(now: number): void {
    if (this.buckets.size < 1024) return;
    for (const [k, v] of this.buckets) {
      if (v.resetAt <= now) this.buckets.delete(k);
    }
  }
}

/** Extract a coarse client-IP key (trust-proxy-aware via Express). */
export function clientIpKey(req: Request): string {
  const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
  return ip;
}

function hashPrefix(s: string): string {
  // Cheap non-cryptographic prefix for log correlation only — never log raw IP.
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8, "0").slice(0, 8);
}
