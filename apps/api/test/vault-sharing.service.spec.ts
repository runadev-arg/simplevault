/**
 * Phase 07 / Plan 02 — VaultSharingService unit tests.
 *
 * Pattern: mock-based unit test (no real Postgres), mirroring the
 * credentials.service.spec.ts approach. The fake DbService intercepts
 * `db.execute(sql)` calls by inspecting the compiled SQL text + params.
 *
 * Covered invariants:
 *   1. createGroupVault — inserts vault + owner membership row
 *   2. lookupUser — returns 404 for requester's own email (anti-enumeration)
 *   3. createInvite — throws ACCESS_DENIED if requester is not owner
 *   4. acceptInvite — throws NOT_FOUND when 0 rows updated
 *   5. removeMember — throws 409 when removing last owner
 */
import { beforeEach, describe, expect, it } from "vitest";

import { VaultSharingService } from "../src/vault-sharing/vault-sharing.service.js";

// ─────────────────────────────────────────── fixture constants

const USER_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const USER_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const VAULT_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const INVITE_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const WRAPPED_KEY_B64 = Buffer.from("fakewrappedkey").toString("base64url");

// ─────────────────────────────────────────── SQL parser helpers

function compileSql(sqlObj: unknown): { text: string; params: unknown[] } {
  if (sqlObj === null || typeof sqlObj !== "object") {
    return { text: String(sqlObj), params: [] };
  }
  const chunks =
    (sqlObj as { queryChunks?: unknown[] }).queryChunks ??
    (sqlObj as { chunks?: unknown[] }).chunks ??
    [];
  const text: string[] = [];
  const params: unknown[] = [];
  for (const chunk of chunks) {
    if (
      chunk &&
      typeof chunk === "object" &&
      "value" in chunk &&
      Array.isArray((chunk as { value: unknown }).value) &&
      ((chunk as { value: unknown[] }).value).every((s) => typeof s === "string")
    ) {
      text.push(((chunk as { value: string[] }).value).join(""));
      continue;
    }
    if (chunk && typeof chunk === "object" && "value" in chunk && "encoder" in chunk) {
      params.push((chunk as { value: unknown }).value);
      text.push("?");
      continue;
    }
    params.push(chunk);
    text.push("?");
  }
  return { text: text.join(""), params };
}

// ─────────────────────────────────────────── fake DB

interface ExecResult<T = unknown> {
  rows: T[];
  rowCount: number;
}

type SqlHandler = (norm: string, params: unknown[]) => ExecResult | Promise<ExecResult>;

/**
 * Minimal fake DbService. Each test configures `handlers` to intercept
 * specific SQL patterns. Unhandled queries throw to surface accidental calls.
 */
class FakeDb {
  handlers: SqlHandler[] = [];
  calls: Array<{ norm: string; params: unknown[] }> = [];

  async execute<T = unknown>(sqlObj: unknown): Promise<ExecResult<T>> {
    const { text, params } = compileSql(sqlObj);
    const norm = text.toLowerCase().replace(/\s+/g, " ").trim();
    this.calls.push({ norm, params });

    for (const handler of this.handlers) {
      const result = await handler(norm, params);
      // A handler returns undefined to pass to the next handler.
      // Using null as a sentinel to mean "not handled" is too ambiguous, so
      // we check rows — if rows is undefined the handler deferred.
      if (result !== undefined) return result as ExecResult<T>;
    }
    throw new Error(`FakeDb: unhandled SQL:\n${norm}\nparams: ${JSON.stringify(params)}`);
  }

  // A helper to simulate a transaction (just calls the callback with `this`).
  async transaction<T>(fn: (tx: FakeDb) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

// ─────────────────────────────────────────── harness

function makeKit() {
  const fake = new FakeDb();
  // VaultSharingService uses `this.db.db.execute(...)` and `this.db.db.transaction(...)`
  const dbSvc = { db: fake } as never;
  const svc = new VaultSharingService(dbSvc);
  return { svc, fake };
}

// ─────────────────────────────────────────── tests

describe("VaultSharingService (Plan 07-02)", () => {
  let kit: ReturnType<typeof makeKit>;

  beforeEach(() => {
    kit = makeKit();
  });

  // ────────── (1) createGroupVault

  it("(1) createGroupVault — inserts vault row then owner membership row", async () => {
    const insertedCalls: string[] = [];
    kit.fake.handlers.push((norm, _params) => {
      if (norm.startsWith("insert into vaults")) {
        insertedCalls.push("vault");
        return { rows: [{ id: VAULT_ID, name: "My Team", kind: "shared" }], rowCount: 1 };
      }
      if (norm.startsWith("insert into vault_memberships")) {
        insertedCalls.push("membership");
        return { rows: [], rowCount: 1 };
      }
      return undefined as unknown as ExecResult;
    });

    const result = await kit.svc.createGroupVault(USER_A, "My Team", WRAPPED_KEY_B64);
    expect(result.id).toBe(VAULT_ID);
    expect(result.name).toBe("My Team");
    expect(result.kind).toBe("shared");
    expect(insertedCalls).toEqual(["vault", "membership"]);
  });

  it("(1b) createGroupVault — validation rejects empty name", async () => {
    await expect(kit.svc.createGroupVault(USER_A, "", WRAPPED_KEY_B64)).rejects.toMatchObject({
      status: 400,
      response: { error: { code: "E4001" } },
    });
  });

  it("(1c) createGroupVault — validation rejects name > 100 chars", async () => {
    const longName = "x".repeat(101);
    await expect(kit.svc.createGroupVault(USER_A, longName, WRAPPED_KEY_B64)).rejects.toMatchObject({
      status: 400,
      response: { error: { code: "E4001" } },
    });
  });

  // ────────── (2) lookupUser — own email returns 404

  it("(2) lookupUser — returns 404 for requester's own email (anti-enumeration)", async () => {
    kit.fake.handlers.push((_norm, _params) => {
      // Return the row with the same user id as the requester
      return {
        rows: [{ id: USER_A, email: "alice@example.com", user_pub_key: Buffer.from("pubkey") }],
        rowCount: 1,
      };
    });

    await expect(kit.svc.lookupUser(USER_A, "alice@example.com")).rejects.toMatchObject({
      status: 404,
      response: { error: { code: "E2016" } },
    });
  });

  it("(2b) lookupUser — returns 404 for non-existent email", async () => {
    kit.fake.handlers.push((_norm, _params) => {
      return { rows: [], rowCount: 0 };
    });

    await expect(kit.svc.lookupUser(USER_A, "nobody@example.com")).rejects.toMatchObject({
      status: 404,
      response: { error: { code: "E2016" } },
    });
  });

  it("(2c) lookupUser — returns id + kxPublicKey for a different user", async () => {
    const pubKey = Buffer.from("x25519pubkey");
    kit.fake.handlers.push((_norm, _params) => {
      return {
        rows: [{ id: USER_B, email: "bob@example.com", user_pub_key: pubKey }],
        rowCount: 1,
      };
    });

    const result = await kit.svc.lookupUser(USER_A, "bob@example.com");
    expect(result.id).toBe(USER_B);
    expect(result.kxPublicKey).toBe(pubKey.toString("base64url"));
  });

  // ────────── (3) createInvite — throws 403 if requester is not owner

  it("(3) createInvite — throws ACCESS_DENIED (403) if requester is not owner", async () => {
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        // Requester is NOT an owner → return empty rows
        return { rows: [], rowCount: 0 };
      }
      return undefined as unknown as ExecResult;
    });

    await expect(
      kit.svc.createInvite(USER_A, VAULT_ID, USER_B, WRAPPED_KEY_B64),
    ).rejects.toMatchObject({
      status: 403,
      response: { error: { code: "E2015" } },
    });
  });

  it("(3b) createInvite — succeeds when requester is owner", async () => {
    let membershipInserted = false;
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        // Requester IS an owner
        return { rows: [{ id: "some-membership-id" }], rowCount: 1 };
      }
      if (norm.startsWith("insert into vault_memberships")) {
        membershipInserted = true;
        return { rows: [], rowCount: 1 };
      }
      return undefined as unknown as ExecResult;
    });

    await expect(
      kit.svc.createInvite(USER_A, VAULT_ID, USER_B, WRAPPED_KEY_B64),
    ).resolves.toBeUndefined();
    expect(membershipInserted).toBe(true);
  });

  it("(3c) createInvite — throws 409 VAULT_ALREADY_MEMBER on unique constraint violation", async () => {
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        return { rows: [{ id: "some-membership-id" }], rowCount: 1 };
      }
      if (norm.startsWith("insert into vault_memberships")) {
        const err = Object.assign(new Error("unique constraint"), { code: "23505" });
        throw err;
      }
      return undefined as unknown as ExecResult;
    });

    await expect(
      kit.svc.createInvite(USER_A, VAULT_ID, USER_B, WRAPPED_KEY_B64),
    ).rejects.toMatchObject({
      status: 409,
      response: { error: { code: "E2014" } },
    });
  });

  // ────────── (4) acceptInvite — throws NOT_FOUND when 0 rows updated

  it("(4) acceptInvite — throws VAULT_INVITE_NOT_FOUND (404) when 0 rows updated", async () => {
    kit.fake.handlers.push((_norm, _params) => {
      // UPDATE returns 0 rows
      return { rows: [], rowCount: 0 };
    });

    await expect(kit.svc.acceptInvite(USER_A, INVITE_ID)).rejects.toMatchObject({
      status: 404,
      response: { error: { code: "E2013" } },
    });
  });

  it("(4b) acceptInvite — succeeds when row is updated", async () => {
    kit.fake.handlers.push((_norm, _params) => {
      return { rows: [{ id: INVITE_ID }], rowCount: 1 };
    });

    await expect(kit.svc.acceptInvite(USER_A, INVITE_ID)).resolves.toBeUndefined();
  });

  // ────────── (5) removeMember — throws 409 when removing last owner

  it("(5) removeMember — throws 409 when removing last owner", async () => {
    let callCount = 0;
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        callCount++;
        if (callCount === 1) {
          // Self-removal check: not same user, so this is the owner check
          // Actually USER_A removing USER_A — self removal case
          // We need to set it up so requesterId === targetUserId for last-owner test
          return { rows: [{ id: "mem-id" }], rowCount: 1 };
        }
      }
      if (norm.includes("select id, role, status from vault_memberships")) {
        // Target IS an owner
        return { rows: [{ id: "mem-id", role: "owner", status: "active" }], rowCount: 1 };
      }
      if (norm.includes("select count(*)::int as n")) {
        // Only 1 active owner
        return { rows: [{ n: 1 }], rowCount: 1 };
      }
      return undefined as unknown as ExecResult;
    });

    // USER_A removing themselves (self-removal path) — they're the last owner
    await expect(kit.svc.removeMember(USER_A, VAULT_ID, USER_A)).rejects.toMatchObject({
      status: 409,
    });
  });

  it("(5b) removeMember — non-owner trying to remove another user → 403", async () => {
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        // Requester is NOT an owner
        return { rows: [], rowCount: 0 };
      }
      return undefined as unknown as ExecResult;
    });

    // USER_A (not an owner) tries to remove USER_B
    await expect(kit.svc.removeMember(USER_A, VAULT_ID, USER_B)).rejects.toMatchObject({
      status: 403,
      response: { error: { code: "E2015" } },
    });
  });

  it("(5c) removeMember — owner can remove a member (non-owner target)", async () => {
    let deleteCount = 0;
    kit.fake.handlers.push((norm, _params) => {
      if (norm.includes("select id from vault_memberships")) {
        // Requester is an owner
        return { rows: [{ id: "owner-mem-id" }], rowCount: 1 };
      }
      if (norm.includes("select id, role, status from vault_memberships")) {
        // Target is a regular member, not an owner
        return { rows: [{ id: "target-mem-id", role: "member", status: "active" }], rowCount: 1 };
      }
      if (norm.startsWith("delete from vault_memberships")) {
        deleteCount++;
        return { rows: [{ id: "target-mem-id" }], rowCount: 1 };
      }
      return undefined as unknown as ExecResult;
    });

    await expect(kit.svc.removeMember(USER_A, VAULT_ID, USER_B)).resolves.toBeUndefined();
    expect(deleteCount).toBe(1);
  });
});
