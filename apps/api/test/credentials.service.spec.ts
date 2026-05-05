/**
 * Phase 04 / Plan 02 — credentials CAS PATCH + uniform-404 spec.
 *
 * RED in T1, GREEN in T2. Tests exercise three load-bearing invariants:
 *
 *   1. Concurrent PATCH race — two simultaneous updates with the same
 *      `version` witness; exactly one wins, the other 409.
 *   2. Version-rollback rejection — PATCH with stale `version` (row already
 *      bumped) rejects 409 even if no concurrent writer is racing.
 *   3. Uniform 404 — cross-user GET / PATCH / DELETE returns
 *      `CREDENTIAL_NOT_FOUND` (NOT 403) — anti-enumeration (Truth 3).
 *
 * Pattern: mock-based unit test (no real Postgres), mirroring
 * `2fa-removal.spec.ts` + `jwt-epoch.spec.ts`. The fake `DbService` runs
 * an in-memory SQL simulator that:
 *   - INSERTs into credentials only when the joined vaults.owner_user_id
 *     matches (so cross-user POST returns 404 via empty rowset).
 *   - SELECT joins on credentials × vaults filtered by owner_user_id.
 *   - UPDATEs atomically with a CAS (`version = $witness`) — concurrent
 *     calls are serialised through a per-row mutex so the race resolves
 *     deterministically (exactly-one-winner) just like a real Postgres
 *     row-lock would.
 *   - DELETEs with the same ownership join.
 *
 * The simulator intentionally MIRRORS Postgres semantics, not the literal
 * SQL string — what matters is that a CAS race resolves to one winner, a
 * stale version returns zero rows, and cross-user queries return zero rows.
 * Real-PG end-to-end coverage lives in Plan 12 (Cypress + service containers).
 */
import { HttpException } from "@nestjs/common";
import { describe, it, expect, beforeEach } from "vitest";

import {
  CredentialsService,
  type CreateCredentialDto,
  type UpdateCredentialDto,
} from "../src/credentials/credentials.service.js";

const USER_A = "11111111-1111-1111-1111-111111111111";
const USER_B = "22222222-2222-2222-2222-222222222222";
const VAULT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const VAULT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const CRED_A = "cccccccc-cccc-cccc-cccc-cccccccccc01";

// ---------------------------------------------------------------- simulator

interface CredentialRow {
  id: string;
  vault_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  updated_at: Date;
}

interface VaultRow {
  id: string;
  owner_user_id: string;
  kind: string;
}

interface ExecResult<T> {
  rows: T[];
  rowCount: number;
}

/**
 * In-memory `db.execute(sql)` simulator. Inspects the query's compiled
 * `.sql` + `.params` (drizzle's `sql` template object) to dispatch INSERT /
 * SELECT / UPDATE / DELETE against an in-memory Map.
 *
 * Per-row mutex: every UPDATE awaits a tiny tick BEFORE checking the CAS
 * predicate, so two concurrent UPDATEs overlap in the JS event loop window
 * — exactly the race the production PG row lock guards against. Without
 * this, JS's run-to-completion semantics would serialise the two awaits and
 * the race wouldn't be a real race.
 */
class FakeDb {
  vaults: Map<string, VaultRow> = new Map();
  credentials: Map<string, CredentialRow> = new Map();
  /** Per-credential-id mutex tail. Awaiting this serialises CAS writes. */
  private rowLocks: Map<string, Promise<void>> = new Map();

  constructor() {
    this.vaults.set(VAULT_A, { id: VAULT_A, owner_user_id: USER_A, kind: "personal" });
    this.vaults.set(VAULT_B, { id: VAULT_B, owner_user_id: USER_B, kind: "personal" });
  }

  /** Seed a credential bypassing the service (raw insert). */
  seedCredential(row: Omit<CredentialRow, "updated_at"> & { updated_at?: Date }): void {
    this.credentials.set(row.id, {
      ...row,
      updated_at: row.updated_at ?? new Date(),
    });
  }

  // The drizzle `sql` template returns an SQL object; its `.queryChunks` /
  // private params are not stable. We instead expose `db.execute(...)` as
  // an async function that the SERVICE will call with a `sql` template.
  // For the test simulator, we intercept by parsing the operation kind
  // from the first non-empty word of `String(sqlObj)`.
  //
  // To make this robust, we expose a helper on the `db` object that the
  // service can use directly. But we don't want to change production code
  // — so the simulator instead parses drizzle's exposed `sql` shape.
  //
  // Drizzle's `SQL` instance has a `.queryChunks` array with mixed
  // strings + Param objects. We concat the strings + collect params in
  // order to reconstruct intent.
  async execute<T = unknown>(sqlObj: unknown): Promise<ExecResult<T>> {
    const { text, params } = compileSql(sqlObj);
    const norm = text.toLowerCase().replace(/\s+/g, " ").trim();

    if (norm.startsWith("insert into credentials")) {
      return this.handleInsert(params) as ExecResult<T>;
    }
    if (norm.startsWith("select")) {
      return this.handleSelect(norm, params) as ExecResult<T>;
    }
    if (norm.startsWith("update credentials")) {
      return this.handleUpdate(params) as ExecResult<T>;
    }
    if (norm.startsWith("delete from credentials")) {
      return this.handleDelete(params) as ExecResult<T>;
    }
    throw new Error(`FakeDb: unhandled SQL: ${norm}`);
  }

  private handleInsert(params: unknown[]): ExecResult<CredentialRow> {
    // Param order (per service GREEN impl):
    //   [credentialIdOrNull, ciphertext, nonce, aadParamsJson, vaultId, ownerUserId]
    const [credId, ciphertext, nonce, aadParamsJson, vaultId, ownerUserId] = params as [
      string | null,
      Uint8Array,
      Uint8Array,
      string,
      string,
      string,
    ];
    const v = this.vaults.get(vaultId);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    const id = credId ?? randomUuid();
    const row: CredentialRow = {
      id,
      vault_id: vaultId,
      version: 1,
      ciphertext,
      nonce,
      aad_params_json: aadParamsJson,
      updated_at: new Date(),
    };
    this.credentials.set(id, row);
    return { rows: [row], rowCount: 1 };
  }

  private handleSelect(_norm: string, params: unknown[]): ExecResult<CredentialRow> {
    // Param order (getById + post-failure ownership probe):
    //   [credId, ownerUserId]
    const [credId, ownerUserId] = params as [string, string];
    const row = this.credentials.get(credId);
    if (!row) return { rows: [], rowCount: 0 };
    const v = this.vaults.get(row.vault_id);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    return { rows: [row], rowCount: 1 };
  }

  private async handleUpdate(params: unknown[]): Promise<ExecResult<CredentialRow>> {
    // Param order:
    //   [ciphertext, nonce, aadParamsJson, credId, casVersion, ownerUserId]
    const [ciphertext, nonce, aadParamsJson, credId, casVersion, ownerUserId] = params as [
      Uint8Array,
      Uint8Array,
      string,
      string,
      number,
      string,
    ];

    // Per-row mutex: serialise concurrent UPDATEs through a single tail
    // promise so two `Promise.all([update, update])` calls actually queue
    // (exactly mirroring how Postgres FOR UPDATE row lock would behave).
    const prev = this.rowLocks.get(credId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.rowLocks.set(credId, prev.then(() => next));
    await prev;
    try {
      // Yield once so the microtask queue interleaves competing callers
      // BEFORE we read the row — this is what makes the race observable.
      await new Promise<void>((r) => { setTimeout(r, 0); });
      const row = this.credentials.get(credId);
      if (!row) return { rows: [], rowCount: 0 };
      const v = this.vaults.get(row.vault_id);
      if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
      if (row.version !== casVersion) return { rows: [], rowCount: 0 };
      const updated: CredentialRow = {
        ...row,
        ciphertext,
        nonce,
        aad_params_json: aadParamsJson,
        version: row.version + 1,
        updated_at: new Date(),
      };
      this.credentials.set(credId, updated);
      return { rows: [updated], rowCount: 1 };
    } finally {
      release();
    }
  }

  private handleDelete(params: unknown[]): ExecResult<{ id: string }> {
    const [credId, ownerUserId] = params as [string, string];
    const row = this.credentials.get(credId);
    if (!row) return { rows: [], rowCount: 0 };
    const v = this.vaults.get(row.vault_id);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    this.credentials.delete(credId);
    return { rows: [{ id: credId }], rowCount: 1 };
  }
}

/**
 * Compile a drizzle `sql` template into `{text, params}` for the simulator.
 * Drizzle's SQL instance exposes a `.queryChunks` array of strings + Param
 * objects (the latter wrap the substituted value in `.value`). We walk it
 * to reconstruct ordered params; the leftover string fragments form the
 * dispatch text.
 */
function compileSql(sqlObj: unknown): { text: string; params: unknown[] } {
  if (sqlObj === null || typeof sqlObj !== "object") {
    return { text: String(sqlObj), params: [] };
  }
  // Drizzle SQL.queryChunks is an internal field; access via index.
  const chunks =
    (sqlObj as { queryChunks?: unknown[] }).queryChunks ??
    (sqlObj as { chunks?: unknown[] }).chunks ??
    [];
  const text: string[] = [];
  const params: unknown[] = [];
  for (const chunk of chunks) {
    // StringChunk: { value: string[] } — pure SQL fragment.
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
    // Param wrapper: { value, encoder } — substituted value w/ encoder.
    if (
      chunk &&
      typeof chunk === "object" &&
      "value" in chunk &&
      "encoder" in chunk
    ) {
      params.push((chunk as { value: unknown }).value);
      text.push("?");
      continue;
    }
    // Anything else (raw string / Uint8Array / number / null) is a
    // direct interpolated param. Drizzle inlines primitive values when
    // the encoder isn't bound at template-build time.
    params.push(chunk);
    text.push("?");
  }
  return { text: text.join(""), params };
}

function randomUuid(): string {
  return "00000000-0000-4000-8000-" + Math.random().toString(16).slice(2, 14).padEnd(12, "0");
}

// ---------------------------------------------------------------- harness

interface Kit {
  svc: CredentialsService;
  fake: FakeDb;
}

function makeKit(): Kit {
  const fake = new FakeDb();
  // DbService shape: `{ db: DbClient }` — the service uses `this.dbSvc.db.execute(...)`.
  const dbSvc = { db: fake } as never;
  const svc = new CredentialsService(dbSvc);
  return { svc, fake };
}

function bytes(...vals: number[]): Uint8Array {
  return Uint8Array.from(vals);
}

function makeCreateDto(overrides: Partial<CreateCredentialDto> = {}): CreateCredentialDto {
  return {
    vaultId: VAULT_A,
    ciphertext: bytes(1, 2, 3),
    nonce: bytes(...new Array<number>(24).fill(7)),
    aadParamsJson: '{"vaultId":"' + VAULT_A + '","credentialId":"x","version":1}',
    version: 1,
    ...overrides,
  };
}

function makeUpdateDto(version: number, overrides: Partial<UpdateCredentialDto> = {}): UpdateCredentialDto {
  return {
    ciphertext: bytes(9, 9, 9),
    nonce: bytes(...new Array<number>(24).fill(8)),
    aadParamsJson: '{"v":' + String(version) + "}",
    version,
    ...overrides,
  };
}

// ---------------------------------------------------------------- specs

describe("CredentialsService — CAS PATCH + uniform-404 (Plan 04-02)", () => {
  let kit: Kit;
  beforeEach(() => {
    kit = makeKit();
  });

  it("(1) create: owner happy path returns {id, vaultId, version: 1, updatedAt}", async () => {
    const r = await kit.svc.create(USER_A, makeCreateDto({ credentialId: CRED_A }));
    expect(r.id).toBe(CRED_A);
    expect(r.vaultId).toBe(VAULT_A);
    expect(r.version).toBe(1);
    expect(typeof r.updatedAt).toBe("string");
  });

  it("(2) create: cross-user vaultId → 404 CREDENTIAL_NOT_FOUND (anti-enum)", async () => {
    // userA tries to insert into VAULT_B (owned by userB).
    await expect(
      kit.svc.create(USER_A, makeCreateDto({ vaultId: VAULT_B })),
    ).rejects.toMatchObject({
      response: { error: { code: "E2006" } },
      status: 404,
    });
  });

  it("(3) getById: owner returns full row including ciphertext + nonce + aadParamsJson", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(1, 1, 1),
      nonce: bytes(...new Array<number>(24).fill(2)),
      aad_params_json: '{"v":1}',
    });
    const r = await kit.svc.getById(USER_A, CRED_A);
    expect(r.id).toBe(CRED_A);
    expect(r.vaultId).toBe(VAULT_A);
    expect(r.version).toBe(1);
    expect(r.ciphertext).toEqual(bytes(1, 1, 1));
    expect(r.nonce?.length).toBe(24);
    expect(r.aadParamsJson).toBe('{"v":1}');
  });

  it("(4) getById: cross-user returns 404 CREDENTIAL_NOT_FOUND (NOT 403)", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    await expect(kit.svc.getById(USER_B, CRED_A)).rejects.toMatchObject({
      response: { error: { code: "E2006" } },
      status: 404,
    });
  });

  it("(5) update: CAS happy path bumps version 1 → 2", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(1),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    const r = await kit.svc.update(USER_A, CRED_A, makeUpdateDto(1));
    expect(r.version).toBe(2);
  });

  it("(6) update: concurrent CAS race — exactly one winner, other 409", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    const results = await Promise.allSettled([
      kit.svc.update(USER_A, CRED_A, makeUpdateDto(1)),
      kit.svc.update(USER_A, CRED_A, makeUpdateDto(1)),
    ]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    // The winner sees version=2 (1 → 2).
    const winner = (fulfilled[0] as PromiseFulfilledResult<{ version: number }>).value;
    expect(winner.version).toBe(2);
    // The loser is a 409 CREDENTIAL_VERSION_CONFLICT.
    const err = (rejected[0] as PromiseRejectedResult).reason as HttpException;
    expect(err).toBeInstanceOf(HttpException);
    expect(err.getStatus()).toBe(409);
    const body = err.getResponse() as { error?: { code?: string } };
    expect(body.error?.code).toBe("E2007");
  });

  it("(7) update: version-rollback (row at v=3, caller witnesses v=1) → 409", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 3,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    await expect(
      kit.svc.update(USER_A, CRED_A, makeUpdateDto(1)),
    ).rejects.toMatchObject({
      response: { error: { code: "E2007" } },
      status: 409,
    });
  });

  it("(8) update: cross-user → 404 (NOT 409 — uniform-404 anti-enum)", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    await expect(
      kit.svc.update(USER_B, CRED_A, makeUpdateDto(1)),
    ).rejects.toMatchObject({
      response: { error: { code: "E2006" } },
      status: 404,
    });
  });

  it("(9) delete: owner removes; subsequent getById → 404", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    await expect(kit.svc.delete(USER_A, CRED_A)).resolves.toBeUndefined();
    await expect(kit.svc.getById(USER_A, CRED_A)).rejects.toMatchObject({
      response: { error: { code: "E2006" } },
      status: 404,
    });
  });

  it("(10) delete: cross-user → 404 CREDENTIAL_NOT_FOUND", async () => {
    kit.fake.seedCredential({
      id: CRED_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
    });
    await expect(kit.svc.delete(USER_B, CRED_A)).rejects.toMatchObject({
      response: { error: { code: "E2006" } },
      status: 404,
    });
    // Row still present.
    expect(kit.fake.credentials.has(CRED_A)).toBe(true);
  });
});
