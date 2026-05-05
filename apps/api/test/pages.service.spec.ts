/**
 * Phase 05 / Plan 02 — pages CAS PATCH + history rotation + uniform-404 spec.
 *
 * RED in T1, GREEN in T2. Tests exercise the load-bearing invariants:
 *
 *   1. PATCH happy path — version bumps `n -> n+1`, response carries the
 *      post-update version + updatedAt.
 *   2. PATCH stale-witness → 409 PAGE_VERSION_CONFLICT, DB unchanged.
 *   3. PATCH inserts the PRE-update snapshot into `page_versions` with the
 *      OLD ciphertext / nonce / aad / version BEFORE bumping `pages`.
 *   4. PATCH after the page already has 10 history entries — after rotation
 *      `page_versions` count stays at 10 and the surviving rows are versions
 *      `current-9 .. current` (descending).
 *   5. PATCH transaction is atomic — failure inside rotation rolls back the
 *      page UPDATE AND leaves no orphan `page_versions` row.
 *   6. Cross-user PATCH → 404 PAGE_NOT_FOUND (NOT 403 — anti-enum).
 *   7. Concurrent PATCH race — two clients with the same witness; exactly
 *      one wins, the other 409.
 *
 * The fake DB simulates a single transactional context with a per-row mutex,
 * mirroring the credentials-service test pattern (Plan 04-02). Real-PG
 * end-to-end coverage lives in Plan 12 (Cypress + service containers).
 */
import { HttpException } from "@nestjs/common";
import { describe, it, expect, beforeEach } from "vitest";

import {
  PagesService,
  type CreatePageDto,
  type UpdatePageDto,
} from "../src/pages/pages.service.js";

const USER_A = "11111111-1111-1111-1111-111111111111";
const USER_B = "22222222-2222-2222-2222-222222222222";
const VAULT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const VAULT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const PAGE_A = "dddddddd-dddd-dddd-dddd-dddddddddd01";

// ---------------------------------------------------------------- simulator

interface PageRow {
  id: string;
  vault_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  title_search_token: Uint8Array;
  is_locked: boolean;
  created_at: Date;
  updated_at: Date;
}

interface PageVersionRow {
  id: string;
  page_id: string;
  version: number;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aad_params_json: string;
  created_at: Date;
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

class FakeDb {
  vaults: Map<string, VaultRow> = new Map();
  pages: Map<string, PageRow> = new Map();
  pageVersions: PageVersionRow[] = [];
  /** Per-page-id mutex tail. */
  private rowLocks: Map<string, Promise<void>> = new Map();
  /** Inject a failure inside the rotation step (DELETE on page_versions). */
  rotationFailureMode = false;

  constructor() {
    this.vaults.set(VAULT_A, { id: VAULT_A, owner_user_id: USER_A, kind: "personal" });
    this.vaults.set(VAULT_B, { id: VAULT_B, owner_user_id: USER_B, kind: "personal" });
  }

  seedPage(row: Omit<PageRow, "created_at" | "updated_at" | "is_locked"> & {
    created_at?: Date;
    updated_at?: Date;
    is_locked?: boolean;
  }): void {
    const now = new Date();
    this.pages.set(row.id, {
      ...row,
      is_locked: row.is_locked ?? false,
      created_at: row.created_at ?? now,
      updated_at: row.updated_at ?? now,
    });
  }

  seedHistory(row: Omit<PageVersionRow, "id" | "created_at"> & { created_at?: Date }): void {
    this.pageVersions.push({
      id: randomUuid(),
      ...row,
      created_at: row.created_at ?? new Date(),
    });
  }

  /** `db.transaction` shim — runs the callback with `this` as the tx. */
  async transaction<T>(cb: (tx: FakeDb) => Promise<T>): Promise<T> {
    // Snapshot for rollback simulation.
    const pagesSnap = new Map(this.pages);
    const versionsSnap = [...this.pageVersions];
    try {
      return await cb(this);
    } catch (err) {
      this.pages = pagesSnap;
      this.pageVersions = versionsSnap;
      throw err;
    }
  }

  async execute<T = unknown>(sqlObj: unknown): Promise<ExecResult<T>> {
    const { text, params } = compileSql(sqlObj);
    const norm = text.toLowerCase().replace(/\s+/g, " ").trim();

    if (norm.startsWith("insert into pages")) {
      return this.handleInsertPage(params) as ExecResult<T>;
    }
    if (norm.startsWith("insert into page_versions")) {
      return this.handleInsertPageVersion(params) as ExecResult<T>;
    }
    if (norm.startsWith("select") && norm.includes("from page_versions")) {
      return this.handleSelectHistory(params) as ExecResult<T>;
    }
    if (norm.startsWith("select") && norm.includes("from pages")) {
      return this.handleSelectPages(norm, params) as ExecResult<T>;
    }
    if (norm.startsWith("update pages")) {
      return this.handleUpdatePage(params) as ExecResult<T>;
    }
    if (norm.startsWith("delete from pages")) {
      return this.handleDeletePage(params) as ExecResult<T>;
    }
    if (norm.startsWith("delete from page_versions")) {
      return this.handleDeletePageVersionsRotation(params) as ExecResult<T>;
    }
    throw new Error(`FakeDb: unhandled SQL: ${norm}`);
  }

  private handleInsertPage(params: unknown[]): ExecResult<PageRow> {
    // Param order: [pageIdOrNull, ciphertext, nonce, aadParamsJson, titleSearchToken, vaultId, ownerUserId]
    const [pageId, ciphertext, nonce, aadParamsJson, titleSearchToken, vaultId, ownerUserId] = params as [
      string | null,
      Uint8Array,
      Uint8Array,
      string,
      Uint8Array,
      string,
      string,
    ];
    const v = this.vaults.get(vaultId);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    const id = pageId ?? randomUuid();
    const now = new Date();
    const row: PageRow = {
      id,
      vault_id: vaultId,
      version: 1,
      ciphertext,
      nonce,
      aad_params_json: aadParamsJson,
      title_search_token: titleSearchToken,
      is_locked: false,
      created_at: now,
      updated_at: now,
    };
    this.pages.set(id, row);
    return { rows: [row], rowCount: 1 };
  }

  private handleInsertPageVersion(params: unknown[]): ExecResult<PageVersionRow> {
    // Param order: [pageId, version, ciphertext, nonce, aadParamsJson]
    const [pageId, version, ciphertext, nonce, aadParamsJson] = params as [
      string,
      number,
      Uint8Array,
      Uint8Array,
      string,
    ];
    const row: PageVersionRow = {
      id: randomUuid(),
      page_id: pageId,
      version,
      ciphertext,
      nonce,
      aad_params_json: aadParamsJson,
      created_at: new Date(),
    };
    this.pageVersions.push(row);
    return { rows: [row], rowCount: 1 };
  }

  private handleSelectHistory(params: unknown[]): ExecResult<PageVersionRow> {
    // Service emits: SELECT ... WHERE pv.page_id = $id AND EXISTS (... p.id = $id AND owner = $user)
    // → params: [pageId, pageId, ownerUserId]. Take first + last.
    const pageId = params[0] as string;
    const ownerUserId = params[params.length - 1] as string;
    const page = this.pages.get(pageId);
    if (!page) return { rows: [], rowCount: 0 };
    const v = this.vaults.get(page.vault_id);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    const rows = this.pageVersions
      .filter((r) => r.page_id === pageId)
      .sort((a, b) => b.version - a.version)
      .slice(0, 10);
    return { rows, rowCount: rows.length };
  }

  private handleSelectPages(norm: string, params: unknown[]): ExecResult<PageRow> {
    // Two shapes:
    //   - getById / post-failure ownership probe: [pageId, ownerUserId]
    //   - list (no q): [ownerUserId]
    //   - list with q (prefix): [prefixLow, prefixHigh, ownerUserId]
    if (norm.includes("title_search_token >=") || norm.includes("title_search_token<=") || norm.includes("title_search_token <")) {
      const [low, high, ownerUserId] = params as [Uint8Array, Uint8Array, string];
      const rows = [...this.pages.values()].filter((p) => {
        const v = this.vaults.get(p.vault_id);
        if (!v || v.owner_user_id !== ownerUserId) return false;
        return cmpBytes(p.title_search_token, low) >= 0 && cmpBytes(p.title_search_token, high) < 0;
      });
      return { rows, rowCount: rows.length };
    }
    if (params.length === 1) {
      const [ownerUserId] = params as [string];
      const rows = [...this.pages.values()].filter((p) => {
        const v = this.vaults.get(p.vault_id);
        return v && v.owner_user_id === ownerUserId;
      });
      return { rows, rowCount: rows.length };
    }
    const [pageId, ownerUserId] = params as [string, string];
    const row = this.pages.get(pageId);
    if (!row) return { rows: [], rowCount: 0 };
    const v = this.vaults.get(row.vault_id);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    return { rows: [row], rowCount: 1 };
  }

  private async handleUpdatePage(params: unknown[]): Promise<ExecResult<PageRow>> {
    // Param order: [ciphertext, nonce, aadParamsJson, titleSearchToken, pageId, casVersion]
    // (ownership is enforced by the prior SELECT FOR UPDATE in the same tx).
    const [ciphertext, nonce, aadParamsJson, titleSearchToken, pageId, casVersion] = params as [
      Uint8Array,
      Uint8Array,
      string,
      Uint8Array,
      string,
      number,
    ];
    const ownerUserId: string | undefined = undefined;

    const prev = this.rowLocks.get(pageId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.rowLocks.set(pageId, prev.then(() => next));
    await prev;
    try {
      await new Promise<void>((r) => { setTimeout(r, 0); });
      const row = this.pages.get(pageId);
      if (!row) return { rows: [], rowCount: 0 };
      if (ownerUserId !== undefined) {
        const v = this.vaults.get(row.vault_id);
        if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
      }
      if (row.version !== casVersion) return { rows: [], rowCount: 0 };
      const updated: PageRow = {
        ...row,
        ciphertext,
        nonce,
        aad_params_json: aadParamsJson,
        title_search_token: titleSearchToken,
        version: row.version + 1,
        updated_at: new Date(),
      };
      this.pages.set(pageId, updated);
      return { rows: [updated], rowCount: 1 };
    } finally {
      release();
    }
  }

  private handleDeletePage(params: unknown[]): ExecResult<{ id: string }> {
    const [pageId, ownerUserId] = params as [string, string];
    const row = this.pages.get(pageId);
    if (!row) return { rows: [], rowCount: 0 };
    const v = this.vaults.get(row.vault_id);
    if (!v || v.owner_user_id !== ownerUserId) return { rows: [], rowCount: 0 };
    this.pages.delete(pageId);
    this.pageVersions = this.pageVersions.filter((r) => r.page_id !== pageId);
    return { rows: [{ id: pageId }], rowCount: 1 };
  }

  private handleDeletePageVersionsRotation(params: unknown[]): ExecResult<{ id: string }> {
    if (this.rotationFailureMode) {
      throw new Error("simulated rotation failure");
    }
    // Param order: [pageId, pageId] — keep only the top 10 by version DESC.
    const [pageId] = params as [string];
    const forPage = this.pageVersions
      .filter((r) => r.page_id === pageId)
      .sort((a, b) => b.version - a.version);
    const keep = new Set(forPage.slice(0, 10).map((r) => r.id));
    const removed: { id: string }[] = [];
    this.pageVersions = this.pageVersions.filter((r) => {
      if (r.page_id !== pageId) return true;
      if (keep.has(r.id)) return true;
      removed.push({ id: r.id });
      return false;
    });
    return { rows: removed, rowCount: removed.length };
  }
}

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
    params.push(chunk);
    text.push("?");
  }
  return { text: text.join(""), params };
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai !== bi) return ai - bi;
  }
  return a.length - b.length;
}

function randomUuid(): string {
  return "00000000-0000-4000-8000-" + Math.random().toString(16).slice(2, 14).padEnd(12, "0");
}

// ---------------------------------------------------------------- harness

interface Kit {
  svc: PagesService;
  fake: FakeDb;
}

function makeKit(): Kit {
  const fake = new FakeDb();
  const dbSvc = { db: fake } as never;
  const svc = new PagesService(dbSvc);
  return { svc, fake };
}

function bytes(...vals: number[]): Uint8Array {
  return Uint8Array.from(vals);
}

function makeCreateDto(overrides: Partial<CreatePageDto> = {}): CreatePageDto {
  return {
    vaultId: VAULT_A,
    ciphertext: bytes(1, 2, 3),
    nonce: bytes(...new Array<number>(24).fill(7)),
    aadParamsJson: '{"v":1}',
    titleSearchToken: bytes(...new Array<number>(8).fill(0xab)),
    version: 1,
    ...overrides,
  };
}

function makeUpdateDto(version: number, overrides: Partial<UpdatePageDto> = {}): UpdatePageDto {
  return {
    ciphertext: bytes(9, 9, 9),
    nonce: bytes(...new Array<number>(24).fill(8)),
    aadParamsJson: '{"v":' + String(version + 1) + "}",
    titleSearchToken: bytes(...new Array<number>(8).fill(0xcd)),
    version,
    ...overrides,
  };
}

// ---------------------------------------------------------------- specs

describe("PagesService — CAS PATCH + history rotation + uniform-404 (Plan 05-02)", () => {
  let kit: Kit;
  beforeEach(() => {
    kit = makeKit();
  });

  it("(1) PATCH happy path: version 1→2, response shape", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(1),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: '{"v":1}',
      title_search_token: bytes(...new Array<number>(8).fill(1)),
    });
    const r = await kit.svc.update(USER_A, PAGE_A, makeUpdateDto(1));
    expect(r.id).toBe(PAGE_A);
    expect(r.version).toBe(2);
    expect(typeof r.updatedAt).toBe("string");
  });

  it("(2) PATCH stale version → 409 PAGE_VERSION_CONFLICT, DB unchanged", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 3,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    await expect(
      kit.svc.update(USER_A, PAGE_A, makeUpdateDto(1)),
    ).rejects.toMatchObject({
      response: { error: { code: "E2010" } },
      status: 409,
    });
    expect(kit.fake.pages.get(PAGE_A)?.version).toBe(3);
  });

  it("(3) PATCH inserts PRE-update snapshot into page_versions", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 5,
      ciphertext: bytes(0xaa, 0xbb),
      nonce: bytes(...new Array<number>(24).fill(0x11)),
      aad_params_json: '{"v":5}',
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    await kit.svc.update(USER_A, PAGE_A, makeUpdateDto(5));
    const hist = kit.fake.pageVersions.filter((r) => r.page_id === PAGE_A);
    expect(hist.length).toBe(1);
    expect(hist[0]!.version).toBe(5);
    expect(Array.from(hist[0]!.ciphertext)).toEqual([0xaa, 0xbb]);
    expect(hist[0]!.aad_params_json).toBe('{"v":5}');
  });

  it("(4) PATCH after 10 history entries — count stays at 10, surviving = current-9..current desc", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 11,
      ciphertext: bytes(11),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: '{"v":11}',
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    // Seed 10 history rows for versions 1..10.
    for (let v = 1; v <= 10; v++) {
      kit.fake.seedHistory({
        page_id: PAGE_A,
        version: v,
        ciphertext: bytes(v),
        nonce: bytes(...new Array<number>(24).fill(0)),
        aad_params_json: `{"v":${String(v)}}`,
      });
    }
    await kit.svc.update(USER_A, PAGE_A, makeUpdateDto(11));
    const hist = kit.fake.pageVersions
      .filter((r) => r.page_id === PAGE_A)
      .sort((a, b) => b.version - a.version);
    expect(hist.length).toBe(10);
    expect(hist.map((r) => r.version)).toEqual([11, 10, 9, 8, 7, 6, 5, 4, 3, 2]);
  });

  it("(5) PATCH atomic rollback: rotation failure → page version NOT incremented + no orphan history row", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 7,
      ciphertext: bytes(7),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: '{"v":7}',
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    kit.fake.rotationFailureMode = true;
    await expect(kit.svc.update(USER_A, PAGE_A, makeUpdateDto(7))).rejects.toThrow();
    // Page version unchanged.
    expect(kit.fake.pages.get(PAGE_A)?.version).toBe(7);
    // No orphan history row.
    expect(kit.fake.pageVersions.filter((r) => r.page_id === PAGE_A).length).toBe(0);
  });

  it("(6) cross-user PATCH → 404 PAGE_NOT_FOUND (NOT 403)", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    await expect(
      kit.svc.update(USER_B, PAGE_A, makeUpdateDto(1)),
    ).rejects.toMatchObject({
      response: { error: { code: "E2009" } },
      status: 404,
    });
  });

  it("(7) concurrent PATCH race — exactly one winner, other 409", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    const results = await Promise.allSettled([
      kit.svc.update(USER_A, PAGE_A, makeUpdateDto(1)),
      kit.svc.update(USER_A, PAGE_A, makeUpdateDto(1)),
    ]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    const winner = (fulfilled[0] as PromiseFulfilledResult<{ version: number }>).value;
    expect(winner.version).toBe(2);
    const err = (rejected[0] as PromiseRejectedResult).reason as HttpException;
    expect(err).toBeInstanceOf(HttpException);
    expect(err.getStatus()).toBe(409);
    const body = err.getResponse() as { error?: { code?: string } };
    expect(body.error?.code).toBe("E2010");
  });

  // ---------------- additional CRUD coverage (cheap given the simulator) ----------------

  it("create: cross-user vaultId → 404 PAGE_NOT_FOUND", async () => {
    await expect(
      kit.svc.create(USER_A, makeCreateDto({ vaultId: VAULT_B })),
    ).rejects.toMatchObject({
      response: { error: { code: "E2009" } },
      status: 404,
    });
  });

  it("getById: cross-user → 404 PAGE_NOT_FOUND", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    await expect(kit.svc.getById(USER_B, PAGE_A)).rejects.toMatchObject({
      response: { error: { code: "E2009" } },
      status: 404,
    });
  });

  it("delete: cross-user → 404 PAGE_NOT_FOUND, row preserved", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 1,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    await expect(kit.svc.delete(USER_B, PAGE_A)).rejects.toMatchObject({
      response: { error: { code: "E2009" } },
      status: 404,
    });
    expect(kit.fake.pages.has(PAGE_A)).toBe(true);
  });

  it("history: returns up to 10 entries, newest first; cross-user → empty", async () => {
    kit.fake.seedPage({
      id: PAGE_A,
      vault_id: VAULT_A,
      version: 3,
      ciphertext: bytes(0),
      nonce: bytes(...new Array<number>(24).fill(0)),
      aad_params_json: "{}",
      title_search_token: bytes(...new Array<number>(8).fill(0)),
    });
    for (let v = 1; v <= 3; v++) {
      kit.fake.seedHistory({
        page_id: PAGE_A,
        version: v,
        ciphertext: bytes(v),
        nonce: bytes(...new Array<number>(24).fill(0)),
        aad_params_json: `{"v":${String(v)}}`,
      });
    }
    const r = await kit.svc.history(USER_A, PAGE_A);
    expect(r.length).toBe(3);
    expect(r[0]!.version).toBe(3);
    expect(r[2]!.version).toBe(1);
    // Cross-user → 404.
    await expect(kit.svc.history(USER_B, PAGE_A)).rejects.toMatchObject({
      response: { error: { code: "E2009" } },
      status: 404,
    });
  });
});
