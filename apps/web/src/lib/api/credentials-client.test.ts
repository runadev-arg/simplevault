import sodium from "libsodium-wrappers-sumo";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthClientError } from "./auth-client";
import {
  createCredential,
  deleteCredential,
  getCredential,
  listVaultPersonal,
  updateCredential,
} from "./credentials-client";
import {
  ApiError,
  CredentialBodyTooLargeError,
  CredentialNotFoundError,
  VersionConflictError,
} from "./errors";

/**
 * Phase 04 / Plan 06 — credentials-client unit spec.
 *
 * Mocks `globalThis.fetch` directly (no MSW dep — the project's vitest
 * setup is intentionally minimal). Asserts:
 *   1. happy paths invoke the right URL + method
 *   2. base64url decode boundary on `getCredential`
 *   3. 404 → CredentialNotFoundError
 *   4. 409 → VersionConflictError carrying credentialId
 *   5. 413 → CredentialBodyTooLargeError
 *   6. ApiError alias points at AuthClientError (instanceof discriminator)
 */

const ACCESS = "test-access-token";
const ID = "11111111-1111-4111-8111-111111111111";
const VAULT_ID = "22222222-2222-4222-8222-222222222222";

beforeAll(async () => {
  await sodium.ready;
});

interface MockResponseOpts {
  status?: number;
  json?: unknown;
  headers?: Record<string, string>;
}

function mockFetchOnce(opts: MockResponseOpts = {}): ReturnType<typeof vi.fn> {
  const status = opts.status ?? 200;
  const body = opts.json ?? {};
  const fakeRes = {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k: string): string | null => opts.headers?.[k.toLowerCase()] ?? null },
    json: (): Promise<unknown> => Promise.resolve(body),
  };
  const fn = vi.fn().mockResolvedValueOnce(fakeRes);
  globalThis.fetch = fn as unknown as typeof globalThis.fetch;
  return fn;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("listVaultPersonal", () => {
  it("happy path: parses and returns the personal vault summary", async () => {
    const fetchMock = mockFetchOnce({
      status: 200,
      json: {
        vaultId: VAULT_ID,
        credentialIds: [
          { id: ID, version: 3, updatedAt: "2026-05-04T00:00:00.000Z" },
        ],
      },
    });
    const r = await listVaultPersonal(ACCESS);
    expect(r.vaultId).toBe(VAULT_ID);
    expect(r.credentialIds).toHaveLength(1);
    expect(r.credentialIds[0]?.version).toBe(3);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith("/vault/personal")).toBe(true);
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${ACCESS}`);
  });
});

describe("getCredential", () => {
  it("decodes base64url ciphertext + nonce back to Uint8Array", async () => {
    const ct = new Uint8Array([1, 2, 3, 4, 5]);
    const nc = new Uint8Array(24).fill(7);
    mockFetchOnce({
      status: 200,
      json: {
        id: ID,
        vaultId: VAULT_ID,
        version: 1,
        ciphertext: sodium.to_base64(ct, sodium.base64_variants.URLSAFE_NO_PADDING),
        nonce: sodium.to_base64(nc, sodium.base64_variants.URLSAFE_NO_PADDING),
        aadParamsJson: '{"v":1}',
        updatedAt: "2026-05-04T00:00:00.000Z",
      },
    });
    const r = await getCredential(ACCESS, ID);
    expect(r.ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(r.ciphertext)).toEqual([1, 2, 3, 4, 5]);
    expect(r.nonce.length).toBe(24);
    expect(r.aadParamsJson).toBe('{"v":1}');
  });

  it("404 → CredentialNotFoundError", async () => {
    mockFetchOnce({
      status: 404,
      json: { error: { code: "CREDENTIAL_NOT_FOUND", message: "Credential not found" } },
    });
    await expect(getCredential(ACCESS, ID)).rejects.toBeInstanceOf(CredentialNotFoundError);
  });
});

describe("createCredential", () => {
  it("encodes ciphertext + nonce as base64url on the wire and returns the summary", async () => {
    const ct = new Uint8Array([9, 9, 9]);
    const nc = new Uint8Array(24).fill(8);
    const fetchMock = mockFetchOnce({
      status: 201,
      json: { id: ID, vaultId: VAULT_ID, version: 1, updatedAt: "2026-05-04T00:00:00.000Z" },
    });
    const r = await createCredential(ACCESS, {
      vaultId: VAULT_ID,
      ciphertext: ct,
      nonce: nc,
      aadParamsJson: '{"v":1}',
    });
    expect(r.id).toBe(ID);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(sent.ciphertext).toBe(sodium.to_base64(ct, sodium.base64_variants.URLSAFE_NO_PADDING));
    expect(sent.nonce).toBe(sodium.to_base64(nc, sodium.base64_variants.URLSAFE_NO_PADDING));
    expect(sent.version).toBe(1);
  });

  it("413 → CredentialBodyTooLargeError", async () => {
    mockFetchOnce({
      status: 413,
      json: { error: { code: "CREDENTIAL_BODY_TOO_LARGE", message: "too big" } },
    });
    await expect(
      createCredential(ACCESS, {
        vaultId: VAULT_ID,
        ciphertext: new Uint8Array([1]),
        nonce: new Uint8Array(24),
        aadParamsJson: "{}",
      }),
    ).rejects.toBeInstanceOf(CredentialBodyTooLargeError);
  });
});

describe("updateCredential", () => {
  it("happy path: PATCHes /credentials/:id with version witness", async () => {
    const fetchMock = mockFetchOnce({
      status: 200,
      json: { id: ID, vaultId: VAULT_ID, version: 4, updatedAt: "2026-05-04T00:00:00.000Z" },
    });
    const r = await updateCredential(ACCESS, ID, {
      ciphertext: new Uint8Array([1]),
      nonce: new Uint8Array(24),
      aadParamsJson: "{}",
      version: 3,
    });
    expect(r.version).toBe(4);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith(`/credentials/${ID}`)).toBe(true);
    expect(init.method).toBe("PATCH");
    const sent = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(sent.version).toBe(3);
  });

  it("409 → VersionConflictError carrying credentialId", async () => {
    mockFetchOnce({
      status: 409,
      json: { error: { code: "CREDENTIAL_VERSION_CONFLICT", message: "Stale version" } },
    });
    let caught: unknown;
    try {
      await updateCredential(ACCESS, ID, {
        ciphertext: new Uint8Array([1]),
        nonce: new Uint8Array(24),
        aadParamsJson: "{}",
        version: 2,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VersionConflictError);
    expect((caught as VersionConflictError).credentialId).toBe(ID);
    expect(caught).toBeInstanceOf(ApiError);
    // Backwards-compat: still an AuthClientError so existing Phase-02 catchers
    // continue to match.
    expect(caught).toBeInstanceOf(AuthClientError);
  });
});

describe("deleteCredential", () => {
  it("happy path: 204 → resolves void", async () => {
    const fetchMock = mockFetchOnce({ status: 204, json: null });
    await expect(deleteCredential(ACCESS, ID)).resolves.toBeUndefined();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("DELETE");
  });

  it("404 → CredentialNotFoundError", async () => {
    mockFetchOnce({
      status: 404,
      json: { error: { code: "CREDENTIAL_NOT_FOUND", message: "Credential not found" } },
    });
    await expect(deleteCredential(ACCESS, ID)).rejects.toBeInstanceOf(CredentialNotFoundError);
  });
});
