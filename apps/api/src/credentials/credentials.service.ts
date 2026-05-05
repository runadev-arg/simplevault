import { Injectable } from "@nestjs/common";

import { DbService } from "../db/db.service.js";

/**
 * Phase 04 / Plan 02 — credentials CRUD service.
 *
 * RED stub (T1): every method throws "not impl". GREEN (T2) replaces with
 * the atomic CAS UPDATE + ownership-join SELECT documented in 04-02-PLAN.md.
 *
 * Public-method shape is the contract the controller (T3) targets — input
 * = the validated DTO; output = the response shape; errors = HttpException
 * with the canonical envelope (`CREDENTIAL_NOT_FOUND` / `CREDENTIAL_VERSION_CONFLICT`).
 */
export interface CreateCredentialDto {
  vaultId: string;
  /** Optional client-supplied uuid (Plan 04-10 cross-dep — keeps AAD self-consistent on POST). */
  credentialId?: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  version: 1;
}

export interface UpdateCredentialDto {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  /** CAS-witness: caller's known-current version. Server bumps to `version + 1` on success. */
  version: number;
}

export interface CredentialResponse {
  id: string;
  vaultId: string;
  version: number;
  /** Optional — included on GET; omitted on POST/PATCH metadata-only responses. */
  ciphertext?: Uint8Array;
  nonce?: Uint8Array;
  aadParamsJson?: string;
  /** ISO 8601 string. */
  updatedAt: string;
}

@Injectable()
export class CredentialsService {
  constructor(private readonly dbSvc: DbService) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async create(_userId: string, _dto: CreateCredentialDto): Promise<CredentialResponse> {
    throw new Error("not impl");
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async getById(_userId: string, _id: string): Promise<CredentialResponse> {
    throw new Error("not impl");
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async update(
    _userId: string,
    _id: string,
    _dto: UpdateCredentialDto,
  ): Promise<CredentialResponse> {
    throw new Error("not impl");
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async delete(_userId: string, _id: string): Promise<void> {
    throw new Error("not impl");
  }
}
