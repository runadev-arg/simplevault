import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from "@nestjs/common";
import { schema } from "@simplevault/db";
import { eq } from "drizzle-orm";

import { Public } from "../auth/jwt/public.decorator.js";
import { DbService } from "../db/db.service.js";
import { MethodsService, userHasSharedVaultDependency } from "../twofa/methods/methods.service.js";

/**
 * Phase 03 Plan 12 — test-only routes used by the Cypress E2E suite.
 *
 * **EXISTS ONLY IN BUILDS WHERE `process.env.EXPOSE_TEST_ROUTES === "1"`.**
 * Production builds MUST leave the env var unset → `TestHelpersModule` is
 * never imported by `AppModule` and the routes here are absent from the
 * router. The runbook (`docs/operator/RUNBOOK.md`) carries grep + Dokploy
 * panel verification steps the operator runs before every deploy.
 *
 * Each route is a narrow seam the existing API doesn't expose because it
 * would be a bypass in production. They exist solely so the e2e tests can
 * exercise paths that real users never hit (forced counter regression,
 * shared-vault dep stub flip, etc.).
 *
 * `@Public()` — opt out of the global JwtAuthGuard. The seams are guarded
 * only by the `EXPOSE_TEST_ROUTES` build-flag, which is the production
 * safety. Adding JWT auth here would just complicate the test setup
 * without changing the security envelope (the routes are absent in prod).
 */
@Controller("test-helpers")
@Public()
export class TestHelpersController {
  constructor(
    private readonly methods: MethodsService,
    private readonly db: DbService,
  ) {}

  /**
   * Flip `MethodsService.sharedVaultDependencyCheck` between the default
   * `() => false` stub and a test-only `() => true` stub, simulating the
   * Phase-07 shared-vault dependency. The 2FA-removal Cypress spec uses
   * this to assert the 409 `AUTH_2FA_REMOVAL_BLOCKED` UI surface.
   *
   * Pass `{value: true}` to enable the dep, `{value: false}` to restore
   * the default stub.
   */
  @Post("flip-shared-vault-stub")
  @HttpCode(HttpStatus.NO_CONTENT)
  async flipSharedVaultStub(@Body() body: unknown): Promise<void> {
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { value?: unknown }).value !== "boolean"
    ) {
      throw new BadRequestException({
        error: { code: "E5001", message: "Body must be {value: boolean}" },
      });
    }
    const value = (body as { value: boolean }).value;
    this.methods.sharedVaultDependencyCheck = value
      ? async (): Promise<boolean> => true
      : userHasSharedVaultDependency;
  }

  /**
   * Seed a placeholder `totp_credentials` row for a given user. The 2FA-
   * removal Cypress spec uses this to put the user into the "≥1 active
   * 2FA method" state without going through the browser-side wrap
   * ceremony (which requires a virtual authenticator + libsodium WASM).
   *
   * The wrappedSecret + encryptedSecretAad are placeholder bytes — the
   * server never decrypts them; the listing + removal flows only read the
   * id + name + createdAt + lastUsedAt fields. Spec MUST NOT then attempt
   * to actually authenticate with this seeded credential — verify would
   * fail because the wrap can't be unwrapped.
   *
   * Returns the new credential's id so the spec can target it.
   */
  @Post("seed-totp-credential")
  @HttpCode(HttpStatus.OK)
  async seedTotpCredential(@Body() body: unknown): Promise<{ id: string }> {
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { email?: unknown }).email !== "string" ||
      typeof (body as { name?: unknown }).name !== "string"
    ) {
      throw new BadRequestException({
        error: { code: "E5001", message: "Body must be {email: string, name: string}" },
      });
    }
    const { email, name } = body as { email: string; name: string };
    const userRows = await this.db.db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1);
    const user = userRows[0];
    if (!user) {
      throw new BadRequestException({
        error: { code: "E5001", message: `No user with email ${email}` },
      });
    }
    // Placeholder bytes — server doesn't decrypt; listing + removal only
    // touch id/name/createdAt/lastUsedAt.
    const placeholderWrapped = Buffer.alloc(60); // 24-byte nonce + 36-byte ct+tag
    const placeholderAad = Buffer.alloc(61); // 1 + 12 + 16 + 32 (encodeAad shape)
    const inserted = await this.db.db
      .insert(schema.totpCredentials)
      .values({
        userId: user.id,
        wrappedSecret: placeholderWrapped,
        encryptedSecretAad: placeholderAad,
        name,
        lastUsedStep: 0,
      })
      .returning({ id: schema.totpCredentials.id });
    const row = inserted[0];
    if (!row) {
      throw new BadRequestException({
        error: { code: "E5001", message: "Insert returned no rows" },
      });
    }
    return { id: row.id };
  }

  /**
   * Force-set a webauthn credential's counter to a target value. The 2FA-
   * webauthn sad-path spec uses this to wind the counter past the
   * authenticator's actual counter so the next ceremony's
   * `assertion.counter > stored.counter` check fails (clone detection /
   * regression rejection — Plan 03-02 Truth 4).
   */
  @Post("mutate-webauthn-counter")
  @HttpCode(HttpStatus.NO_CONTENT)
  async mutateWebauthnCounter(@Body() body: unknown): Promise<void> {
    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { credentialId?: unknown }).credentialId !== "string" ||
      typeof (body as { counter?: unknown }).counter !== "number"
    ) {
      throw new BadRequestException({
        error: {
          code: "E5001",
          message: "Body must be {credentialId: uuid, counter: number}",
        },
      });
    }
    const { credentialId, counter } = body as {
      credentialId: string;
      counter: number;
    };
    await this.db.db
      .update(schema.webauthnCredentials)
      .set({ counter })
      .where(eq(schema.webauthnCredentials.id, credentialId));
  }
}
