import {
  ready,
  computeTotpStep,
  totpReady,
} from "@simplevault/crypto/browser";
import { startAuthentication } from "@simplewebauthn/browser";
import sodium from "libsodium-wrappers-sumo";

import {
  beginWebauthnAuth,
  finishWebauthnAuth,
  getStepUpMaterial,
  verifyTotp,
  type WebauthnFinishAuthResponse,
} from "../api/twofa-client";
import { AAD_LABEL_MASTER } from "../crypto/aad-labels";
import { unlockSecrets } from "../crypto/login-derivations";
import { unwrapTotpSecret } from "../crypto/totp-wrap";

import { keyStore } from "./key-store";

/**
 * Phase 03 Plan 10 T3 — drives the step-up ceremony given a step-up token.
 *
 * Two flavours, both end in a fully-authenticated session response from
 * the server (Phase-02 LoginSessionResponseSchema shape):
 *
 *   - `completeWithPasskey(stepUpToken)` — fires the WebAuthn assertion
 *     ceremony. No master_DEK required: the server validates the
 *     credential signature server-side (counter + RP-ID + origin).
 *
 *   - `completeWithTotp(stepUpToken, code)` — needs master_DEK to
 *     decrypt the wrapped TOTP secret. master_DEK is derived from
 *     keyStore-preserved password + secret_key + the unwrap material
 *     fetched via `GET /2fa/step-up-material`. The user's typed code is
 *     compared against the locally-computed RFC 6238 expected value
 *     across a ±1-step drift window before the candidate step is posted
 *     to /2fa/totp/verify.
 *
 * Caller owns the post-success handoff: after either function returns,
 * write the access token to `accessTokenStore`, run `unlockSecrets()` to
 * populate keyStore with master_KEK / master_DEK / signing_sk / kx_sk
 * (the same `unlockSecrets` that the 1FA-only login path runs), then
 * redirect to /me.
 */

export type StepUpResult = WebauthnFinishAuthResponse;

export async function completeWithPasskey(
  stepUpToken: string,
): Promise<StepUpResult> {
  const optionsJSON = (await beginWebauthnAuth(stepUpToken)) as Parameters<
    typeof startAuthentication
  >[0]["optionsJSON"];
  const assertion = await startAuthentication({ optionsJSON });
  return finishWebauthnAuth(stepUpToken, assertion);
}

/**
 * Returns the step-up material once derived. Useful for callers that want
 * to surface a clear "no TOTP credentials enrolled" error before walking
 * the user through the code-entry UI.
 */
export type StepUpMaterialDerived = Awaited<ReturnType<typeof getStepUpMaterial>>;

export async function loadStepUpMaterial(
  stepUpToken: string,
): Promise<StepUpMaterialDerived> {
  return getStepUpMaterial(stepUpToken);
}

/**
 * Decrypt every TOTP credential in the supplied step-up material; for the
 * code the user typed, find the credential whose decrypted secret matches
 * (±1 step). Returns `{credentialId, candidateStep}` ready to be posted to
 * `/2fa/totp/verify`.
 *
 * `password` + `secretKey` + `email` come from keyStore, preserved across
 * the soft `/login` → `/login/2fa` navigation.
 */
export async function findTotpMatch(
  material: StepUpMaterialDerived,
  email: string,
  password: string,
  secretKey: Uint8Array,
  code: string,
): Promise<{ credentialId: string; candidateStep: number; masterDek: Uint8Array }> {
  if (material.totpCredentials.length === 0) {
    throw new Error("No authenticator app enrolled.");
  }
  if (!/^\d{6}$/.test(code.trim())) {
    throw new Error("Enter the 6-digit code from your authenticator app.");
  }

  await ready();
  await totpReady();

  // Re-derive master_KEK + unwrap master_DEK from the unwrap material.
  // Same code path as a 1FA-only login (`unlockSecrets`) — minus the
  // signing/kx unwraps which we don't need at step-up time. To keep
  // server response shapes identical we just feed it dummies for those
  // fields and call the existing helper. Cheaper alternative: factor out
  // the master-only unwrap. Punted — this path runs once per login.
  // We use a 4-byte dummy ciphertext + nonce; if signing/kx unwrap fails
  // it would throw — but we're only using `masterDek` from the result.
  // Safer: inline the master-only derivation here.
  const userArgonSalt = sodium.from_base64(
    material.userArgonSalt,
    sodium.base64_variants.ORIGINAL,
  );
  const { deriveMasterKek, unwrapKey, encodeAad } = await import(
    "@simplevault/crypto/browser"
  );
  const masterKek = await deriveMasterKek({
    password,
    secretKey,
    email,
    userArgonSalt,
    argon2Params: material.argon2Params,
  });
  const enc = new TextEncoder();
  const emailHash = sodium.crypto_hash_sha256(
    enc.encode(email.toLowerCase()),
  );
  const masterLabelBytes = enc.encode(AAD_LABEL_MASTER);
  const masterAadCtx = new Uint8Array(masterLabelBytes.length + emailHash.length);
  masterAadCtx.set(masterLabelBytes, 0);
  masterAadCtx.set(emailHash, masterLabelBytes.length);
  const masterAad = encodeAad(material.argon2Params, masterAadCtx);
  const wrappedMasterDek = sodium.from_base64(
    material.wrappedMasterDek,
    sodium.base64_variants.ORIGINAL,
  );
  if (wrappedMasterDek.length < 24 + 16) {
    throw new Error("Wrapped master DEK is too short.");
  }
  const masterDek = await unwrapKey(
    {
      nonce: wrappedMasterDek.slice(0, 24),
      ciphertext: wrappedMasterDek.slice(24),
    },
    masterKek,
    masterAad,
  );

  const trimmed = code.trim();
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  const drift = 1;

  for (const cred of material.totpCredentials) {
    let secret: Uint8Array | null = null;
    try {
      secret = await unwrapTotpSecret(
        cred.wrappedSecret,
        cred.encryptedSecretAad,
        masterDek,
      );
      // Walk the drift window and compare; matches `verifyTotpCandidate`'s
      // semantics but lets us return both the credentialId AND the
      // matching step.
      for (let d = -drift; d <= drift; d++) {
        if (computeTotpStep(secret, currentStep + d) === trimmed) {
          return {
            credentialId: cred.id,
            candidateStep: currentStep + d,
            masterDek,
          };
        }
      }
    } catch {
      // Tag mismatch → wrong wrap key; try next credential. This path is
      // not expected: master_DEK is the same for every TOTP credential
      // for this user. A failure here means data corruption or a stale
      // credential.
    } finally {
      if (secret) secret.fill(0);
    }
  }

  // Best-effort wipe — caller will also wipe via keyStore on a hard nav.
  masterKek.fill(0);
  // masterDek will be re-derived by completeWithTotp's caller via
  // unlockSecrets() after the verify response lands; wipe ours here.
  masterDek.fill(0);
  throw new Error("That code didn't match. Try again with the most recent one.");
}

export async function completeWithTotp(
  stepUpToken: string,
  credentialId: string,
  candidateStep: number,
): Promise<StepUpResult> {
  return verifyTotp(stepUpToken, { credentialId, candidateStep });
}

/**
 * After a successful step-up, finalise the session in the same way the
 * 1FA-only login path does: store the access token, derive master_KEK +
 * master_DEK + signing_sk + kx_sk via `unlockSecrets`, write them to
 * keyStore, and wipe the input password (best-effort — JS strings).
 *
 * The session response shape is byte-identical to LoginSessionResponse.
 * Caller is responsible for redirecting after this resolves.
 */
export async function applyStepUpSession(
  result: StepUpResult,
  email: string,
  password: string,
  secretKey: Uint8Array,
): Promise<void> {
  const unlocked = await unlockSecrets({
    email,
    password,
    secretKey,
    argon2Params: result.argon2Params,
    userArgonSaltB64: result.userArgonSalt,
    wrappedMasterDekB64: result.wrappedMasterDek,
    wrappedUserSigningSkB64: result.wrappedUserSigningSk,
    wrappedUserKxSkB64: result.wrappedUserKxSk,
  });
  keyStore.set("secret_key", secretKey);
  keyStore.set("master_kek", unlocked.masterKek);
  keyStore.set("master_dek", unlocked.masterDek);
  keyStore.set("signing_sk", unlocked.signingSk);
  keyStore.set("kx_sk", unlocked.kxSk);
}
