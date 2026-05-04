"use client";

import { useRouter, useSearchParams } from "next/navigation";
import type { JSX, SyntheticEvent } from "react";
import { Suspense, useEffect, useState } from "react";

import {
  AuthClientError,
  getAuthParams,
  login as apiLogin,
  type Argon2Params,
} from "../../lib/api/auth-client";
import { accessTokenStore } from "../../lib/auth/access-token-store";
import { keyStore } from "../../lib/auth/key-store";
import {
  buildLoginEnvelope,
  unlockSecrets,
} from "../../lib/crypto/login-derivations";
import {
  SecretKeyFormatError,
  crockfordToBytes,
} from "../../lib/crypto/secret-key-format";

/**
 * /login — single-step form (email + master password + secret_key).
 *
 * Flow (matches 02-08 SUMMARY contracts byte-for-byte):
 *  1. GET /auth/params -> { argon2Params, serverArgonSalt }    (cached for the page)
 *  2. Compute `argon2_secret_key_hash` = Argon2id(secret_key, serverArgonSalt, params)
 *  3. POST /auth/login { email, argon2SecretKeyHash } ->
 *      { accessToken, expiresIn, wrappedMasterDek, wrappedUserSigningSk,
 *        wrappedUserKxSk, userArgonSalt, argon2Params, ... }
 *  4. accessTokenStore.set(accessToken, expiresIn)              (memory only)
 *  5. unlockSecrets(...) -> master_KEK + master_DEK + signing_sk + kx_sk
 *      via byte-identical AAD labels matching signup
 *  6. keyStore.set(...) the unwrapped material; redirect to /me
 *
 * SECRET LIFECYCLE:
 *  - master_password lives in component state until the unlock completes,
 *    then is dropped (best-effort; JS can't reliably zero strings).
 *  - secret_key Uint8Array(16) is stashed in keyStore so future operations
 *    that need it (e.g. password change, recovery) can read it without a
 *    re-prompt; logout calls keyStore.wipe() to zero it.
 *  - Wrong creds: canonical "Invalid credentials"; no enumeration of which
 *    field was wrong.
 */

function LoginPageInner(): JSX.Element {
  const searchParams = useSearchParams();
  const router = useRouter();
  const justSignedUp = searchParams.get("signed_up") === "1";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKeyText, setSecretKeyText] = useState("");
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<
    "idle" | "params" | "deriving" | "submitting" | "unlocking" | "ok"
  >("idle");
  const [err, setErr] = useState<string | null>(null);

  // Cached server params for the page (one fetch per session).
  const [paramsCache, setParamsCache] = useState<{
    argon2Params: Argon2Params;
    serverArgonSalt: string;
  } | null>(null);

  // Pre-fetch params on mount to avoid a visible round-trip during submit.
  useEffect(() => {
    const flag = { cancelled: false };
    void (async (): Promise<void> => {
      try {
        const p = await getAuthParams();
        if (!flag.cancelled) {
          setParamsCache({
            argon2Params: p.argon2Params,
            serverArgonSalt: p.serverArgonSalt,
          });
        }
      } catch {
        // non-fatal — submit will retry the fetch
      }
    })();
    return () => {
      flag.cancelled = true;
    };
  }, []);

  async function onSubmit(e: SyntheticEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    if (busy) return;
    setErr(null);

    const trimmedEmail = email.trim().toLowerCase();
    if (trimmedEmail === "" || password === "" || secretKeyText.trim() === "") {
      setErr("All three fields are required.");
      return;
    }

    let secretKey: Uint8Array;
    try {
      secretKey = crockfordToBytes(secretKeyText);
    } catch (e2) {
      const msg = e2 instanceof SecretKeyFormatError ? e2.message : "Invalid secret key format.";
      setErr(msg);
      return;
    }

    setBusy(true);
    let derivedRefs: { masterKek?: Uint8Array; masterDek?: Uint8Array; signingSk?: Uint8Array; kxSk?: Uint8Array } = {};
    try {
      // Step 1: ensure params (use cache if available).
      setPhase("params");
      let cache = paramsCache;
      if (!cache) {
        const p = await getAuthParams();
        cache = { argon2Params: p.argon2Params, serverArgonSalt: p.serverArgonSalt };
        setParamsCache(cache);
      }

      // Step 2: build the verifier.
      setPhase("deriving");
      const envelope = await buildLoginEnvelope({
        email: trimmedEmail,
        secretKey,
        argon2Params: cache.argon2Params,
        serverArgonSaltB64: cache.serverArgonSalt,
      });

      // Step 3: POST /auth/login.
      setPhase("submitting");
      const loginRes = await apiLogin({
        email: envelope.email,
        argon2SecretKeyHash: envelope.argon2SecretKeyHash,
      });

      // Phase 03 Plan 08 — `/auth/login` may now return a 2FA-required
      // branch (Truth 8). Detect via the `kind` discriminator the server
      // sets only on the step-up shape; legacy 1FA-only callers see no
      // `kind` field (regression-free).
      //
      // Plan 10 ships the `/login/2fa` page that consumes the step-up
      // token + `twoFa` flags. Until Plan 10 lands, redirecting to that
      // route is a 404 — acceptable for the inter-wave window since no
      // test users have 2FA enrolled in any deployed environment yet.
      // TS narrowing: `"kind" in loginRes` alone widens to `unknown` on the
      // discriminator-bearing branch. Cast through `as { kind?: string }`
      // and re-check; once we've taken the early-return, the rest of the
      // function continues with the session-shape narrowing.
      const stepUpKind = (loginRes as { kind?: unknown }).kind;
      if (stepUpKind === "2fa-required") {
        const stepUp = loginRes as Extract<typeof loginRes, { kind: "2fa-required" }>;
        // Stash the step-up token + flags via sessionStorage so the
        // /login/2fa page can pick them up after the navigation. The
        // step-up token is short-lived (default 120s) and authorises
        // only /2fa/*.
        try {
          sessionStorage.setItem(
            "sv:step-up",
            JSON.stringify({
              token: stepUp.stepUpToken,
              twoFa: stepUp.twoFa,
            }),
          );
        } catch {
          // sessionStorage may be disabled; /login/2fa handles the
          // missing-handoff case by redirecting back to /login.
        }
        // Plan 10: KEEP password + secret_key + email in the in-memory
        // keyStore so /login/2fa can derive master_KEK to decrypt the
        // wrapped TOTP secret (the 2FA-required login response carries
        // no wrapped material — that comes from /2fa/step-up-material
        // gated by the step-up token). Soft router.push (NOT
        // window.location.assign) preserves the JS realm; the keyStore
        // singleton survives the navigation.
        keyStore.set("step_up_email", trimmedEmail);
        keyStore.set("step_up_password", password);
        keyStore.set("step_up_secret_key", secretKey);
        // Don't wipe accessTokenStore — there's nothing in it yet on
        // the 2FA-required branch (server didn't issue an access token).
        setPhase("ok");
        router.push("/login/2fa");
        return;
      }

      // ---- 1FA-only branch — Phase-02 unchanged ----
      // After the early-return above, `loginRes` is necessarily the session
      // shape (no `kind` discriminator); narrow explicitly so TS sees it.
      const sessionRes = loginRes as Exclude<typeof loginRes, { kind: "2fa-required" }>;
      // Step 4: stash access token in memory only.
      accessTokenStore.set(sessionRes.accessToken, sessionRes.expiresIn);

      // Step 5: unwrap the wrapped key material.
      setPhase("unlocking");
      const unlocked = await unlockSecrets({
        email: trimmedEmail,
        password,
        secretKey,
        argon2Params: sessionRes.argon2Params,
        userArgonSaltB64: sessionRes.userArgonSalt,
        wrappedMasterDekB64: sessionRes.wrappedMasterDek,
        wrappedUserSigningSkB64: sessionRes.wrappedUserSigningSk,
        wrappedUserKxSkB64: sessionRes.wrappedUserKxSk,
      });
      derivedRefs = unlocked;

      // Step 6: stash in the in-memory keyStore. Phase 04+ vault items
      // will pull master_DEK from here.
      keyStore.set("secret_key", secretKey);
      keyStore.set("master_kek", unlocked.masterKek);
      keyStore.set("master_dek", unlocked.masterDek);
      keyStore.set("signing_sk", unlocked.signingSk);
      keyStore.set("kx_sk", unlocked.kxSk);
      // master_password intentionally NOT stored — only secret_key + derived
      // material. The user's typed password is dropped here (string GC).

      setPhase("ok");
      // Hard navigate: full page reload tears down React state including
      // the typed password from the form's closures.
      window.location.assign("/me");
    } catch (e2) {
      // Wipe ANY partially-derived keys from memory before re-renders.
      try {
        if (derivedRefs.masterKek) derivedRefs.masterKek.fill(0);
        if (derivedRefs.masterDek) derivedRefs.masterDek.fill(0);
        if (derivedRefs.signingSk) derivedRefs.signingSk.fill(0);
        if (derivedRefs.kxSk) derivedRefs.kxSk.fill(0);
        secretKey.fill(0);
      } catch {
        // ignore
      }
      accessTokenStore.wipe();
      keyStore.wipe();

      if (e2 instanceof AuthClientError) {
        if (e2.code === "AUTH_INVALID_CREDENTIALS" || e2.code === "E1001" || e2.status === 401) {
          setErr("Invalid credentials.");
        } else if (e2.code === "E1007" || e2.status === 429) {
          setErr("Too many login attempts. Please try again later.");
        } else {
          setErr(e2.message);
        }
      } else if (
        e2 instanceof Error &&
        // libsodium throws a generic Error on AEAD tag mismatch; treat as bad creds
        /verification failed|wrong secret key|tag/i.test(e2.message)
      ) {
        setErr("Invalid credentials.");
      } else {
        setErr("Network or unexpected error. Please try again.");
      }
      setPhase("idle");
      setBusy(false);
    }
  }

  const phaseMsg: Record<typeof phase, string> = {
    idle: "",
    params: "Fetching server parameters…",
    deriving: "Deriving login key (Argon2id)…",
    submitting: "Signing in…",
    unlocking: "Unlocking your vault…",
    ok: "Signed in. Redirecting…",
  };

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-10">
      <div className="w-full max-w-md space-y-6">
        <header className="space-y-2 text-center">
          <h1 className="text-3xl font-semibold tracking-tight">Sign in to SimpleVault</h1>
          {justSignedUp && (
            <p className="text-sm text-emerald-300">
              Account created. Sign in with your master password and secret key.
            </p>
          )}
        </header>

        <form onSubmit={(e) => { void onSubmit(e); }} className="space-y-4" autoComplete="off">
          <div className="space-y-1">
            <label htmlFor="email" className="block text-sm font-medium">Email</label>
            <input
              id="email"
              type="email"
              inputMode="email"
              autoComplete="username"
              value={email}
              onChange={(ev) => { setEmail(ev.target.value); }}
              disabled={busy}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="password" className="block text-sm font-medium">Master password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(ev) => { setPassword(ev.target.value); }}
              disabled={busy}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="secret-key" className="block text-sm font-medium">Secret key</label>
            <input
              id="secret-key"
              type="text"
              spellCheck={false}
              autoComplete="off"
              value={secretKeyText}
              onChange={(ev) => { setSecretKeyText(ev.target.value); }}
              disabled={busy}
              placeholder="K3JM-9PXQ-7T4N-22HS-VR8E-A6YF"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono"
            />
            <p className="text-xs text-zinc-500">
              The 26-character key shown once during signup.
            </p>
          </div>

          {err && (
            <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {err}
            </p>
          )}

          {busy && phaseMsg[phase] !== "" && (
            <p className="text-xs text-zinc-400">{phaseMsg[phase]}</p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium hover:bg-emerald-500 disabled:opacity-40"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </main>
  );
}

export default function LoginPage(): JSX.Element {
  // Suspense boundary required by Next.js App Router for `useSearchParams`.
  return (
    <Suspense fallback={<main className="flex min-h-screen items-center justify-center"><p className="text-zinc-400">Loading…</p></main>}>
      <LoginPageInner />
    </Suspense>
  );
}
