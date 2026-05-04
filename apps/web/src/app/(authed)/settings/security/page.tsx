"use client";

import type { JSX } from "react";
import { useState } from "react";

import { EnrollPasskeyButton } from "./enroll-passkey-button";
import { MethodList } from "./method-list";

/**
 * Phase 03 Plan 10 — `/settings/security` route.
 *
 * Lists active 2FA methods (Truth 9) and offers two enrolment surfaces:
 *   - Add passkey       — PRIMARY CTA (phishing-resistant; INDEX Key Link 12)
 *   - Add authenticator app — SECONDARY, with phishing-warning copy
 *     mandated by THREAT-MODEL §17 (auditor will check exact copy + ordering)
 *
 * The two enrolment buttons are wired in T2 (passkey) + T3 (TOTP). T1 lands
 * the skeleton + the method list + the UX copy that's part of the security
 * control. Refresh callback is passed down so a successful enrolment
 * triggers a list re-fetch without a full page reload.
 */
export default function SecuritySettingsPage(): JSX.Element {
  // `refreshKey` increments to force MethodList to re-fetch after an
  // enrolment completes. T2/T3 wire their success handlers to this.
  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = (): void => {
    setRefreshKey((k) => k + 1);
  };
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col gap-6 px-6 py-10">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          Two-factor authentication
        </h1>
        <p className="mt-2 text-sm text-zinc-400">
          Add a second factor to require more than your master password and
          secret key when signing in.
        </p>
      </header>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium uppercase tracking-wide text-zinc-500">
          Methods
        </h2>
        <MethodList key={refreshKey} />
      </section>

      <section className="flex flex-col gap-3 rounded-md border border-emerald-500/40 bg-emerald-500/5 p-5">
        <div className="flex items-center gap-2">
          <h3 className="text-base font-semibold text-emerald-100">
            Add passkey
          </h3>
          <span className="rounded bg-emerald-500/30 px-2 py-0.5 text-xs font-medium text-emerald-100">
            Recommended — phishing-resistant
          </span>
        </div>
        <p className="text-sm text-zinc-300">
          Passkeys use this device's biometric or PIN. Sites that don't match
          your real account can't trick a passkey into authenticating —
          unlike codes you type.
        </p>
        <EnrollPasskeyButton onEnrolled={refresh} />
      </section>

      <section className="flex flex-col gap-3 rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
        <h3 className="text-base font-semibold text-zinc-100">
          Add authenticator app
        </h3>
        <div
          role="note"
          className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100"
        >
          Authenticator-app codes can be entered into a phishing site. Use a
          passkey when possible — passkeys cryptographically refuse to log
          in to a fake site.
        </div>
        <p className="text-sm text-zinc-300">
          Compatible with Google Authenticator, 1Password, Authy, and any
          other TOTP / RFC 6238 app.
        </p>
        <p className="text-sm italic text-zinc-500">
          Enrolment flow is wired in the next commit (Plan 03-10 T3).
        </p>
      </section>
    </main>
  );
}
