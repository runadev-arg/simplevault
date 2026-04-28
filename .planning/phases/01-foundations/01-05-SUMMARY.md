# Plan 01-05 — apps/web Next.js + security middleware (SUMMARY)

**Status:** COMPLETE
**Date:** 2026-04-28
**Commits:**
- `feat(01-05-T1): nextjs 15 scaffold + tailwind dark mode`
- `feat(01-05-T2): security headers middleware with per-request CSP nonce`
- `feat(01-05-T3): placeholder home page + global layout`

## What shipped

`apps/web` is a Next.js 15.1.0 + React 19.0.0 App Router workspace with:

- **Standalone build output** (`output: "standalone"` in `next.config.mjs`) so the Phase 06 Dockerfile can ship a small production image.
- **Strict CSP middleware** (`src/middleware.ts`) emitting per-request 16-byte base64 nonce on every page (200 + 404), `'strict-dynamic'` script-src, no `unsafe-inline`, no `unsafe-eval`. CSP plus HSTS preload, X-Frame-Options DENY, Referrer-Policy no-referrer, Permissions-Policy locking down geolocation/mic/camera/payment/usb/FLoC, COOP same-origin, CORP same-origin, X-Content-Type-Options nosniff, X-DNS-Prefetch-Control off.
- **Dark-mode-default placeholder UI** with Tailwind v3.4.17 (class strategy, `dark` on `<html>`, zinc-950 bg) and a `lang="es"` root layout with robots noindex/nofollow.
- **Per-request nonce propagation** to server components via `x-nonce` request header (consumable through `headers()` in Phase 02+ when we render inline scripts/styles).

## Verification results

- `pnpm install` clean.
- `pnpm --filter @simplevault/web build` exits 0 (4 static pages + Middleware bundle 32.3 kB).
- `pnpm --filter @simplevault/web typecheck` clean.
- Root `pnpm build` (turbo) green for both `@simplevault/api` and `@simplevault/web` plus all packages (5 tasks successful).
- `pnpm --filter @simplevault/web start` then `curl -sI http://localhost:3000/` returns HTTP 200 with **all required security headers** present: `content-security-policy` (with `nonce-...` and `'strict-dynamic'`), `strict-transport-security`, `x-frame-options: DENY`, `referrer-policy: no-referrer`, `permissions-policy: ...`, plus COOP/CORP/X-Content-Type-Options/X-DNS-Prefetch-Control.
- Two consecutive `curl -sI` requests yielded **different nonces** (`I2aF0PBuyroVyo5cuLn9tQ==` vs `1rfOfmoUfqHetH9qiuz9ng==`) — proves per-request generation.
- Body smoke test (`curl -s ... | grep`) confirms HTML contains `SimpleVault`, `lang="es"`, `class="dark"`.

## Decisions / rationale

- **Tailwind v3.4 over v4-alpha** — chose stability for Phase 01. v4 PostCSS plugin and CSS-first config syntax are still moving; aceternity-style components (Phase 12) currently target v3. Re-evaluate at Phase 12.
- **Next.js patch version: 15.1.0** — matches `eslint-config-next@15.1.0` to avoid peer drift. Plan said `15.1.0`; confirmed.
- **No `eslint-config-next` integration into shared eslint flat config** — `eslint-config-next` ships a legacy `.eslintrc`-style config that is not flat-config native. The Next ESLint plugin warning (`The Next.js plugin was not detected`) is benign during `next build`. We rely on `@simplevault/eslint-config/next` (which has the `no-restricted-imports` rule blocking `@simplevault/db` from web) for actual linting via `pnpm lint`. Worth revisiting when `eslint-config-next` ships flat-config-native (likely Next 16).
- **`apps/web/package.json` set `"type": "module"`** — silences a Node `MODULE_TYPELESS_PACKAGE_JSON` warning Next emits when reparsing `eslint.config.js` as ESM. Aligns with the rest of the workspace.
- **Per-package `tsBuildInfoFile`** retained (matches apps/api). The base-tsconfig pitfall noted in carry-overs is unchanged in this plan to keep scope tight; consider sweeping it out in a later cleanup commit alongside other base-tsconfig touches.
- **Module-resolution for middleware.ts:** Next.js webpack uses `bundler` resolution (no `.js` extensions on TS imports). `import "./lib/csp.js"` (NodeNext-style) breaks the build; switched to `import "./lib/csp"`. This diverges from the apps/api convention but is required for the Next bundler.
- **Nonce encoding:** plan suggested a `.reduce(...)` over Uint8Array — TypeScript strict types reject that signature on Edge runtime, so used a plain `for...of` loop building a binary string before `btoa(...)`.

## Issues / impact on later plans

- **Plan 06 (Dockerfile for apps/web):** standalone output is enabled. Multi-stage Dockerfile should `COPY --from=builder /app/apps/web/.next/standalone ./` and `.next/static`. Note: standalone trace doesn't include the `public` dir (we don't have one yet) or middleware-only package files (Next handles automatically).
- **Plan 07 (compose):** apps/web listens on `:3000`. Traefik (Dokploy) handles TLS termination. Compose service should NOT expose port 3000 to host in the production-ish profile; local dev profile may.
- **Plan 09 (CI):** add `pnpm --filter @simplevault/web build|lint|typecheck` to the CI matrix. Build needs `~600 MB` RAM (Next 15 + standalone tracing) — should fit GitHub-hosted runners. The Next ESLint plugin warning surfaces during `next build` lint pass — non-blocking but loud; CI should not fail on stderr.
- **Phase 12 (web hardening):** current CSP is already strict (no `unsafe-inline`, no `unsafe-eval`, `'strict-dynamic'`). Phase 12 likely (a) replaces `'strict-dynamic'` with explicit per-route hashes if needed for non-Next inline JS, (b) adds Reporting-Endpoints + report-to/report-uri, (c) adds CSRF mitigation and SameSite=strict cookie middleware once auth lands.
- **Carry-over preserved:** `@simplevault/db` import-blocking lives in `@simplevault/eslint-config/next` (no-restricted-imports group includes `@simplevault/db` and `@simplevault/db/*`). Verified.

## Files added

```
apps/web/package.json
apps/web/tsconfig.json
apps/web/next.config.mjs
apps/web/postcss.config.mjs
apps/web/tailwind.config.ts
apps/web/eslint.config.js
apps/web/src/app/globals.css
apps/web/src/app/layout.tsx
apps/web/src/app/page.tsx
apps/web/src/lib/csp.ts
apps/web/src/middleware.ts
```

Plus `pnpm-lock.yaml` regenerated for the new deps.
