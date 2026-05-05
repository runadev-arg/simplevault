---
phase: 05-vault-pages
plan: 05-04
subsystem: web-tiptap-editor + sanitize-html
tags: [tiptap, sanitize-html, xss, link-validation, REQ-WEBSEC-005, REQ-VAULT-008]
requires:
  - 05-01 (page schemas + AAD label) — only soft dep; this plan is self-contained
provides:
  - apps/web/src/components/tiptap-editor/extensions.ts — STRICT_EXTENSIONS (FROZEN v1) + isSafeHttpUrl
  - apps/web/src/components/tiptap-editor/index.tsx — <PageEditor value onChange readOnly?> controlled
  - apps/web/src/components/tiptap-editor/rendered-tiptap-html.tsx — sanitizeRenderedHtml + <RenderedTipTapHtml>
  - 32 Vitest specs (index.test.tsx 19 + rendered-tiptap-html.test.ts 13)
affects:
  - 05-05 (web pages routes) — imports { PageEditor, RenderedTipTapHtml } from "components/tiptap-editor"
key-decisions:
  - StarterKit v3 used as the single bundled source (link + underline included; image/table/embed NOT shipped). horizontalRule disabled — not in v1 schema.
  - Link.validate=/^https?:\/\//i + protocols=[http,https] = belt; sanitize-html allowedSchemes=[http,https] + allowProtocolRelative=false = suspenders. Both gates run on every render path.
  - Path: components/tiptap-editor/ (NOT lib/tiptap/) to match user-prompt import surface and existing 05-05 imports.
  - Live editor renders via TipTap React reconciliation (<EditorContent>) — never raw HTML. Only <RenderedTipTapHtml> uses dangerouslySetInnerHTML, and only against sanitize-html allowlist output.
  - immediatelyRender:false on useEditor to avoid Next 15 SSR hydration mismatch.
  - parseOptions.preserveWhitespace=false to drop pasted pre-formatting.
  - Bundle budget: TipTap StarterKit + Link + Underline + sanitize-html add ~100-150 KiB to /pages routes — acceptable, within REQ-PERF-007 vault-route budget.
commits:
  - 95a7d54 feat(05-04-T1): TipTap deps + STRICT_EXTENSIONS frozen v1 schema
  - a1ce7f0 feat(05-04-T2): controlled PageEditor + sanitize-html + RenderedTipTapHtml
  - e606362 feat(05-04-T3): restructure to components/tiptap-editor + Vitest specs
verify:
  - "pnpm --filter @simplevault/web test: 11 files / 98 tests PASS (32 new)"
  - "pnpm exec eslint apps/web/src/components/tiptap-editor/: clean"
  - "pnpm --filter @simplevault/web typecheck: only PRE-EXISTING errors (credentials-client unused-import, credential-cipher possibly-undefined, aad-parity unused-import) — no new tiptap errors"
  - "grep -rn 'dangerouslySetInnerHTML={' apps/web/src | wc -l == 1 (rendered-tiptap-html.tsx:87 vs sanitize-html output)"
duration: ~25min
completed: 2026-05-04
---

# Phase 05 Plan 04: TipTap editor + strict schema + link sanitization

Wave 2 / 5-plan MVP-track. Three atomic commits land the vault-page editor with two independent XSS gates (TipTap parse-time schema + sanitize-html render-time allowlist) and the single sanctioned `dangerouslySetInnerHTML` site in the codebase.

**Status:** COMPLETE
**Date:** 2026-05-04

## Security invariant — REQ-WEBSEC-005

```
$ grep -rn 'dangerouslySetInnerHTML={' apps/web/src
apps/web/src/components/tiptap-editor/rendered-tiptap-html.tsx:87:      dangerouslySetInnerHTML={{ __html: clean }}
```

Exactly ONE JSX-attribute hit, inside the sanctioned `<RenderedTipTapHtml>`, against `sanitizeRenderedHtml(html)` output (allowlist matching the FROZEN v1 schema). The live editor uses TipTap's React reconciliation (`<EditorContent>`) — never raw HTML injection.

## Link-href rejection vectors covered (Vitest)

`javascript:` (any case), `data:text/html`, `vbscript:`, `file://`, protocol-relative `//host`, `mailto:`, `ftp:`, empty, whitespace-only — all rejected by `isSafeHttpUrl` and stripped by `sanitize-html`. `http://` and `https://` (any case) accepted. `setLink({href:"javascript:..."})` leaves NO `<a>` in the editor's HTML output.

## Disallowed-node coverage (Vitest)

`<script>`, `<iframe>`, `<img>`, `<table>`, `<style>`, inline `onclick=` / `onerror=`, headings `<h4>`-`<h6>` — all dropped by both gates.

## Hand-offs to siblings

- **05-05 (/pages routes)** imports `{ PageEditor, RenderedTipTapHtml } from "../../../../components/tiptap-editor"`. `PageEditor` is controlled (`value: JSONContent`, `onChange: (next) => void`); `RenderedTipTapHtml` takes `{html: string}` for the history-diff side panel.

## Bundle-budget note

TipTap (`@tiptap/core` + `@tiptap/react` + `@tiptap/starter-kit` + `@tiptap/extension-link` + `@tiptap/extension-underline`) plus `sanitize-html` add an estimated 100-150 KiB gzipped to `/pages` and `/page/[id]` routes. This is within REQ-PERF-007's vault-route budget. The marketing/landing routes never transitively import this directory and are unaffected.

## Frozen-schema invariant

Adding ANY extension to `STRICT_EXTENSIONS` (image, table, taskList, mention, embed, iframe, horizontalRule, etc.) requires a security review and a Phase-bump. The corresponding `sanitize-html` allowlist in `rendered-tiptap-html.tsx` MUST be updated in lockstep — both gates exist precisely so a single forgotten update cannot become an XSS sink.
