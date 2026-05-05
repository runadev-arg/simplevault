/**
 * Plan 05-04 (T2) — sanitize-html allowlist + the ONLY component in the
 * codebase allowed to use `dangerouslySetInnerHTML`.
 *
 * Belt-and-suspenders per REQ-WEBSEC-005:
 *   1. TipTap drops unknown nodes at parse (FROZEN STRICT_EXTENSIONS).
 *   2. `sanitizeRenderedHtml` runs again at render against the same
 *      allowlist, so even if the JSON-to-HTML serializer ever leaks a
 *      disallowed tag, it gets stripped before hitting the DOM.
 *
 * No raw HTML is ever passed to `dangerouslySetInnerHTML` — the only call
 * site is `<RenderedTipTapHtml>` below, which feeds it `sanitize-html`
 * output. The grep invariant
 *     `grep -rn "dangerouslySetInnerHTML" apps/web/src` -> exactly 1 hit
 * is documented in 05-04-SUMMARY.md.
 */

import sanitizeHtml from "sanitize-html";

/**
 * Allowlist that mirrors `extensions.ts`'s STRICT_EXTENSIONS:
 *   - block : p, h1-h3, ul, ol, li, blockquote, pre, code (also inline)
 *   - inline: strong, em, s, u, a, br
 *
 * `allowedSchemes` is `http|https`; `data:`, `javascript:`, `vbscript:`,
 * `file:`, etc. are stripped. Every `<a>` is rewritten to carry
 * `rel="noopener noreferrer" target="_blank"`.
 */
const SANITIZE_OPTIONS: sanitizeHtml.IOptions = {
  allowedTags: [
    "p",
    "h1",
    "h2",
    "h3",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "code",
    "strong",
    "em",
    "s",
    "u",
    "a",
    "br",
  ],
  allowedAttributes: {
    a: ["href", "target", "rel"],
    code: ["class"],
    pre: ["class"],
  },
  allowedSchemes: ["http", "https"],
  allowedSchemesAppliedToAttributes: ["href"],
  allowProtocolRelative: false,
  disallowedTagsMode: "discard",
  transformTags: {
    a: sanitizeHtml.simpleTransform("a", {
      rel: "noopener noreferrer",
      target: "_blank",
    }),
  },
};

/**
 * Sanitize TipTap-emitted HTML against the v1 schema allowlist. Strips any
 * tag/attribute/scheme outside the allowlist; output is safe to pass to
 * `dangerouslySetInnerHTML` (and ONLY from `<RenderedTipTapHtml>` below).
 */
export function sanitizeRenderedHtml(html: string): string {
  return sanitizeHtml(html, SANITIZE_OPTIONS);
}

/**
 * Read-only HTML renderer for the history-diff view. The ONLY component in
 * the codebase that uses `dangerouslySetInnerHTML`, and only against
 * `sanitize-html` output. Live editing uses TipTap's React reconciliation
 * (`<EditorContent>` in `./editor.tsx`) — never raw HTML injection.
 */
export function RenderedTipTapHtml({ html }: { html: string }) {
  const clean = sanitizeRenderedHtml(html);
  return (
    <div
      data-testid="rendered-tiptap-html"
      // Sanctioned use of dangerouslySetInnerHTML — single grep hit invariant.
      // Input is sanitize-html allowlist output (REQ-WEBSEC-005).
      dangerouslySetInnerHTML={{ __html: clean }}
    />
  );
}
