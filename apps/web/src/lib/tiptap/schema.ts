/**
 * FROZEN v1 schema per REQ-VAULT-008.
 *
 * Adding image/table/embed extensions here = security review required +
 * Phase-bump. The strict allowlist below mirrors `sanitize.ts`'s tag
 * allowlist; both gates run (TipTap drops unknown nodes at parse, then
 * `sanitize-html` runs again at render — belt-and-suspenders per
 * REQ-WEBSEC-005).
 *
 * Plan 05-04 — TipTap editor strict schema.
 *
 * StarterKit v3 (`@tiptap/starter-kit`) is the single source of every
 * allowed node + mark. It already EXCLUDES `image`, `table`, `taskList`,
 * `mention`, `iframe`, and any embed extension — none of those types are
 * imported anywhere in this directory, so the bundle never carries them.
 * `horizontalRule` ships in StarterKit but is disabled below; it is not in
 * the v1 schema.
 */

import type { Extensions } from "@tiptap/core";
import StarterKit from "@tiptap/starter-kit";

/**
 * Reject any href that is not http(s). TipTap will silently drop the link
 * mark when this returns false. Defence-in-depth: `sanitize-html` runs the
 * same allowlist against rendered HTML.
 */
export const isSafeHttpUrl = (href: string): boolean => /^https?:\/\//i.test(href);

/**
 * The single source of truth for the v1 vault-page schema.
 *
 * Allowed nodes : doc, paragraph, text, hardBreak, heading(1-3), bulletList,
 *                 orderedList, listItem, blockquote, codeBlock.
 * Allowed marks : bold, italic, strike, underline, code, link (http(s) only).
 *
 * Disallowed (and not configurable on by accident): image, table, taskList,
 * mention, embed, iframe. `horizontalRule` is explicitly disabled.
 */
export const STRICT_EXTENSIONS: Extensions = [
  StarterKit.configure({
    heading: { levels: [1, 2, 3] },
    horizontalRule: false,
    link: {
      openOnClick: false,
      autolink: true,
      protocols: ["http", "https"],
      validate: isSafeHttpUrl,
      HTMLAttributes: {
        rel: "noopener noreferrer",
        target: "_blank",
      },
    },
  }),
];
