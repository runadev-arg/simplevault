"use client";

/**
 * Plan 05-04 (T2) — TipTap controlled editor.
 *
 * Wraps `useEditor` with the FROZEN `STRICT_EXTENSIONS` schema. The live
 * editor renders via TipTap's React reconciliation through `EditorContent`
 * (NEVER `dangerouslySetInnerHTML`). The read-only history-diff view is in
 * `./sanitize.tsx` (`<RenderedTipTapHtml>`), the single component in the
 * codebase allowed to use `dangerouslySetInnerHTML`, and only against
 * `sanitize-html` output.
 *
 * REQ-WEBSEC-005 / REQ-VAULT-008.
 */

import { type JSONContent, EditorContent, useEditor } from "@tiptap/react";
import { useEffect } from "react";

import { STRICT_EXTENSIONS } from "./schema";

export interface PageEditorProps {
  /** Controlled JSON value. */
  value: JSONContent;
  /** Called with TipTap JSON on every transaction. */
  onChange: (next: JSONContent) => void;
  /** Render-only mode (history viewer in same shell). Default false. */
  readOnly?: boolean;
}

/**
 * Controlled vault-page editor. Pass `value` (TipTap JSON) and `onChange`;
 * the component owns the ProseMirror state.
 */
export function PageEditor({ value, onChange, readOnly = false }: PageEditorProps) {
  const editor = useEditor({
    extensions: STRICT_EXTENSIONS,
    content: value,
    editable: !readOnly,
    // Disallowed nodes pasted as HTML are silently dropped by TipTap because
    // the strict schema does not declare them. preserveWhitespace=false keeps
    // pasted whitespace from leaking unexpected pre-formatting.
    parseOptions: { preserveWhitespace: false },
    onUpdate: ({ editor: e }) => {
      onChange(e.getJSON());
    },
    // Avoid SSR hydration mismatch — render the editor only on the client.
    immediatelyRender: false,
  });

  // Keep editable state in sync with the readOnly prop.
  useEffect(() => {
    if (editor?.isEditable === readOnly) {
      editor.setEditable(!readOnly);
    }
  }, [editor, readOnly]);

  return <EditorContent editor={editor} data-testid="page-editor" />;
}

export { PageEditor as default };
