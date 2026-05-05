// @vitest-environment jsdom
//
// Plan 05-04 (T3): TipTap editor schema strictness + link-validate rejection.
//
// We test the parse boundary directly via @tiptap/core's `Editor`: feeding
// disallowed HTML through `setContent` MUST drop the unknown nodes (TipTap's
// default behaviour against the strict schema) and feeding an unsafe href
// through the link `validate` predicate MUST reject.
import { Editor } from "@tiptap/core";
import { describe, expect, it } from "vitest";

import { isSafeHttpUrl, STRICT_EXTENSIONS } from "./extensions";

const makeEditor = () =>
  new Editor({
    extensions: STRICT_EXTENSIONS,
    content: "",
  });

describe("STRICT_EXTENSIONS — TipTap parse-time gate", () => {
  it("drops <script> nodes pasted as HTML", () => {
    const editor = makeEditor();
    editor.commands.setContent("<p>hi</p><script>alert(1)</script>");
    const json = JSON.stringify(editor.getJSON());
    expect(json.toLowerCase()).not.toContain("script");
    expect(editor.getHTML().toLowerCase()).not.toContain("<script");
    editor.destroy();
  });

  it("drops <iframe> nodes pasted as HTML", () => {
    const editor = makeEditor();
    editor.commands.setContent('<p>hi</p><iframe src="https://evil"></iframe>');
    expect(editor.getHTML().toLowerCase()).not.toContain("<iframe");
    editor.destroy();
  });

  it("drops <img> nodes (not in v1 schema)", () => {
    const editor = makeEditor();
    editor.commands.setContent('<p>hi</p><img src="x" onerror="alert(1)">');
    expect(editor.getHTML().toLowerCase()).not.toContain("<img");
    expect(editor.getHTML().toLowerCase()).not.toContain("onerror");
    editor.destroy();
  });

  it("drops <table> nodes (not in v1 schema)", () => {
    const editor = makeEditor();
    editor.commands.setContent("<table><tr><td>x</td></tr></table>");
    expect(editor.getHTML().toLowerCase()).not.toContain("<table");
    editor.destroy();
  });

  it("preserves valid headings, lists, blockquote, code-block", () => {
    const editor = makeEditor();
    editor.commands.setContent(
      "<h2>t</h2><ul><li>a</li></ul><blockquote>q</blockquote><pre><code>k</code></pre>",
    );
    const html = editor.getHTML();
    expect(html).toContain("<h2>t</h2>");
    expect(html).toContain("<ul>");
    expect(html).toContain("<blockquote>");
    expect(html).toContain("<pre>");
    editor.destroy();
  });
});

describe("Link mark — validate predicate rejection vectors", () => {
  // Direct unit-test of the validate predicate. TipTap calls this for every
  // href before applying the link mark; false => mark not applied.
  it.each([
    ["javascript:alert(1)"],
    ["JavaScript:alert(1)"],
    ["data:text/html,<script>alert(1)</script>"],
    ["vbscript:msgbox"],
    ["file:///etc/passwd"],
    ["//protocol-relative.example"],
    ["mailto:x@y.z"],
    ["ftp://example.com"],
    [""],
    ["   "],
  ])("rejects unsafe href %j", (href) => {
    expect(isSafeHttpUrl(href)).toBe(false);
  });

  it.each([
    ["https://example.com"],
    ["http://example.com"],
    ["HTTPS://Example.com/path?q=1#h"],
  ])("accepts safe http(s) href %j", (href) => {
    expect(isSafeHttpUrl(href)).toBe(true);
  });

  it("does not apply the link mark when href is javascript:", () => {
    const editor = makeEditor();
    editor.commands.setContent("<p>hello</p>");
    // Select all so the mark would apply if validate did not reject.
    editor.commands.selectAll();
    editor.commands.setLink({ href: "javascript:alert(1)" });
    const html = editor.getHTML();
    expect(html.toLowerCase()).not.toContain("javascript:");
    expect(html.toLowerCase()).not.toContain("<a ");
    editor.destroy();
  });
});
