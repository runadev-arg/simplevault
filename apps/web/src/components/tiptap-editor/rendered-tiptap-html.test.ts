// Plan 05-04 (T3): sanitize-html allowlist rejection vectors.
//
// Belt-and-suspenders per REQ-WEBSEC-005. Every dangerous scheme is stripped
// from <a href>; every dangerous tag is dropped; every disallowed v1-schema
// node is dropped; safe TipTap-emitted HTML round-trips with rel/target
// auto-applied.
import { describe, expect, it } from "vitest";

import { sanitizeRenderedHtml } from "./rendered-tiptap-html";

describe("sanitizeRenderedHtml", () => {
  // ---- Link-href rejection vectors -----------------------------------------
  it("strips javascript: hrefs", () => {
    const out = sanitizeRenderedHtml('<a href="javascript:alert(1)">x</a>');
    expect(out.toLowerCase()).not.toContain("javascript:");
  });

  it("strips data:text/html hrefs", () => {
    const out = sanitizeRenderedHtml('<a href="data:text/html,<script>alert(1)</script>">x</a>');
    expect(out.toLowerCase()).not.toContain("data:");
    expect(out.toLowerCase()).not.toContain("<script");
  });

  it("strips vbscript: hrefs", () => {
    const out = sanitizeRenderedHtml('<a href="vbscript:msgbox">x</a>');
    expect(out.toLowerCase()).not.toContain("vbscript:");
  });

  it("strips file: hrefs", () => {
    const out = sanitizeRenderedHtml('<a href="file:///etc/passwd">x</a>');
    expect(out.toLowerCase()).not.toContain("file:");
  });

  it("strips protocol-relative hrefs", () => {
    const out = sanitizeRenderedHtml('<a href="//evil.example/x">x</a>');
    // allowProtocolRelative=false drops the href; either tag is empty or href is gone.
    expect(out).not.toContain('href="//evil.example');
  });

  // ---- Dangerous tags ------------------------------------------------------
  it("drops <script>", () => {
    const out = sanitizeRenderedHtml("<script>alert(1)</script>");
    expect(out.toLowerCase()).not.toContain("<script");
  });

  it("drops <iframe>", () => {
    const out = sanitizeRenderedHtml('<iframe src="https://evil.example"></iframe>');
    expect(out.toLowerCase()).not.toContain("<iframe");
  });

  it("drops <img> (not in v1 schema)", () => {
    const out = sanitizeRenderedHtml('<img src="x" onerror="alert(1)">');
    expect(out.toLowerCase()).not.toContain("<img");
    expect(out.toLowerCase()).not.toContain("onerror");
  });

  it("drops <table> (not in v1 schema)", () => {
    const out = sanitizeRenderedHtml("<table><tr><td>x</td></tr></table>");
    expect(out.toLowerCase()).not.toContain("<table");
    expect(out.toLowerCase()).not.toContain("<td");
  });

  it("drops <style> and inline event handlers", () => {
    const out = sanitizeRenderedHtml('<p onclick="alert(1)">x</p><style>.x{}</style>');
    expect(out.toLowerCase()).not.toContain("onclick");
    expect(out.toLowerCase()).not.toContain("<style");
  });

  // ---- Round-trip valid HTML -----------------------------------------------
  it("round-trips a safe paragraph + bold + link", () => {
    const html = '<p>hello <strong>world</strong> <a href="https://example.com">link</a></p>';
    const out = sanitizeRenderedHtml(html);
    expect(out).toContain("<p>");
    expect(out).toContain("<strong>world</strong>");
    expect(out).toContain('href="https://example.com"');
    // transformTags must add safe rel/target on every <a>.
    expect(out).toContain('rel="noopener noreferrer"');
    expect(out).toContain('target="_blank"');
  });

  it("preserves heading levels 1-3, lists, blockquote, code", () => {
    const html =
      "<h1>a</h1><h2>b</h2><h3>c</h3>" +
      "<ul><li>x</li></ul><ol><li>y</li></ol>" +
      "<blockquote>q</blockquote>" +
      "<pre><code>k</code></pre>" +
      "<p>i<code>j</code></p>";
    const out = sanitizeRenderedHtml(html);
    expect(out).toContain("<h1>a</h1>");
    expect(out).toContain("<h2>b</h2>");
    expect(out).toContain("<h3>c</h3>");
    expect(out).toContain("<ul><li>x</li></ul>");
    expect(out).toContain("<ol><li>y</li></ol>");
    expect(out).toContain("<blockquote>q</blockquote>");
    expect(out).toContain("<pre><code>k</code></pre>");
    expect(out).toContain("<code>j</code>");
  });

  it("drops headings outside the [1,2,3] allowlist", () => {
    const out = sanitizeRenderedHtml("<h4>x</h4><h5>y</h5><h6>z</h6>");
    expect(out.toLowerCase()).not.toContain("<h4");
    expect(out.toLowerCase()).not.toContain("<h5");
    expect(out.toLowerCase()).not.toContain("<h6");
  });
});
