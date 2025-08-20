// test/test.js
// Dev deps: jsdom
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { sanitize } from "../src/sanitize.js";

function createDocument(html) {
  return new JSDOM(String(html)).window.document;
}

function s(html) {
  return sanitize(html, { createDocument });
}

console.log("Running sanitizer tests...");

// 1) strips <script>, keeps text when unwrapping unknown tags
assert.equal(s("<p>hi<script>alert(1)</script></p>"), "<p>hi</p>");
assert.equal(s("<custom>hello<b>world</b></custom>"), "hello<b>world</b>");

// 2) drops event handlers
assert.equal(
  s('<img src="x" onerror="alert(1)">'),
  '<img src="x">'
);

// 3) blocks javascript: and non-http(s) URLs
assert.equal(
  s('<a href="javascript:alert(1)">x</a>'),
  "<a>x</a>"
);
assert.equal(
  s('<a href="vbscript:msgbox(1)">x</a>'),
  "<a>x</a>"
);
assert.equal(
  s('<a href="data:text/html,hi">x</a>'),
  "<a>x</a>"
);

// 4) allows http(s), relative, and protocol-relative URLs
assert.equal(
  s('<a href="https://example.com">x</a>'),
  '<a href="https://example.com">x</a>'
);
assert.equal(
  s('<a href="/docs">x</a>'),
  '<a href="/docs">x</a>'
);
assert.equal(
  s('<a href="//cdn.example.com/lib.js">x</a>'),
  '<a href="//cdn.example.com/lib.js">x</a>'
);

// 5) style removed, unknown attrs removed
assert.equal(
  s('<p style="color:red" data-x="1" title="ok">t</p>'),
  '<p title="ok">t</p>'
);

// 6) target=_blank hardened with rel
assert.equal(
  s('<a href="https://x.com" target="_blank">x</a>'),
  '<a href="https://x.com" target="_blank" rel="noopener noreferrer">x</a>'
);

// 7) SVG/Math/template removed
assert.equal(
  s('<p>ok<svg onload="x()"></svg></p>'),
  "<p>ok</p>"
);
assert.equal(
  s('<template><img src=x onerror=1></template><p>t</p>'),
  "<p>t</p>"
);

// 8) images need http(s)/relative src
assert.equal(
  s('<img src="javascript:alert(1)" alt="x">'),
  '<img alt="x">'
);

console.log("All tests passed.");
