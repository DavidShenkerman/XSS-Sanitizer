// src/sanitize.js
// Minimal DOM-based sanitizer. Browser-first; Node users pass a createDocument() option.
// MIT License.

const SAFE_ELEMENTS = new Set([
    "a", "abbr", "b", "blockquote", "br", "code", "div", "em", "i", "img",
    "li", "ol", "p", "pre", "s", "small", "span", "strong", "sub", "sup",
    "table", "tbody", "td", "th", "thead", "tr", "u", "ul", "hr", "h1",
    "h2", "h3", "h4", "h5", "h6", "section", "article", "nav", "header", "footer"
  ]);
  
  // Per-tag attribute allowlists (lowercase). Anything else is removed.
  const GLOBAL_ATTRS = new Set(["class", "id", "title", "role"]);
  const TAG_ATTRS = {
    a: new Set(["href", "target", "rel"]),
    img: new Set(["src", "alt", "width", "height"]),
    table: new Set([]), thead: new Set([]), tbody: new Set([]),
    tr: new Set([]), th: new Set([]), td: new Set([]),
    // add more per tag as needed
  };
  
  // Tags we always drop entirely (with children unwrapped or removed depending on context)
  const ALWAYS_DROP = new Set([
    "script", "style", "template", "iframe", "object", "embed",
    "svg", "math", "base", "link", "meta"
  ]);
  
  /**
   * Basic URL sanitizer: allow only http(s), protocol-relative (//), and relative URLs.
   * Everything else (javascript:, vbscript:, data:, file:, etc.) is stripped.
   */
  function isSafeUrl(raw) {
    if (!raw) return true; // empty/absent treated as safe
    const value = String(raw).trim();
  
    // Remove control chars and whitespace that can hide protocols
    const compact = value.replace(/[\u0000-\u001F\u007F\s]+/g, "").toLowerCase();
  
    if (compact.startsWith("javascript:")) return false;
    if (compact.startsWith("vbscript:")) return false;
    if (compact.startsWith("data:")) return false;
    if (compact.startsWith("file:")) return false;
  
    // protocol-relative //example.com ok
    if (compact.startsWith("//")) return true;
  
    // absolute with scheme:
    const colon = compact.indexOf(":");
    if (colon > 0) {
      const scheme = compact.slice(0, colon);
      return scheme === "http" || scheme === "https";
    }
  
    // relative (no scheme) ok
    return true;
  }
  
  function isAllowedAttr(tag, name) {
    const n = name.toLowerCase();
    if (n.startsWith("on")) return false;          // event handlers
    if (n === "style") return false;               // drop inline CSS for MVP safety
    if (GLOBAL_ATTRS.has(n)) return true;
    const allowed = TAG_ATTRS[tag] || new Set();
    return allowed.has(n);
  }
  
  function ensureSafeLinkAttrs(el) {
    // If <a target="_blank">, enforce rel="noopener noreferrer"
    const tag = el.tagName.toLowerCase();
    if (tag === "a" && el.getAttribute("target") === "_blank") {
      const rel = (el.getAttribute("rel") || "").toLowerCase();
      const needed = new Set(["noopener", "noreferrer"]);
      const parts = new Set(rel.split(/\s+/).filter(Boolean));
      needed.forEach((x) => parts.add(x));
      el.setAttribute("rel", Array.from(parts).join(" "));
    }
  }
  
  function unwrapElement(el) {
    const parent = el.parentNode;
    if (!parent) { el.remove(); return; }
    while (el.firstChild) parent.insertBefore(el.firstChild, el);
    el.remove();
  }
  
  function sanitizeElement(el) {
    const tag = el.tagName.toLowerCase();
  
    // Drop always-dangerous containers entirely
    if (ALWAYS_DROP.has(tag)) {
      el.remove(); // remove whole subtree
      return;
    }
  
    // If not in whitelist: unwrap so content remains but tag is gone
    if (!SAFE_ELEMENTS.has(tag)) {
      unwrapElement(el);
      return;
    }
  
    // Sanitize attributes
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      const value = attr.value;
  
      if (!isAllowedAttr(tag, name)) {
        el.removeAttribute(attr.name);
        continue;
      }
  
      // URL-bearing attributes
      if ((name === "href" || name === "src")) {
        if (!isSafeUrl(value)) {
          el.removeAttribute(attr.name); // neutralize
          continue;
        }
      }
    }
  
    ensureSafeLinkAttrs(el);
  }
  
  function walkAndSanitize(root) {
    // Use a snapshot to avoid live-collection pitfalls while mutating
    const nodes = Array.from(root.querySelectorAll("*"));
    for (const node of nodes) sanitizeElement(node);
  }
  
  /**
   * Sanitize an HTML string. Returns safe HTML string.
   *
   * Options:
   *   - createDocument?: (html) => Document    // Node users pass a JSDOM-based factory
   *
   * In browsers, no options are required.
   */
  export function sanitize(html, options = {}) {
    if (html == null) return "";
  
    let doc;
    if (options.createDocument && typeof options.createDocument === "function") {
      doc = options.createDocument(String(html));
    } else if (typeof window !== "undefined" && window.DOMParser) {
      doc = new window.DOMParser().parseFromString(String(html), "text/html");
    } else {
      throw new Error(
        "No DOM available. In Node, pass options.createDocument(html) using jsdom."
      );
    }
  
    const { body } = doc;
    walkAndSanitize(body);
    return body.innerHTML;
  }
  