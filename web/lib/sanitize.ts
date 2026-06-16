import sanitizeHtml from "sanitize-html";

// Allowlist mirroring the previous Flask/bleach config: a safe subset for
// third-party article HTML. data: URLs are allowed for <img> only.
const OPTIONS: sanitizeHtml.IOptions = {
  allowedTags: [
    "p",
    "br",
    "hr",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "s",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "a",
    "img",
    "figure",
    "figcaption",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "span",
    "div",
  ],
  allowedAttributes: {
    a: ["href", "title", "rel"],
    img: ["src", "alt", "title", "width", "height"],
    "*": ["id"],
  },
  allowedSchemes: ["http", "https", "mailto"],
  allowedSchemesByTag: { img: ["http", "https", "data"] },
  // Discard disallowed tags (keep their text), matching bleach strip=True.
  disallowedTagsMode: "discard",
};

export function sanitizeArticle(html: string | null | undefined): string {
  if (!html) {
    return "";
  }
  return sanitizeHtml(html, OPTIONS);
}
