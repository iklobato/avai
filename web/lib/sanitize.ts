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

// Every article image should link to the homepage. We wrap bare <img> tags in
// an anchor AFTER sanitizing (the markup is ours, so it isn't re-stripped).
const HOME_HREF = "/";
const IMG_TAG = /<img\b[^>]*>/gi;
const OPEN_A = /<a\b[^>]*>/gi;
const CLOSE_A = /<\/a\s*>/gi;

// True when the character offset falls inside an open <a>…</a> region. Used to
// skip images already linked, since nesting anchors is invalid HTML.
function isInsideAnchor(html: string, offset: number): boolean {
  const region = html.slice(0, offset);
  const opens = (region.match(OPEN_A) ?? []).length;
  const closes = (region.match(CLOSE_A) ?? []).length;
  return opens > closes;
}

function wrapImagesWithHomeLink(html: string): string {
  return html.replace(IMG_TAG, (tag, offset: number) =>
    isInsideAnchor(html, offset)
      ? tag
      : `<a href="${HOME_HREF}" class="cursor-pointer" aria-label="Go to homepage">${tag}</a>`,
  );
}

export function sanitizeArticle(html: string | null | undefined): string {
  if (!html) {
    return "";
  }
  return wrapImagesWithHomeLink(sanitizeHtml(html, OPTIONS));
}
