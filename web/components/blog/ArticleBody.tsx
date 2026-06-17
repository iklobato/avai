// Renders already-sanitized article HTML. The `html` passed in MUST have gone
// through sanitizeArticle() first.
export function ArticleBody({ html }: { html: string }) {
  return (
    <div
      className="prose prose-invert max-w-none prose-headings:text-slate-100 prose-a:text-accent"
      // eslint-disable-next-line react/no-danger
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
