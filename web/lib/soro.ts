import "server-only";

// Soro (https://trysoro.com) hosts a set of blog articles and exposes them via
// a public embed endpoint. We read that endpoint server-side and merge Soro's
// articles with our own AutoSEO posts into one blog. The embed token is public
// (it ships in the landing page's client JS), so it's a plain config value.
const SORO_API_BASE = "https://app.trysoro.com";
const SORO_TOKEN =
  process.env.SORO_EMBED_TOKEN ?? "bd68eb65-c4c0-4180-88e9-4b69fde0944c";
const REVALIDATE_SECONDS = 600;

export interface SoroArticle {
  id: string;
  title: string;
  slug: string;
  excerpt: string | null;
  date: string | null; // human label, e.g. "June 16, 2026"
  isoDate: string | null; // sortable ISO timestamp
  image: string | null;
}

// The embed endpoint returns a JS file with `var SORO_ARTICLES = [...]`.
function extractArticles(js: string): unknown[] {
  const marker = "var SORO_ARTICLES = ";
  const start = js.indexOf(marker);
  if (start === -1) {
    return [];
  }
  // The array is followed by `];\n  var SORO_TOKEN`; the list entries carry
  // `"content":null`, so the first `];` is the true end of the array.
  const tail = js.slice(start + marker.length);
  const end = tail.indexOf("];");
  if (end === -1) {
    return [];
  }
  return JSON.parse(tail.slice(0, end + 1)) as unknown[];
}

export async function listSoroArticles(): Promise<SoroArticle[]> {
  if (!SORO_TOKEN) {
    return [];
  }
  try {
    const res = await fetch(`${SORO_API_BASE}/api/embed/${SORO_TOKEN}`, {
      next: { revalidate: REVALIDATE_SECONDS },
    });
    if (!res.ok) {
      return [];
    }
    const raw = extractArticles(await res.text()) as Array<
      Record<string, unknown>
    >;
    return raw.map((a) => ({
      id: String(a.id ?? ""),
      title: String(a.title ?? ""),
      slug: String(a.slug ?? ""),
      excerpt: (a.excerpt as string | undefined) ?? null,
      date: (a.date as string | undefined) ?? null,
      isoDate: (a.isoDate as string | undefined) ?? null,
      image: (a.image as string | undefined) ?? null,
    }));
  } catch {
    // Soro being unreachable must not break the blog — just drop its articles.
    return [];
  }
}

export async function getSoroArticleBySlug(
  slug: string,
): Promise<{ article: SoroArticle; content: string } | null> {
  const article = (await listSoroArticles()).find((a) => a.slug === slug);
  if (!article) {
    return null;
  }
  try {
    const res = await fetch(
      `${SORO_API_BASE}/api/embed/${SORO_TOKEN}/article/${article.id}`,
      { next: { revalidate: REVALIDATE_SECONDS } },
    );
    if (!res.ok) {
      return null;
    }
    const data = (await res.json()) as { content?: string };
    return { article, content: data.content ?? "" };
  } catch {
    return null;
  }
}
