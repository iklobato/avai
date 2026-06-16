import "server-only";
import { type BlogPost, listPosts } from "./posts";
import { listSoroArticles } from "./soro";

// A blog entry from either provider, normalised for listing.
export interface FeedItem {
  source: "autoseo" | "soro";
  slug: string;
  title: string;
  excerpt: string | null;
  image: string | null;
  iso: string | null; // sortable timestamp
  dateLabel: string | null; // display label
}

function fromAutoseo(p: BlogPost): FeedItem {
  return {
    source: "autoseo",
    slug: p.slug,
    title: p.title,
    excerpt: p.meta_description,
    image: p.hero_image_url,
    iso: p.published_at ?? p.received_at,
    dateLabel: p.published_at,
  };
}

// Merge AutoSEO (Postgres) and Soro (embed API) articles into one list, newest
// first. Either source failing is non-fatal — the other still shows. AutoSEO
// wins on a slug collision so /blog/<slug> resolves consistently.
export async function listFeed(limit?: number): Promise<FeedItem[]> {
  const [autoseo, soro] = await Promise.all([
    listPosts().catch(() => [] as BlogPost[]),
    listSoroArticles(),
  ]);

  const seen = new Set(autoseo.map((p) => p.slug));
  const items: FeedItem[] = [
    ...autoseo.map(fromAutoseo),
    ...soro
      .filter((a) => !seen.has(a.slug))
      .map((a) => ({
        source: "soro" as const,
        slug: a.slug,
        title: a.title,
        excerpt: a.excerpt,
        image: a.image,
        iso: a.isoDate,
        dateLabel: a.date,
      })),
  ];

  items.sort((x, y) => (y.iso ?? "").localeCompare(x.iso ?? ""));
  return limit ? items.slice(0, limit) : items;
}
