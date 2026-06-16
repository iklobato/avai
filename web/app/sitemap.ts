import type { MetadataRoute } from "next";
import { listFeed } from "@/lib/feed";

const BASE = "https://getavai.com";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const entries: MetadataRoute.Sitemap = [
    { url: `${BASE}/`, changeFrequency: "weekly", priority: 1.0 },
    { url: `${BASE}/blog`, changeFrequency: "weekly", priority: 0.8 },
  ];
  try {
    const items = await listFeed();
    for (const item of items) {
      entries.push({
        url: `${BASE}/blog/${item.slug}`,
        lastModified: item.iso ? new Date(item.iso) : undefined,
        changeFrequency: "monthly",
        priority: 0.6,
      });
    }
  } catch {
    // Sources unreachable — still emit the static URLs.
  }
  return entries;
}
