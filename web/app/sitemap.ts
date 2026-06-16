import type { MetadataRoute } from "next";
import { listPosts } from "@/lib/posts";

const BASE = "https://getavai.com";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const entries: MetadataRoute.Sitemap = [
    { url: `${BASE}/`, changeFrequency: "weekly", priority: 1.0 },
    { url: `${BASE}/blog`, changeFrequency: "weekly", priority: 0.8 },
  ];
  try {
    const posts = await listPosts();
    for (const post of posts) {
      const last = post.updated_at ?? post.received_at;
      entries.push({
        url: `${BASE}/blog/${post.slug}`,
        lastModified: last ? new Date(last) : undefined,
        changeFrequency: "monthly",
        priority: 0.6,
      });
    }
  } catch {
    // DB unreachable at build/request time — still emit the static URLs.
  }
  return entries;
}
