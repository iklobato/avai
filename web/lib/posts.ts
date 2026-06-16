import "server-only";
import { ensureSchema, query } from "./db";

// One row of autoseo_blog_posts. JSON columns come back already parsed by pg.
export interface BlogPost {
  id: number;
  autoseo_id: number;
  event: string | null;
  title: string;
  slug: string;
  published_url: string | null;
  meta_description: string | null;
  content_html: string | null;
  content_markdown: string | null;
  hero_image_url: string | null;
  hero_image_alt: string | null;
  infographic_image_url: string | null;
  keywords_json: string[] | null;
  meta_keywords: string | null;
  faq_schema_json: Array<{ question?: string; answer?: string }> | null;
  language_code: string | null;
  status: string | null;
  published_at: string | null;
  updated_at: string | null;
  created_at: string | null;
  received_at: string;
}

// The webhook payload as delivered by AutoSEO.
export interface AutoseoPayload {
  event?: string;
  id?: number | string;
  title?: string;
  slug?: string;
  published_url?: string | null;
  metaDescription?: string | null;
  content_html?: string | null;
  content_markdown?: string | null;
  heroImageUrl?: string | null;
  heroImageAlt?: string | null;
  infographicImageUrl?: string | null;
  keywords?: unknown[];
  metaKeywords?: string | null;
  faqSchema?: unknown[] | null;
  languageCode?: string | null;
  status?: string | null;
  publishedAt?: string | null;
  updatedAt?: string | null;
  createdAt?: string | null;
}

export async function listPosts(limit?: number): Promise<BlogPost[]> {
  await ensureSchema();
  const text =
    "SELECT * FROM autoseo_blog_posts ORDER BY published_at DESC NULLS LAST" +
    (limit ? " LIMIT $1" : "");
  return query<BlogPost>(text, limit ? [limit] : undefined);
}

export async function getPostBySlug(slug: string): Promise<BlogPost | null> {
  await ensureSchema();
  const rows = await query<BlogPost>(
    "SELECT * FROM autoseo_blog_posts WHERE slug = $1 ORDER BY received_at DESC LIMIT 1",
    [slug],
  );
  return rows[0] ?? null;
}

// Upsert keyed on autoseo_id so re-deliveries / article.updated overwrite in
// place instead of duplicating. Mirrors the Flask _store_post contract.
export async function upsertPost(
  payload: AutoseoPayload,
  autoseoId: number,
  slug: string,
): Promise<void> {
  const faq = payload.faqSchema;
  const params = [
    autoseoId, // $1 autoseo_id
    payload.event ?? null, // $2 event
    payload.title ?? "", // $3 title
    slug, // $4 slug
    payload.published_url ?? null, // $5 published_url
    payload.metaDescription ?? null, // $6 meta_description
    payload.content_html ?? null, // $7 content_html
    payload.content_markdown ?? null, // $8 content_markdown
    payload.heroImageUrl ?? null, // $9 hero_image_url
    payload.heroImageAlt ?? null, // $10 hero_image_alt
    payload.infographicImageUrl ?? null, // $11 infographic_image_url
    JSON.stringify(payload.keywords ?? []), // $12 keywords_json
    payload.metaKeywords ?? null, // $13 meta_keywords
    faq != null ? JSON.stringify(faq) : null, // $14 faq_schema_json
    payload.languageCode ?? null, // $15 language_code
    payload.status ?? null, // $16 status
    payload.publishedAt ?? null, // $17 published_at
    payload.updatedAt ?? null, // $18 updated_at
    payload.createdAt ?? null, // $19 created_at
    new Date().toISOString().replace(/\.\d+Z$/, "Z"), // $20 received_at (seconds)
  ];

  await query(
    `INSERT INTO autoseo_blog_posts (
       autoseo_id, event, title, slug, published_url, meta_description,
       content_html, content_markdown, hero_image_url, hero_image_alt,
       infographic_image_url, keywords_json, meta_keywords, faq_schema_json,
       language_code, status, published_at, updated_at, created_at, received_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
       $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
     )
     ON CONFLICT (autoseo_id) DO UPDATE SET
       event = EXCLUDED.event,
       title = EXCLUDED.title,
       slug = EXCLUDED.slug,
       published_url = EXCLUDED.published_url,
       meta_description = EXCLUDED.meta_description,
       content_html = EXCLUDED.content_html,
       content_markdown = EXCLUDED.content_markdown,
       hero_image_url = EXCLUDED.hero_image_url,
       hero_image_alt = EXCLUDED.hero_image_alt,
       infographic_image_url = EXCLUDED.infographic_image_url,
       keywords_json = EXCLUDED.keywords_json,
       meta_keywords = EXCLUDED.meta_keywords,
       faq_schema_json = EXCLUDED.faq_schema_json,
       language_code = EXCLUDED.language_code,
       status = EXCLUDED.status,
       published_at = EXCLUDED.published_at,
       updated_at = EXCLUDED.updated_at,
       created_at = EXCLUDED.created_at,
       received_at = EXCLUDED.received_at`,
    params,
  );
}
