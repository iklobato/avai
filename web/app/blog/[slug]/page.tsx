import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ArticleBody } from "@/components/blog/ArticleBody";
import { faqJsonLd } from "@/lib/faq";
import { getPostBySlug } from "@/lib/posts";
import { sanitizeArticle } from "@/lib/sanitize";
import { getSoroArticleBySlug } from "@/lib/soro";

export const dynamic = "force-dynamic";

type Params = Promise<{ slug: string }>;

// Normalised view for either provider so the page renders once.
interface ArticleView {
  title: string;
  description: string | null;
  keywords: string | null;
  dateLabel: string | null;
  heroImage: string | null;
  heroAlt: string | null;
  contentHtml: string; // sanitized
  infographic: string | null;
  jsonLd: string | null;
  lang: string;
}

// Resolve a slug to an article from AutoSEO (Postgres) first, then Soro.
async function resolveArticle(slug: string): Promise<ArticleView | null> {
  const post = await getPostBySlug(slug).catch(() => null);
  if (post) {
    return {
      title: post.title,
      description: post.meta_description,
      keywords: post.meta_keywords,
      dateLabel: post.published_at,
      heroImage: post.hero_image_url,
      heroAlt: post.hero_image_alt,
      contentHtml: sanitizeArticle(post.content_html),
      infographic: post.infographic_image_url,
      jsonLd: faqJsonLd(post.faq_schema_json),
      lang: post.language_code ?? "en",
    };
  }

  const soro = await getSoroArticleBySlug(slug);
  if (soro) {
    return {
      title: soro.article.title,
      description: soro.article.excerpt,
      keywords: null,
      dateLabel: soro.article.date,
      heroImage: soro.article.image,
      heroAlt: soro.article.title,
      contentHtml: sanitizeArticle(soro.content),
      infographic: null,
      jsonLd: null,
      lang: "en",
    };
  }

  return null;
}

export async function generateMetadata({
  params,
}: {
  params: Params;
}): Promise<Metadata> {
  const { slug } = await params;
  const article = await resolveArticle(slug);
  if (!article) {
    return { title: "Not found — avai" };
  }
  return {
    title: `${article.title} — avai`,
    description: article.description ?? undefined,
    keywords: article.keywords ?? undefined,
    openGraph: {
      title: article.title,
      description: article.description ?? undefined,
      type: "article",
      images: article.heroImage ? [article.heroImage] : undefined,
    },
  };
}

export default async function BlogPost({ params }: { params: Params }) {
  const { slug } = await params;
  const article = await resolveArticle(slug);
  if (!article) {
    notFound();
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-16" lang={article.lang}>
      {article.jsonLd ? (
        <script
          type="application/ld+json"
          // eslint-disable-next-line react/no-danger
          dangerouslySetInnerHTML={{ __html: article.jsonLd }}
        />
      ) : null}
      <Link
        href="/blog"
        className="text-sm text-slate-400 hover:text-slate-200 transition"
      >
        ← Blog
      </Link>
      <article className="mt-4">
        <h1 className="text-3xl font-bold leading-tight text-slate-100">
          {article.title}
        </h1>
        {article.dateLabel ? (
          <p className="mt-2 text-sm text-slate-500">{article.dateLabel}</p>
        ) : null}
        {article.heroImage ? (
          <Link href="/" className="mt-6 block" aria-label="Go to homepage">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              className="w-full rounded-lg"
              src={article.heroImage}
              alt={article.heroAlt ?? article.title}
            />
          </Link>
        ) : null}
        <div className="mt-6">
          <ArticleBody html={article.contentHtml} />
        </div>
        {article.infographic ? (
          <Link href="/" className="mt-8 block" aria-label="Go to homepage">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              className="w-full rounded-lg"
              src={article.infographic}
              alt={`${article.title} infographic`}
            />
          </Link>
        ) : null}
      </article>
    </main>
  );
}
