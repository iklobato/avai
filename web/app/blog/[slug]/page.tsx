import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ArticleBody } from "@/components/blog/ArticleBody";
import { faqJsonLd } from "@/lib/faq";
import { getPostBySlug } from "@/lib/posts";
import { sanitizeArticle } from "@/lib/sanitize";

export const dynamic = "force-dynamic";

type Params = Promise<{ slug: string }>;

export async function generateMetadata({
  params,
}: {
  params: Params;
}): Promise<Metadata> {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) {
    return { title: "Not found — avai" };
  }
  return {
    title: `${post.title} — avai`,
    description: post.meta_description ?? undefined,
    keywords: post.meta_keywords ?? undefined,
    openGraph: {
      title: post.title,
      description: post.meta_description ?? undefined,
      type: "article",
      images: post.hero_image_url ? [post.hero_image_url] : undefined,
    },
  };
}

export default async function BlogPost({ params }: { params: Params }) {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) {
    notFound();
  }

  const content = sanitizeArticle(post.content_html);
  const hero = post.hero_image_url;
  const infographic = post.infographic_image_url;
  const jsonLd = faqJsonLd(post.faq_schema_json);

  return (
    <main
      className="mx-auto max-w-3xl px-6 py-16"
      lang={post.language_code ?? "en"}
    >
      {jsonLd ? (
        <script
          type="application/ld+json"
          // eslint-disable-next-line react/no-danger
          dangerouslySetInnerHTML={{ __html: jsonLd }}
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
          {post.title}
        </h1>
        {post.published_at ? (
          <p className="mt-2 text-sm text-slate-500">{post.published_at}</p>
        ) : null}
        {hero ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            className="mt-6 w-full rounded-lg"
            src={hero}
            alt={post.hero_image_alt ?? post.title}
          />
        ) : null}
        <div className="mt-6">
          <ArticleBody html={content} />
        </div>
        {infographic ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            className="mt-8 w-full rounded-lg"
            src={infographic}
            alt={`${post.title} infographic`}
          />
        ) : null}
      </article>
    </main>
  );
}
