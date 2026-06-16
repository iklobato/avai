import Link from "next/link";
import { listFeed } from "@/lib/feed";

// Native latest-articles feed (replaces the old third-party Soro script embed).
// Pulls the newest posts from BOTH providers — our AutoSEO posts in Postgres
// and Soro's hosted articles — merged newest-first.
export async function BlogFeed() {
  let posts: Awaited<ReturnType<typeof listFeed>> = [];
  try {
    posts = await listFeed(3);
  } catch {
    posts = [];
  }

  return (
    <section id="blog" className="mx-auto max-w-6xl px-6 py-16">
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 sm:text-3xl">
            From the blog.
          </h2>
          <p className="mt-2 max-w-2xl text-slate-400">
            Notes on what avai checks, why it matters, and how to read your
            results.
          </p>
        </div>
        <Link href="/blog" className="text-sm text-accent hover:underline">
          All posts →
        </Link>
      </div>
      {posts.length > 0 ? (
        <div className="mt-8 grid gap-4 md:grid-cols-3">
          {posts.map((post) => (
            <Link
              key={`${post.source}:${post.slug}`}
              href={`/blog/${post.slug}`}
              className="card p-5"
            >
              <h3 className="font-semibold text-slate-100">{post.title}</h3>
              {post.excerpt ? (
                <p className="mt-2 text-sm text-slate-400">{post.excerpt}</p>
              ) : null}
            </Link>
          ))}
        </div>
      ) : null}
    </section>
  );
}
