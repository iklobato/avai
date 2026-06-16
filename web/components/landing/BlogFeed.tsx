import Link from "next/link";
import { listPosts } from "@/lib/posts";

// Native latest-articles feed. Replaces the old third-party Soro embed; pulls
// the newest posts straight from our own Postgres.
export async function BlogFeed() {
  let posts: Awaited<ReturnType<typeof listPosts>> = [];
  try {
    posts = await listPosts(3);
  } catch {
    // If the DB is unreachable, the landing page still renders without the feed.
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
              key={post.id}
              href={`/blog/${post.slug}`}
              className="card p-5"
            >
              <h3 className="font-semibold text-slate-100">{post.title}</h3>
              {post.meta_description ? (
                <p className="mt-2 text-sm text-slate-400">
                  {post.meta_description}
                </p>
              ) : null}
            </Link>
          ))}
        </div>
      ) : null}
    </section>
  );
}
