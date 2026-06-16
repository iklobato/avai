import Link from "next/link";
import type { Metadata } from "next";
import { FeedCard } from "@/components/blog/FeedCard";
import { listFeed } from "@/lib/feed";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Blog — avai",
  description:
    "Notes on what avai checks, why it matters, and how to read your results.",
};

export default async function BlogIndex() {
  const items = await listFeed();
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <Link
        href="/"
        className="text-sm text-slate-400 hover:text-slate-200 transition"
      >
        ← avai
      </Link>
      <h1 className="mt-4 text-3xl font-bold text-slate-100">Blog</h1>
      <p className="mt-2 text-slate-400">
        Notes on what avai checks, why it matters, and how to read your results.
      </p>
      {items.length === 0 ? (
        <p className="mt-8 text-slate-500">No posts yet.</p>
      ) : (
        <ul className="mt-8 space-y-4">
          {items.map((item) => (
            <FeedCard key={`${item.source}:${item.slug}`} item={item} />
          ))}
        </ul>
      )}
    </main>
  );
}
