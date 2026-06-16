import Link from "next/link";
import type { Metadata } from "next";
import { PostCard } from "@/components/blog/PostCard";
import { listPosts } from "@/lib/posts";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Blog — avai",
  description:
    "Notes on what avai checks, why it matters, and how to read your results.",
};

export default async function BlogIndex() {
  const posts = await listPosts();
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
      {posts.length === 0 ? (
        <p className="mt-8 text-slate-500">No posts yet.</p>
      ) : (
        <ul className="mt-8 space-y-4">
          {posts.map((post) => (
            <PostCard key={post.id} post={post} />
          ))}
        </ul>
      )}
    </main>
  );
}
