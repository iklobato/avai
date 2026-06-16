import Link from "next/link";
import type { BlogPost } from "@/lib/posts";

export function PostCard({ post }: { post: BlogPost }) {
  return (
    <li className="card p-5">
      <Link
        href={`/blog/${post.slug}`}
        className="text-lg font-semibold text-slate-100 hover:text-accent transition"
      >
        {post.title}
      </Link>
      {post.published_at ? (
        <span className="ml-2 text-xs text-slate-500">
          · {post.published_at}
        </span>
      ) : null}
      {post.meta_description ? (
        <p className="mt-1 text-sm text-slate-400">{post.meta_description}</p>
      ) : null}
    </li>
  );
}
