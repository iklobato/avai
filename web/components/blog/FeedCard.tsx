import Link from "next/link";
import type { FeedItem } from "@/lib/feed";

export function FeedCard({ item }: { item: FeedItem }) {
  return (
    <li className="card p-5">
      <div className="flex items-center gap-2">
        <Link
          href={`/blog/${item.slug}`}
          className="text-lg font-semibold text-slate-100 hover:text-accent transition"
        >
          {item.title}
        </Link>
        {item.dateLabel ? (
          <span className="text-xs text-slate-500">· {item.dateLabel}</span>
        ) : null}
      </div>
      {item.excerpt ? (
        <p className="mt-1 text-sm text-slate-400">{item.excerpt}</p>
      ) : null}
    </li>
  );
}
