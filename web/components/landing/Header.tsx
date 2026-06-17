import Link from "next/link";

const NAV = [
  { href: "#how", label: "How it works" },
  { href: "#what", label: "What it checks" },
  { href: "#features", label: "Features" },
  { href: "#why", label: "Why avai" },
  { href: "#install", label: "Get started" },
  { href: "/blog", label: "Blog" },
  { href: "https://github.com/iklobato/avai", label: "GitHub" },
];

export function Header() {
  return (
    <header className="sticky top-0 z-20 border-b border-white/5 bg-[#0b0d10]/70 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
        <Link href="/" className="flex items-center gap-2">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/assets/logo.png"
            alt="avai"
            width={28}
            height={28}
            className="rounded"
          />
          <span className="font-semibold text-slate-100">avai</span>
          <span className="hidden text-xs text-slate-500 sm:inline">
            host telemetry
          </span>
        </Link>
        <nav className="hidden items-center gap-5 text-sm text-slate-400 md:flex">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="hover:text-slate-100 transition"
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <Link
          href="#install"
          className="rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-medium text-emerald-950 hover:bg-emerald-400 transition"
        >
          Run it
        </Link>
      </div>
    </header>
  );
}
