export function Footer() {
  return (
    <footer className="border-t border-white/5">
      <div className="mx-auto flex max-w-6xl flex-col items-center gap-4 px-6 py-10 text-center">
        <a
          href="https://www.producthunt.com/products/avai-you-ai-anti-virus-scanner?embed=true&utm_source=badge-featured&utm_medium=badge&utm_campaign=badge-avai-you-ai-anti-virus-scanner"
          target="_blank"
          rel="noopener noreferrer"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1159062&theme=light"
            alt="avai on Product Hunt"
            width={250}
            height={54}
          />
        </a>
        <div className="flex items-center gap-2">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/assets/logo.png"
            alt="avai"
            width={20}
            height={20}
            className="rounded"
          />
          <span className="text-sm text-slate-400">
            avai · MIT · a simple security check-up for your computer
          </span>
        </div>
        <div className="flex gap-4 text-sm text-slate-400">
          <a
            href="https://github.com/iklobato/avai"
            className="hover:text-slate-200 transition"
          >
            GitHub
          </a>
          <a
            href="https://pypi.org/project/avai-monitor/"
            className="hover:text-slate-200 transition"
          >
            PyPI
          </a>
          <a
            href="https://hub.docker.com/r/iklob1/avai"
            className="hover:text-slate-200 transition"
          >
            Docker Hub
          </a>
        </div>
      </div>
    </footer>
  );
}
