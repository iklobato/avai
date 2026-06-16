import { CopyButton } from "./CopyButton";

const STATS = [
  { n: "26", label: "places it checks" },
  { n: "17", label: "expert databases consulted" },
  { n: "every 5 min", label: "automatic re-check" },
  { n: "$0", label: "free & open source" },
];

export function Hero() {
  return (
    <section className="mx-auto max-w-6xl px-6 pt-16 pb-12 text-center">
      <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300">
        <span className="pulse-dot" /> v0.5.0 — open source, MIT licensed
      </span>
      <h1 className="mx-auto mt-6 max-w-3xl text-4xl font-bold leading-tight sm:text-5xl">
        <span className="grad-text">
          Is anything shady running on your computer?
        </span>
      </h1>
      <p className="mx-auto mt-5 max-w-2xl text-lg text-slate-300">
        avai is a tiny security guard for your computer. It quietly checks the
        places malware likes to hide, then has an AI security expert look at
        what it found and tell you — in plain English — whether anything is
        dangerous.
      </p>
      <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-500">
        Think of it as a health check-up for your laptop or server. Nothing
        leaves your machine.
      </p>

      <div className="mx-auto mt-8 max-w-xl">
        <div className="card flex items-start justify-between gap-3 p-4 text-left">
          <pre className="mono overflow-x-auto text-sm text-slate-200">
            <code>{`$ pip install 'avai-monitor[judge]'
$ sudo avai monitor &
$ avai dashboard`}</code>
          </pre>
          <CopyButton />
        </div>
        <a
          href="https://github.com/iklobato/avai"
          className="mt-3 inline-block text-sm text-accent hover:underline"
        >
          or read the source →
        </a>
      </div>

      <div className="mx-auto mt-10 grid max-w-4xl grid-cols-2 gap-3 sm:grid-cols-4">
        {STATS.map((s) => (
          <div key={s.label} className="card p-4">
            <div className="text-xl font-semibold text-slate-100">{s.n}</div>
            <div className="mt-1 text-xs text-slate-400">{s.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
