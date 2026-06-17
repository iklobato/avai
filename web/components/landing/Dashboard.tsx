const SHOTS = [
  "finding-detail.png",
  "network-flows.png",
  "network-flows-enriched.png",
  "findings-collectors-runs.png",
];

export function Dashboard() {
  return (
    <section id="dashboard" className="mx-auto max-w-6xl px-6 py-16">
      <h2 className="text-2xl font-bold text-slate-100 sm:text-3xl">
        One simple web page.
      </h2>
      <p className="mt-2 max-w-2xl text-slate-400">
        Open the dashboard and read your computer&apos;s health at a glance —
        findings, network, and posture, all in one place.
      </p>
      <div className="card mt-8 overflow-hidden p-2">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/assets/dashboard-overview.png"
          alt="avai dashboard overview"
          className="w-full rounded-lg"
        />
      </div>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        {SHOTS.map((s) => (
          <div key={s} className="card overflow-hidden p-2">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`/assets/${s}`}
              alt={s.replace(/[-.]/g, " ")}
              className="w-full rounded-lg"
            />
          </div>
        ))}
      </div>
      <div className="card mt-4 overflow-hidden p-2">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/assets/dashboard-host.png"
          alt="avai dashboard host view"
          className="w-full rounded-lg"
        />
      </div>
    </section>
  );
}
