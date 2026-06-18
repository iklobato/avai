// Static marketing sections recreated from the original landing page.

function Section({
  id,
  title,
  subtitle,
  children,
}: {
  id?: string;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="mx-auto max-w-6xl px-6 py-16">
      <h2 className="text-2xl font-bold text-slate-100 sm:text-3xl">{title}</h2>
      {subtitle ? (
        <p className="mt-2 max-w-2xl text-slate-400">{subtitle}</p>
      ) : null}
      <div className="mt-8">{children}</div>
    </section>
  );
}

function Card({ title, body }: { title: string; body: string }) {
  return (
    <div className="card p-5">
      <h3 className="font-semibold text-slate-100">{title}</h3>
      <p className="mt-2 text-sm text-slate-400">{body}</p>
    </div>
  );
}

export function ProblemFix() {
  const verdicts = [
    { label: "🔴 dangerous", cls: "text-rose-400" },
    { label: "🟡 worth a look", cls: "text-amber-400" },
    { label: "⚪ not sure", cls: "text-slate-300" },
    { label: "🟢 all good", cls: "text-emerald-400" },
  ];
  return (
    <section className="mx-auto grid max-w-6xl gap-6 px-6 py-16 md:grid-cols-2">
      <div className="card p-6">
        <h2 className="text-xl font-bold text-slate-100">
          You can&apos;t see what your computer is really doing
        </h2>
        <p className="mt-3 text-sm text-slate-400">
          Malware hides in the boring places — startup items, browser
          extensions, background network connections. Logs are noisy and
          unreadable, and antivirus only catches the signatures it already
          knows.
        </p>
        <p className="mt-3 text-sm text-slate-400">
          You&apos;re left guessing whether that process, that connection, that
          extension is fine.
        </p>
      </div>
      <div className="card p-6">
        <h2 className="text-xl font-bold text-slate-100">
          A plain-English answer you can trust
        </h2>
        <p className="mt-3 text-sm text-slate-400">
          avai collects the evidence and an AI security expert reviews it,
          cross-checked against 17 threat-intel sources, and gives every finding
          a verdict you can act on:
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {verdicts.map((v) => (
            <span
              key={v.label}
              className={`rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs ${v.cls}`}
            >
              {v.label}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

export function HowItWorks() {
  const steps = [
    {
      title: "🔎 1 · It looks around",
      body: "Every few minutes avai checks the places malware likes to hide — without sending anything off your machine.",
    },
    {
      title: "🧠 2 · An AI expert reviews it",
      body: "Findings are cross-checked against 17 threat-intel databases and judged by a Claude-class model.",
    },
    {
      title: "📋 3 · You get a simple list",
      body: "A clean web dashboard shows what's safe, what's worth a look, and what's dangerous.",
    },
  ];
  return (
    <Section id="how" title="Three steps, then it runs itself.">
      <div className="grid gap-4 md:grid-cols-3">
        {steps.map((s) => (
          <Card key={s.title} title={s.title} body={s.body} />
        ))}
      </div>
      <p className="mt-6 text-sm text-slate-500">
        One command sets it up; after that it re-checks on its own.
      </p>
    </Section>
  );
}

export function WhatItChecks() {
  const items = [
    {
      title: "🚀 Programs that start by themselves",
      body: "Launch agents, services, scheduled tasks.",
    },
    {
      title: "🌐 Who your computer is talking to",
      body: "Outbound connections, DNS lookups, listening ports.",
    },
    {
      title: "🧩 Browser extensions",
      body: "Chrome, Firefox, and Chromium-based browsers.",
    },
    {
      title: "🔒 App privacy permissions",
      body: "Camera, mic, disk, and TCC grants on macOS.",
    },
    {
      title: "🔌 USB & Bluetooth devices",
      body: "What's plugged in and paired.",
    },
    {
      title: "📄 Tampered system files",
      body: "Hosts file, integrity, setuid binaries.",
    },
    {
      title: "🛡️ Your security settings",
      body: "FileVault, Gatekeeper, SIP, firewall posture.",
    },
    {
      title: "🔑 Authentication events",
      body: "Logins, sudo, SSH keys, privilege changes.",
    },
    {
      title: "…and 18 more checks",
      body: "Running processes, open ports, installed apps, kernel extensions, quarantined downloads, MDM profiles, Wi-Fi security, drive mounts, and more.",
    },
  ];
  return (
    <Section id="what" title="All the places trouble hides.">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((i) => (
          <Card key={i.title} title={i.title} body={i.body} />
        ))}
      </div>
    </Section>
  );
}

const INTEL_SOURCES = [
  "VirusTotal",
  "MalwareBazaar",
  "URLhaus",
  "ThreatFox",
  "Feodo Tracker",
  "AbuseIPDB",
  "GreyNoise",
  "Shodan InternetDB",
  "CISA KEV",
  "NVD",
  "OSV",
  "GitHub Advisory",
  "CIRCL hashlookup",
  "crt.sh",
  "PhishTank",
  "Safe Browsing",
  "endoflife.date",
];

export function Features() {
  const collectors = [
    {
      title: "⚙️ Processes & execution",
      body: "Running processes, exec events, command lines.",
    },
    {
      title: "🌐 Network",
      body: "Connections, flows, DNS, listening ports, interfaces.",
    },
    {
      title: "📌 Persistence",
      body: "Launch items, scheduled tasks, login items.",
    },
    {
      title: "🔑 Access & identity",
      body: "Auth events, SSH keys, privilege config.",
    },
    {
      title: "🛡️ Integrity & posture",
      body: "System integrity, file integrity, security settings.",
    },
    {
      title: "🔌 Hardware & browser",
      body: "USB, Bluetooth, Wi-Fi, browser extensions.",
    },
    {
      title: "🧬 YARA file scanning",
      body: "On-disk binaries matched against thousands of malware rules.",
    },
  ];
  const capabilities = [
    "One `docker run`",
    "No SIEM · no agent · no cloud",
    "Dedup by content hash",
    "Read-only dashboard",
    "Just a SQLite file",
    "macOS & Linux",
    "Native install",
    "Open source · MIT",
  ];
  return (
    <Section
      id="features"
      title="Everything avai watches — and does."
      subtitle="26 collectors on macOS (21 on Linux), 17 threat-intel sources, and a Claude-class model that turns it all into plain-English verdicts."
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {collectors.map((c) => (
          <Card key={c.title} title={c.title} body={c.body} />
        ))}
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <div className="card p-6">
          <h3 className="font-semibold text-slate-100">
            🛰️ 17 threat-intel sources behind every verdict
          </h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {INTEL_SOURCES.map((s) => (
              <span
                key={s}
                className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-xs text-slate-300"
              >
                {s}
              </span>
            ))}
          </div>
        </div>
        <div className="card p-6">
          <h3 className="font-semibold text-slate-100">🧠 AI verdicts</h3>
          <p className="mt-3 text-sm text-slate-400">
            Each finding is judged dangerous, worth a look, not sure, or all
            good — with a short plain-English reason and remediation you can act
            on.
          </p>
        </div>
      </div>

      <div className="mt-6 card p-6">
        <h3 className="font-semibold text-slate-100">
          🧬 YARA file scanning, built in
        </h3>
        <p className="mt-3 text-sm text-slate-400">
          avai compiles a YARA ruleset from a small bundled set plus optional
          public packs (signature-base, YARA-Forge) — thousands of rules across
          APT, commodity malware, hacktools, webshells and exploits — and scans
          on-disk executables and recently-changed Downloads against them every
          cycle. It&apos;s targeted rather than a full-disk crawl, so it stays
          fast, and the scan runs entirely on your machine — no files leave the
          host.
        </p>
        <p className="mt-3 text-sm text-slate-400">
          The integration&apos;s real payoff: every match flows through the same
          LLM judge as every other finding, so a hit becomes a plain-English
          verdict and remediation — with file path, matched rule, and author —
          instead of a raw rule name you have to interpret. The dashboard&apos;s
          File Scan panel shows the compiled ruleset (rules loaded, sources, top
          categories) alongside the matches, and rule packs are refreshable with{" "}
          <code className="rounded bg-white/5 px-1 py-0.5 text-xs text-slate-300">
            scripts/update_rules.py
          </code>
          .
        </p>
      </div>

      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {capabilities.map((c) => (
          <div key={c} className="card p-4 text-sm text-slate-300">
            {c}
          </div>
        ))}
      </div>
    </Section>
  );
}

export function WhyAvai() {
  const items = [
    {
      title: "✅ Answers, not logs",
      body: "Verdicts in plain English, not a wall of events.",
    },
    {
      title: "📦 Zero infrastructure",
      body: "No SIEM, no agent fleet, no cloud account.",
    },
    {
      title: "🔐 Private by default",
      body: "Telemetry stays on your machine.",
    },
    {
      title: "💸 Cheap to run",
      body: "Free and open source; bring your own LLM key.",
    },
    {
      title: "🔭 EDR breadth, no agent",
      body: "26 collectors of coverage from one command.",
    },
    {
      title: "🖥️ Cross-platform",
      body: "macOS and Linux from the same image.",
    },
    {
      title: "🧰 Open and yours",
      body: "MIT licensed; inspect and extend it.",
    },
    {
      title: "🟢 Safe for production",
      body: "Read-only collection, read-only dashboard.",
    },
    {
      title: "📤 Portable history",
      body: "Everything is just a SQLite file you own.",
    },
  ];
  return (
    <Section
      id="why"
      title="The pros, in plain terms."
      subtitle="What you get for one `docker run`."
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((i) => (
          <Card key={i.title} title={i.title} body={i.body} />
        ))}
      </div>
    </Section>
  );
}

export function AiExpert() {
  const examples = [
    {
      tag: "Auto-start program",
      verdict: "🔴 dangerous",
      cls: "text-rose-400",
      body: "A hidden updater launching from a temp folder with no signature — a common persistence trick.",
    },
    {
      tag: "Browser extension · Chrome",
      verdict: "🟡 worth a look",
      cls: "text-amber-400",
      body: "“Free YouTube Video Downloader” requests broad permissions and isn't from a known publisher.",
    },
    {
      tag: "Internet connection",
      verdict: "🟢 all good",
      cls: "text-emerald-400",
      body: "Spotify talking to its own CDN — expected and benign.",
    },
  ];
  return (
    <section
      id="judge"
      className="mx-auto grid max-w-6xl gap-6 px-6 py-16 md:grid-cols-2"
    >
      <div>
        <h2 className="text-2xl font-bold text-slate-100 sm:text-3xl">
          Like having a security analyst on call 24/7.
        </h2>
        <ul className="mt-5 space-y-2 text-sm text-slate-400">
          <li>• Reads every finding the way an analyst would.</li>
          <li>• Cross-checks hashes, IPs, and domains against 17 sources.</li>
          <li>• Explains the “why”, not just a score.</li>
          <li>• Tells you what to do about it.</li>
          <li>• Re-checks automatically as things change.</li>
        </ul>
      </div>
      <div className="space-y-4">
        {examples.map((e) => (
          <div key={e.tag} className="card p-5">
            <div className="flex items-center justify-between">
              <span className="text-sm text-slate-300">{e.tag}</span>
              <span className={`text-xs ${e.cls}`}>{e.verdict}</span>
            </div>
            <p className="mt-2 text-sm text-slate-400">{e.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export function GetStarted() {
  const options = [
    {
      title: "Docker",
      tag: "recommended",
      body: 'docker run -p 8765:8765 -v "$PWD":/data iklob1/avai',
    },
    { title: "docker compose", tag: "", body: "docker compose up -d" },
    {
      title: "pip (macOS or Linux)",
      tag: "",
      body: "pip install avai-monitor",
    },
  ];
  const recipes = [
    {
      title: "🔑 Turn on the AI verdicts",
      body: "Set your LLM key (the judge ships by default) and run.",
    },
    {
      title: "🖥️ Watch a Linux server, keep it running",
      body: "avai monitor as a service.",
    },
    {
      title: "🍎 Full macOS coverage",
      body: "TCC, Gatekeeper, and auth events.",
    },
    {
      title: "📟 See the alerts without a browser",
      body: "Tail the findings from the CLI.",
    },
    {
      title: "👀 Already have a scan? Just view it",
      body: "avai dashboard --db ./avai.db",
    },
  ];
  return (
    <Section
      id="install"
      title="One command to run it."
      subtitle="One `docker run` — or install natively with pip — then open the dashboard."
    >
      <div className="grid gap-4 md:grid-cols-3">
        {options.map((o) => (
          <div key={o.title} className="card p-5">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-slate-100">{o.title}</h3>
              {o.tag ? (
                <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">
                  {o.tag}
                </span>
              ) : null}
            </div>
            <pre className="mono mt-3 overflow-x-auto text-xs text-slate-300">
              <code>{o.body}</code>
            </pre>
          </div>
        ))}
      </div>
      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {recipes.map((r) => (
          <Card key={r.title} title={r.title} body={r.body} />
        ))}
      </div>
      <a
        href="https://github.com/iklobato/avai#readme"
        className="mt-6 inline-block text-sm text-accent hover:underline"
      >
        Read the full README →
      </a>
    </Section>
  );
}
