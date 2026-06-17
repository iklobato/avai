"use client";

import { useState } from "react";

const INSTALL = `pip install 'avai-monitor[judge]'
sudo avai monitor &
avai dashboard`;

export function CopyButton() {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(INSTALL);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable (insecure context); fail quietly.
    }
  }

  return (
    <button
      type="button"
      onClick={onCopy}
      className="rounded-md border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300 hover:border-accent/40 hover:text-slate-100 transition"
    >
      {copied ? "copied" : "copy"}
    </button>
  );
}
