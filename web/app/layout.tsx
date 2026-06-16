import type { Metadata, Viewport } from "next";
import "./globals.css";

const TITLE = "avai — is anything shady running on your computer?";
const DESCRIPTION =
  "A free, open-source security guard for your computer. avai checks the places malware hides and has an AI explain, in plain English, whether anything is dangerous. Nothing leaves your machine.";

export const metadata: Metadata = {
  metadataBase: new URL("https://getavai.com"),
  title: TITLE,
  description: DESCRIPTION,
  icons: { icon: "/assets/logo.png" },
  openGraph: {
    title: TITLE,
    description:
      "A tiny security guard for your laptop or server. It checks where malware hides and an AI tells you, in plain English, what's safe and what's not.",
    type: "website",
    url: "https://getavai.com",
    images: ["/assets/dashboard-overview.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description:
      "Open-source host telemetry + an LLM threat classifier. One docker run.",
    images: ["/assets/dashboard-overview.png"],
  },
};

export const viewport: Viewport = {
  themeColor: "#0b0d10",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">
        <div className="grid-bg" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
