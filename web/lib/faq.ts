import type { BlogPost } from "./posts";

// schema.org FAQPage JSON-LD from stored FAQ pairs, or null when absent/empty.
export function faqJsonLd(faq: BlogPost["faq_schema_json"]): string | null {
  if (!Array.isArray(faq) || faq.length === 0) {
    return null;
  }
  const mainEntity = faq
    .filter(
      (p): p is { question?: string; answer?: string } =>
        typeof p === "object" && p !== null,
    )
    .map((p) => ({
      "@type": "Question",
      name: p.question ?? "",
      acceptedAnswer: { "@type": "Answer", text: p.answer ?? "" },
    }));
  return JSON.stringify({
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity,
  });
}
