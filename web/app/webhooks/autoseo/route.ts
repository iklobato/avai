import { ensureSchema } from "@/lib/db";
import { type AutoseoPayload, upsertPost } from "@/lib/posts";
import { checkBearer, checkSignature } from "@/lib/webhook-auth";

// Uses node:crypto + pg — must run on the Node.js runtime, never Edge.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TOKEN_ENV = "AUTOSEO_WEBHOOK_TOKEN";
const DEFAULT_SITE_URL = "https://www.getavai.com";

function json(body: unknown, status: number): Response {
  return Response.json(body, { status });
}

function siteUrl(): string {
  return (process.env.AUTOSEO_SITE_URL ?? DEFAULT_SITE_URL).replace(/\/+$/, "");
}

export async function POST(request: Request): Promise<Response> {
  const token = process.env[TOKEN_ENV];
  if (!token) {
    return json({ error: "webhook not configured" }, 503);
  }

  if (!checkBearer(request.headers.get("authorization"), token)) {
    return json({ error: "unauthorized" }, 401);
  }

  // Read the RAW body before parsing so the HMAC matches the exact bytes.
  const raw = await request.text();
  const signature = request.headers.get("x-autoseo-signature");
  if (signature && !checkSignature(raw, signature, token)) {
    return json({ error: "invalid signature" }, 401);
  }

  let payload: AutoseoPayload;
  try {
    const parsed = JSON.parse(raw);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return json({ error: "invalid JSON body" }, 400);
    }
    payload = parsed as AutoseoPayload;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const site = siteUrl();
  const event = payload.event || request.headers.get("x-autoseo-event") || "";
  if (event === "test") {
    return json({ url: `${site}/test` }, 200);
  }

  const autoseoId = Number(payload.id);
  if (!Number.isInteger(autoseoId)) {
    return json({ error: "missing or invalid 'id'" }, 400);
  }
  const slug = (payload.slug ?? "").trim();
  if (!slug) {
    return json({ error: "missing 'slug'" }, 400);
  }

  // Edge boundary: convert any unexpected failure (DB) into a 500 so AutoSEO
  // retries rather than dropping the article.
  try {
    await ensureSchema();
    await upsertPost(payload, autoseoId, slug);
  } catch (err) {
    console.error(
      "autoseo webhook failed to store article id=%s",
      autoseoId,
      err,
    );
    return json({ error: "internal error" }, 500);
  }

  return json({ url: `${site}/blog/${slug}` }, 200);
}
