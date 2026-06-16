import { createHmac, timingSafeEqual } from "node:crypto";

// Constant-time string compare that tolerates unequal lengths (timingSafeEqual
// throws when buffer lengths differ).
function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

const BEARER_PREFIX = "Bearer ";

export function checkBearer(authHeader: string | null, token: string): boolean {
  if (!authHeader || !authHeader.startsWith(BEARER_PREFIX)) {
    return false;
  }
  return safeEqual(authHeader.slice(BEARER_PREFIX.length).trim(), token);
}

// HMAC-SHA256 of the raw request body, keyed by the shared token. Accepts a
// bare hex digest or a `sha256=<hex>` form.
export function checkSignature(
  rawBody: string,
  signature: string,
  secret: string,
): boolean {
  const expected = createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("hex");
  const provided = signature.startsWith("sha256=")
    ? signature.slice("sha256=".length)
    : signature;
  return safeEqual(expected, provided.trim());
}
