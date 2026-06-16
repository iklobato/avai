# AutoSEO article webhook

Receives article deliveries from [AutoSEO](https://getautoseo.com) and publishes
them as blog posts served by the dashboard app.

## Production (DigitalOcean App Platform)

The Flask app runs as the `webhook` service component of the `avai-landing`
app, path-routed behind getavai.com (see `landing-page/.do/app.yaml`):

- Webhook:  `https://getavai.com/webhooks/autoseo`
- Articles: `https://getavai.com/blog` and `https://getavai.com/blog/<slug>`

The marketing static site keeps serving `/`. Storage is **ephemeral** — posts
and downloaded images reset on every redeploy.

## Endpoint

`POST /webhooks/autoseo`

- Verifies `Authorization: Bearer <token>` against `AUTOSEO_WEBHOOK_TOKEN`
  (HTTP 401 if missing/wrong).
- If `X-AutoSEO-Signature` is present, verifies it is the HMAC-SHA256 hex digest
  of the **raw** request body keyed by the same token (HTTP 401 if it doesn't
  match). A bare hex digest or a `sha256=<hex>` form is accepted.
- `event: "test"` → returns `{"url": "<site>/test"}` without storing anything.
- `article.published` / `article.updated` → **upserts** on the AutoSEO `id`, so
  duplicate deliveries and later edits update the same post instead of creating
  duplicates.
- Downloads `heroImageUrl` / `infographicImageUrl` to `static/blog/<id>/` and
  serves them from `/static/...` (no hot-linking). Image fetches are SSRF-guarded
  (public-IP-only, redirect-revalidated, 10 MB cap, image content-type, 10 s
  timeout); a failed download keeps the original URL and the request still
  succeeds.
- Returns `200 {"url": "<site>/blog/<slug>"}` on success, or `5xx` so AutoSEO
  retries (`503` when the server token is unset, `500` on a storage error).

Posts render at `GET /blog/<slug>` (and `GET /blog` lists them). Article HTML is
sanitised with bleach before rendering to prevent stored XSS.

## Configuration (environment)

Set these in your **gitignored** `.env` — never commit the token:

```
AUTOSEO_WEBHOOK_TOKEN=aseo_wh_b4f9779f67f1f5297587c26ea9342a4f
AUTOSEO_SITE_URL=https://mysite.com
```

- `AUTOSEO_WEBHOOK_TOKEN` (required) — shared Bearer/HMAC secret. The endpoint
  fails closed (HTTP 503) when unset, mirroring the dashboard's existing
  `AVAI_CONTROL_TOKEN` gate.
- `AUTOSEO_SITE_URL` (optional) — public base URL used to build the returned post
  URL. Defaults to `http://127.0.0.1:8765`.

## Schema

A single new table, `autoseo_blog_posts`, is created with
`CREATE TABLE IF NOT EXISTS` semantics. No existing table is altered or dropped.
