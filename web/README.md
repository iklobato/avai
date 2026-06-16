# avai web

Single Next.js app that serves the marketing landing page (`/`), the blog
(`/blog`, `/blog/[slug]`), and the AutoSEO webhook (`POST /webhooks/autoseo`).
Articles persist in DO Managed Postgres; images are hotlinked from AutoSEO's CDN.

## Environment variables

| Var | Required | Notes |
| --- | --- | --- |
| `AUTOSEO_WEBHOOK_TOKEN` | yes | Bearer + HMAC secret. Endpoint returns 503 until set. Never commit it. |
| `AUTOSEO_SITE_URL` | no | Base URL for returned post URLs. Default `https://www.getavai.com`. |
| `DATABASE_URL` | yes | Postgres connection string. In prod, injected by App Platform from the attached managed-DB component (`${avai-db.DATABASE_URL}`). |
| `DATABASE_CA_CERT` | no | Managed-DB CA cert (PEM). When set, TLS verifies the cert; otherwise the pool uses `rejectUnauthorized:false`. App Platform can inject `${avai-db.CA_CERT}`. |

## Local development

```bash
npm install
# a throwaway local Postgres:
docker run -d --name avai-pg -e POSTGRES_DB=avai -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres:17
export DATABASE_URL=postgres://postgres@localhost:5432/avai
export AUTOSEO_WEBHOOK_TOKEN=dev-token
npm run migrate   # creates the autoseo_blog_posts table
npm run dev       # http://localhost:3000
```

## Deploy

App Platform service built from `web/Dockerfile` (standalone output). See
`landing-page/.do/app.yaml` for the single-service spec with the existing
managed-DB cluster attached.
