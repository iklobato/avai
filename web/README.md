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

App Platform service built from `web/Dockerfile` (standalone output). The
single-service spec is `web/.do/app.yaml` (app `avai-landing`,
getavai.com). Apply with a local copy that has the real secrets:

```bash
doctl apps update b7308f12-6cd4-4c0f-b248-e82f558b40f5 --spec <local-copy>
```

### One-time database setup (managed Postgres cluster `db-postgresql-nyc3-86715`)

The app uses an isolated `avai` database + `avai_app` user in the shared
cluster. Because Postgres 15+ locks down the `public` schema, the app user must
be granted privileges once (run as `doadmin` against the `avai` db):

```sql
GRANT USAGE, CREATE ON SCHEMA public TO avai_app;
GRANT ALL ON ALL TABLES IN SCHEMA public TO avai_app;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO avai_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO avai_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO avai_app;
```

The table itself is auto-created on first DB access (`ensureSchema()`), so no
migration step is required after the grant. The app is registered as a trusted
source on the cluster.

### SSL note

`DATABASE_URL` must NOT contain `?sslmode=` — node-postgres 8.13+ treats
`sslmode=require` as `verify-full` and rejects the managed DB's self-signed
chain. TLS is driven by `DATABASE_SSL=require` (see `lib/db.ts`).
