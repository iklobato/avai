import { Pool, type PoolConfig } from "pg";

// Single process-wide pool, stashed on globalThis so Next dev's hot-reload
// doesn't leak a new pool on every change.
declare global {
  // eslint-disable-next-line no-var
  var __avaiPgPool: Pool | undefined;
}

function isLocal(connectionString: string): boolean {
  return /@(localhost|127\.0\.0\.1)[:/]/.test(connectionString);
}

function buildConfig(): PoolConfig {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not set");
  }
  const config: PoolConfig = { connectionString, max: 5 };
  // Managed Postgres requires TLS; local dev usually doesn't. pg does not
  // honour sslmode from the URL, so configure ssl explicitly. DATABASE_SSL
  // forces the decision ("disable"/"require") for non-localhost hosts that
  // still don't use TLS (e.g. a Docker host bridge in local testing).
  const sslMode = process.env.DATABASE_SSL;
  const useSsl =
    sslMode === "require" ||
    (sslMode !== "disable" && !isLocal(connectionString));
  if (useSsl) {
    const ca = process.env.DATABASE_CA_CERT;
    config.ssl = ca
      ? { ca, rejectUnauthorized: true }
      : { rejectUnauthorized: false };
  }
  return config;
}

export function getPool(): Pool {
  if (!global.__avaiPgPool) {
    global.__avaiPgPool = new Pool(buildConfig());
  }
  return global.__avaiPgPool;
}

export async function query<T = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<T[]> {
  const result = await getPool().query(text, params);
  return result.rows as T[];
}

// Idempotent schema bootstrap. Creates ONLY the autoseo_blog_posts table; it
// never touches any other table/database in the shared cluster. Safe to call
// repeatedly (guarded so it runs at most once per process).
const CREATE_TABLE = `
CREATE TABLE IF NOT EXISTS autoseo_blog_posts (
  id                    BIGSERIAL PRIMARY KEY,
  autoseo_id            BIGINT NOT NULL UNIQUE,
  event                 TEXT,
  title                 TEXT NOT NULL DEFAULT '',
  slug                  TEXT NOT NULL,
  published_url         TEXT,
  meta_description      TEXT,
  content_html          TEXT,
  content_markdown      TEXT,
  hero_image_url        TEXT,
  hero_image_alt        TEXT,
  infographic_image_url TEXT,
  keywords_json         JSONB,
  meta_keywords         TEXT,
  faq_schema_json       JSONB,
  language_code         TEXT,
  status                TEXT,
  published_at          TEXT,
  updated_at            TEXT,
  created_at            TEXT,
  received_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autoseo_blog_posts_slug ON autoseo_blog_posts (slug);
`;

let schemaReady: Promise<void> | undefined;

export function ensureSchema(): Promise<void> {
  if (!schemaReady) {
    schemaReady = getPool()
      .query(CREATE_TABLE)
      .then(() => undefined)
      .catch((err) => {
        // Reset so a transient failure can be retried on the next request.
        schemaReady = undefined;
        throw err;
      });
  }
  return schemaReady;
}
