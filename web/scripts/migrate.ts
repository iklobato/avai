// One-shot schema bootstrap for the avai blog.
//
// Creates ONLY the autoseo_blog_posts table (CREATE TABLE IF NOT EXISTS) in the
// database named by DATABASE_URL. It must be pointed at the dedicated `avai`
// logical database — it never drops or alters anything, but run it only against
// the avai DB, never a shared application database.
//
//   DATABASE_URL=postgres://... npm run migrate

import { ensureSchema, getPool } from "../lib/db";

async function main(): Promise<void> {
  await ensureSchema();
  // eslint-disable-next-line no-console
  console.log("autoseo_blog_posts is ready");
  await getPool().end();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
