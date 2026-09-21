// Worker bindings for sideimpactor-backend.
// Run `bun run cf-typegen` (wrangler types) to regenerate this file after
// changing wrangler.jsonc.

interface Env {
  /** Static frontend assets (../app/dist), SPA fallback to index.html. */
  ASSETS: Fetcher;
  /** Optional: SHA-256 hex of the access token required as ?token= on /wisp/. */
  ACCESS_TOKEN_HASH?: string;
  /** Optional: plaintext access token; its SHA-256 hex is used as the expected token. */
  ACCESS_PASSWORD?: string;
}
