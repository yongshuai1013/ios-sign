/**
 * postinstall patch: make @mercuryworkshop/wisp-js loadable in Cloudflare Workers.
 *
 * Root cause: wisp-js's `src/server/net.mjs` defines
 * `is_node = (typeof process !== "undefined")`, and Workers ships a `process`
 * shim, so `is_node` is true there. `src/server/http.mjs` then runs
 * `new compat.WebSocketServer({ noServer: true })` at module scope, but the
 * `ws` package's server cannot be constructed outside Node -> the Worker
 * fails Cloudflare's module validation on deploy.
 *
 * This backend never calls `routeRequest()` (the only user of `ws_server`);
 * it drives `ServerConnection` directly, so guarding the construction is safe.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const target = path.join(
  here,
  "..",
  "node_modules",
  "@mercuryworkshop",
  "wisp-js",
  "src",
  "server",
  "http.mjs",
);

const src = readFileSync(target, "utf8");
if (src.includes("sideimpactor patch")) {
  console.log("wisp-js already patched, skipping");
  process.exit(0);
}

const needle = `if (is_node) {
  ws_server = new compat.WebSocketServer({ noServer: true });
}`;
const replacement = `if (is_node) {
  // sideimpactor patch: Cloudflare Workers defines a \`process\` shim, so
  // is_node is true there, but the \`ws\` WebSocketServer cannot be
  // constructed outside Node. Guard it; routeRequest() is Node-only anyway
  // and this backend drives ServerConnection directly.
  try {
    ws_server = new compat.WebSocketServer({ noServer: true });
  } catch {
    ws_server = null;
  }
}`;

if (!src.includes(needle)) {
  throw new Error(
    "wisp-js http.mjs pattern not found; the patch needs updating for this wisp-js version",
  );
}
writeFileSync(target, src.replace(needle, replacement));
console.log("patched wisp-js http.mjs for Workers compatibility");
