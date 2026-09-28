# Vendored `@mercuryworkshop/wisp-js@0.5.0` (server subset)

Verbatim copy of the package's ESM `src/` files needed by the
`@mercuryworkshop/wisp-js/server` entrypoint:

- `src/entrypoints/server.mjs`
- `src/server/*.mjs`
- `src/packet.mjs`, `src/logging.mjs`, `src/extensions.mjs`,
  `src/compat.mjs`, `src/websocket.mjs`

Source: https://github.com/MercuryWorkshop/wisp-js

Why vendored: the project no longer depends on MercuryWorkshop's
npm/GitHub remaining available at install time.

The sideimpactor Workers patch (previously applied by
`backend/scripts/patch-wisp-js.mjs` at postinstall) is baked in:
`src/server/http.mjs` guards the `ws` WebSocketServer construction,
which cannot run on Cloudflare Workers. The postinstall script has
been removed.

`src/server/filter.mjs` still imports the `ipaddr.js` npm package
(whitequark/ipaddr.js, widely used and stable); it is declared as a
direct dependency in `backend/package.json`.
