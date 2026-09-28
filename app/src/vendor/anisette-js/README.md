# Vendored `@lbr77/anisette-js@0.1.3`

Verbatim copy of the npm package's `dist/` (minus sourcemaps).

Source: https://github.com/lbr77/anisette-js

Why vendored: the project no longer depends on lbr77's npm/GitHub
remaining available at install time. The module graph is byte-identical
to the published package, so bundling behavior is unchanged.

Wiring:

- `app/vite.config.ts` aliases `@lbr77/anisette-js` to
  `src/vendor/anisette-js/browser.js` (the package's own `browser`
  export condition).
- `app/tsconfig.json` `paths` maps the specifier to `browser.d.ts`
  for type checking.

Note: the WASM binary itself is NOT loaded from here. The app loads
`/assets/anisette_rs.js` + `/assets/anisette_rs.wasm` (public/assets/)
directly with its own `locateFile` (see `src/anisette-service.ts`),
exactly as before.
