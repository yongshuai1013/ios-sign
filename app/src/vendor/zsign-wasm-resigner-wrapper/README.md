# Vendored `@lbr77/zsign-wasm-resigner-wrapper@0.1.5`

Verbatim copy of the npm package's `dist/` + `npm/` (minus sourcemaps),
preserving their relative layout (`dist/browser.js` imports
`../npm/browser.mjs`, which imports `../dist/zsign-wasm.min.js?url`).

Source: https://github.com/lbr77/zsign-wasm-resigner-wrapper

Why vendored: the project no longer depends on lbr77's npm/GitHub
remaining available at install time. This package provides
`createResigner()` (the zsign WASM signer) used by the vendored
`src/vendor/altsign.js`.

Wiring:

- `app/vite.config.ts` aliases `@lbr77/zsign-wasm-resigner-wrapper`
  to `src/vendor/zsign-wasm-resigner-wrapper/dist/browser.js` (the
  package's own `browser` export condition).
- `app/tsconfig.json` `paths` maps the specifier to `dist/browser.d.ts`
  for type checking.

External runtime dependency: `jszip` (bare import in `npm/browser.mjs`),
declared as a direct dependency in `app/package.json`.
