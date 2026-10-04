import path from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  optimizeDeps: {
    // Emscripten/WASM-heavy modules: keep them out of the pre-bundler so
    // their dynamic `import()` / `locateFile` logic keeps working.
    exclude: ['altsign.js', '@lbr77/anisette-js', 'libcurl.js', 'libcurl.js/bundled'],
  },
  resolve: {
    alias: {
      '@pairing': path.resolve(__dirname, '../src/pairing'),
      // Use our vendored altsign.js with fixed 2FA (refresh anisette before
      // /trusteddevice and /validate, like isideload does).
      'altsign.js': path.resolve(__dirname, 'src/vendor/altsign.js'),
      // Vendored @lbr77/anisette-js (see src/vendor/anisette-js/README.md);
      // resolves to the package's own `browser` export condition.
      '@lbr77/anisette-js': path.resolve(__dirname, 'src/vendor/anisette-js/browser.js'),
      // Vendored @lbr77/zsign-wasm-resigner-wrapper (see
      // src/vendor/zsign-wasm-resigner-wrapper/README.md); used by the
      // vendored altsign.js. Resolves to the package's own `browser`
      // export condition.
      '@lbr77/zsign-wasm-resigner-wrapper': path.resolve(
        __dirname,
        'src/vendor/zsign-wasm-resigner-wrapper/dist/browser.js',
      ),
    },
  },
  server: {
    // Serve the anisette native libraries from the repo's public dir.
    fs: {
      allow: [__dirname, path.resolve(__dirname, '..')],
    },
  },
});
