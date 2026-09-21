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
    },
  },
  server: {
    // Serve the anisette native libraries from the repo's public dir.
    fs: {
      allow: [__dirname, path.resolve(__dirname, '..')],
    },
  },
});
