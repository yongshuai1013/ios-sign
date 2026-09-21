/**
 * Vendored libcurl.js (Emscripten WASM, single-file build).
 *
 * Source: https://github.com/lbr77/libcurl.js `binary/libcurl_full.mjs` (main branch).
 *
 * Why vendored instead of the npm `libcurl.js@0.7.4` package: the npm build's
 * WASM predates the `insecure` fetch option (`request_set_insecure` /
 * `CURLOPT_SSL_VERIFYPEER=0`), so passing `insecure: true` was silently
 * ignored and every Apple API request failed with CURLE_PEER_FAILED_VERIFICATION
 * (error 60) — Apple's API hosts use Apple-issued certificates that are not in
 * the WASM's Mozilla CA bundle. The main-branch build honors `insecure: true`.
 */
export const VENDORED_LIBCURL_VERSION = 'lbr77/libcurl.js@main';
