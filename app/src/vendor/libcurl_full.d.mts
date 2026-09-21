/**
 * Type shim for the vendored `libcurl_full.mjs` Emscripten entry module
 * (no upstream TypeScript types are shipped).
 */
export declare const libcurl: {
  fetch(
    input: string,
    init?: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
      /** Disables TLS certificate verification (CURLOPT_SSL_VERIFYPEER/VERIFYHOST=0). */
      insecure?: boolean;
    },
  ): Promise<Response>;
  load_wasm(url?: string): Promise<void>;
  set_websocket(url: string): void;
};
