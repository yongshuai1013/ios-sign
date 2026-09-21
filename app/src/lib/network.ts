/**
 * Apple API HTTP transport.
 *
 * Browsers cannot reach Apple endpoints directly (CORS), so all Apple API
 * traffic goes through libcurl-WASM (`libcurl.js`) tunneled over a WISP
 * WebSocket proxy — the same approach the original SideImpactor used.
 * The WISP URL is configurable (settings on the login page); when libcurl
 * cannot start, or WISP is disabled, requests fall back to plain `fetch`
 * with a clear log line so failures stay diagnosable.
 */
import { Fetch } from 'altsign.js';
import type { HttpClient } from '@lbr77/anisette-js';
import { loadText, saveText } from './storage';

export const FALLBACK_WISP_URL = 'wss://sideload.nvme0n1p.dev/wisp/';

/**
 * Default WISP URL follows the original SideImpactor design: the proxy lives
 * on the same host that serves this frontend (`<proto>//<host>/wisp/`), so a
 * self-hosted deployment talks to its own backend instead of a third party.
 * Falls back to the public proxy only when `location` is unavailable.
 */
export function defaultWispUrl(): string {
  try {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${location.host}/wisp/`;
  } catch {
    return FALLBACK_WISP_URL;
  }
}
const WISP_URL_STORAGE_KEY = 'webmuxd:wisp-url';
const WISP_ENABLED_STORAGE_KEY = 'webmuxd:wisp-enabled';

export function getWispUrl(): string {
  const stored = loadText(WISP_URL_STORAGE_KEY);
  return stored && stored.trim().length > 0 ? stored.trim() : defaultWispUrl();
}

export function setWispUrl(url: string): void {
  saveText(WISP_URL_STORAGE_KEY, url.trim());
  // The libcurl instance pins its websocket URL at init; force re-init.
  libcurlPromise = null;
}

export function isWispEnabled(): boolean {
  return loadText(WISP_ENABLED_STORAGE_KEY) !== '0';
}

export function setWispEnabled(enabled: boolean): void {
  saveText(WISP_ENABLED_STORAGE_KEY, enabled ? '1' : '0');
  libcurlPromise = null;
}

export interface LibcurlApi {
  fetch(
    input: string,
    init?: {
      method?: string;
      headers?: Record<string, string>;
      body?: string;
      insecure?: boolean;
    },
  ): Promise<Response>;
  load_wasm(url?: string): Promise<void>;
  set_websocket(url: string): void;
}

let libcurlPromise: Promise<LibcurlApi | null> | null = null;

/**
 * Loads the vendored `libcurl_full.mjs` (WASM embedded, single-file build from
 * lbr77/libcurl.js main — the npm 0.7.4 build silently ignores `insecure`),
 * points it at the configured WISP proxy and initializes it. Resolves to
 * `null` when unavailable so callers can fall back to direct `fetch`.
 */
export function ensureLibcurl(log?: (message: string) => void): Promise<LibcurlApi | null> {
  if (!libcurlPromise) {
    libcurlPromise = (async (): Promise<LibcurlApi | null> => {
      if (!isWispEnabled()) {
        log?.('network: WISP disabled by settings, using direct fetch');
        return null;
      }
      const wispUrl = getWispUrl();
      try {
        const mod = (await import('../vendor/libcurl_full.mjs')) as unknown as {
          libcurl: LibcurlApi;
        };
        const api = mod.libcurl;
        api.set_websocket(wispUrl);
        await api.load_wasm();
        log?.(`network: libcurl WASM ready (WISP ${wispUrl})`);
        return api;
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        log?.(`network: libcurl unavailable (${detail}); falling back to direct fetch`);
        return null;
      }
    })();
  }
  return libcurlPromise;
}

interface AppleHttpResponse {
  status: number;
  ok: boolean;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** Hosts whose Apple API traffic goes through the Worker's reverse proxy. */
const APPLE_PROXY_HOST_RE = /^(gsa|developerservices2|auth\.itunes|buy\.itunes|init\.itunes|p\d+-buy\.itunes)\.apple\.com$/i;

function toBufferedResponse(
  status: number,
  ok: boolean,
  buf: Uint8Array,
  log: ((message: string) => void) | undefined,
  label: string,
  method: string,
  url: string,
): AppleHttpResponse {
  if (log && /apple\.com/.test(url)) {
    const preview = new TextDecoder().decode(buf.slice(0, 400));
    log?.(`network: ${method} ${url} -> ${status} [${label}] :: ${preview}`);
  }
  const bytes = buf.slice().buffer as ArrayBuffer;
  return {
    status,
    ok,
    text: async () => new TextDecoder().decode(buf),
    arrayBuffer: async () => bytes.slice(0),
  };
}

/**
 * Apple API via the Worker's same-origin reverse proxy (`/apple-proxy/`).
 *
 * The WISP path (Mbed TLS inside libcurl WASM over cloudflare:sockets) gets
 * HTTP 503 from gsa.apple.com/grandslam/GsService2 — Apple rejects that egress
 * path — while a plain Workers fetch() to the same URL returns 200. The proxy
 * forwards to the same Apple hosts with the Worker's normal TLS stack.
 *
 * Since early September 2026, Apple's GSA edge rejects requests whose
 * `X-Mme-Client-Info` contains `com.apple.dt.Xcode` with an HTML 503
 * (see nab138/isideload#11, altstoreio/AltStore#1790). The fix is to report
 * the client as `com.apple.akd` (the daemon that actually performs these
 * requests on macOS) instead of Xcode.
 */
const GSA_AUTHKIT_USER_AGENT = 'AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)';

async function proxyFetch(
  url: string,
  options: { method: string; headers: Record<string, string>; body?: string },
  log?: (message: string) => void,
): Promise<AppleHttpResponse> {
  const u = new URL(url);
  const proxyUrl = `/apple-proxy/${u.host}${u.pathname}${u.search}`;
  const headers = { ...options.headers };
  if (u.hostname === 'gsa.apple.com') {
    // Replace blocked Xcode client identifier with akd (nab138/isideload#11).
    // anisette-js WASM hardcodes `com.apple.dt.Xcode`, which Apple's GSA edge
    // rejects with 503 since early September 2026. Applies to all GSA hosts.
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === 'x-mme-client-info' && headers[key].includes('com.apple.dt.Xcode')) {
        headers[key] = headers[key].replace(/com\.apple\.dt\.Xcode\/[\d.]+/, 'com.apple.akd/1.0');
        break;
      }
    }
    // Modern AuthKit User-Agent for SRP (rileytestut/AltSign#47). Only for
    // /grandslam/GsService2 — the 2FA endpoints (/auth/verify/*) must keep
    // `User-Agent: Xcode` as AltSign's makeTwoFactorCodeRequest does.
    if (u.pathname.startsWith('/grandslam/GsService2')) {
      headers['User-Agent'] = GSA_AUTHKIT_USER_AGENT;
    }
    // Fix 2FA headers: altsign.js sends `Accept: text/x-xml-plist` for the
    // trusteddevice trigger, but Apple's endpoint expects
    // `Accept: application/x-buddyml` (see AltSign's makeTwoFactorCodeRequest).
    // With the wrong Accept, Apple returns an HTML page instead of triggering
    // the 2FA push, so the code the user enters is never valid for this login.
    if (u.pathname === '/auth/verify/trusteddevice') {
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === 'accept') {
          headers[key] = 'application/x-buddyml';
          break;
        }
      }
      // Debug: log non-sensitive 2FA request headers
      if (log) {
        const keys = Object.keys(headers).map((k) => k.toLowerCase()).sort();
        const mme = headers['X-MMe-Client-Info'] || headers['x-mme-client-info'] || '';
        log(`2fa-debug: trusteddevice headers keys=[${keys.join(',')}] accept=${headers['Accept'] || headers['accept']} has-identity-token=${'X-Apple-Identity-Token' in headers} mme-info=${mme.slice(0, 60)}`);
      }
    }
  }
  const res = await fetch(proxyUrl, {
    method: options.method,
    headers,
    body: options.body,
  });
  const buf = new Uint8Array(await res.arrayBuffer());
  return toBufferedResponse(res.status, res.ok, buf, log, 'proxy', options.method, url);
}

async function routedFetch(
  url: string,
  options: { method: string; headers: Record<string, string>; body?: string },
  log?: (message: string) => void,
): Promise<AppleHttpResponse> {
  // Prefer the reverse proxy for Apple API hosts; fall back to libcurl/WISP
  // only if the proxy itself is unreachable.
  try {
    if (APPLE_PROXY_HOST_RE.test(new URL(url).hostname)) {
      return await proxyFetch(url, options, log);
    }
  } catch (error) {
    log?.(`network: proxy failed (${error}), falling back to libcurl/WISP`);
  }
  const api = await ensureLibcurl(log);
  if (api) {
    // NOTE: `insecure` disables TLS certificate verification inside the
    // libcurl WASM (CURLOPT_SSL_VERIFYPEER/VERIFYHOST = 0). This matches the
    // original SideImpactor: Apple's API hosts (gsa.apple.com,
    // developerservices2.apple.com) serve certificates issued by Apple's own
    // CA, which is not in the Mozilla CA bundle that the WASM TLS stack
    // verifies against — verification always fails with
    // CURLE_PEER_FAILED_VERIFICATION (error 60) otherwise. Traffic is still
    // TLS-encrypted; only the chain-of-trust check is skipped.
    // IMPORTANT: this requires the vendored main-branch libcurl_full.mjs —
    // the npm 0.7.4 build silently ignores `insecure` (verified from source).
    const raw = await api.fetch(url, {
      method: options.method,
      headers: options.headers,
      body: options.body,
      insecure: true,
    });
    // Buffer the body once: libcurl's Response body can only be consumed once,
    // and we want both a diagnostic preview and the real body for the caller.
    // (Apple responses never contain the password — GSA uses SRP.)
    const buf = new Uint8Array(await raw.arrayBuffer());
    return toBufferedResponse(raw.status, raw.ok, buf, log, 'libcurl', options.method, url);
  }
  const res = await fetch(url, {
    method: options.method,
    headers: options.headers,
    body: options.body,
  });
  return {
    status: res.status,
    ok: res.ok,
    text: () => res.text(),
    arrayBuffer: () => res.arrayBuffer(),
  };
}

/** `altsign.js` Fetch backed by libcurl/WISP with direct-fetch fallback. */
export function createAppleFetch(log?: (message: string) => void): Fetch {
  return new Fetch(
    async () => {
      await ensureLibcurl(log);
    },
    async (url: string, options: { method: string; headers: Record<string, string>; body?: string }) => {
      return routedFetch(url, options, log);
    },
  );
}

/** `@lbr77/anisette-js` HttpClient backed by the same routed transport. */
export function createAnisetteHttpClient(log?: (message: string) => void): HttpClient {
  const toBytes = async (res: AppleHttpResponse): Promise<Uint8Array> => {
    if (!res.ok) {
      throw new Error(`anisette http request failed with status ${res.status}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  };
  return {
    get: async (url: string, headers: Record<string, string>) =>
      toBytes(await routedFetch(url, { method: 'GET', headers }, log)),
    post: async (url: string, body: string, headers: Record<string, string>) =>
      toBytes(await routedFetch(url, { method: 'POST', headers, body }, log)),
  };
}
