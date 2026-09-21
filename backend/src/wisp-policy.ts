/**
 * Pure, testable policy helpers for the WISP worker.
 *
 * These encode the security rules of the proxy:
 *  - only Apple hostnames needed for signing/login may be reached,
 *  - only TCP on port 443 is allowed (no UDP, no other ports),
 *  - no direct IP literals (defense in depth against SSRF; the wisp-js
 *    runtime options additionally reject private/loopback ranges),
 *  - /wisp/ endpoint shape and optional access-token authentication.
 */

/** Apple hosts the sideloading login flow talks to. */
export const APPLE_HOST_PATTERNS: readonly RegExp[] = [
  /^auth\.itunes\.apple\.com$/,
  /^buy\.itunes\.apple\.com$/,
  /^init\.itunes\.apple\.com$/,
  /^p\d+-buy\.itunes\.apple\.com$/,
  /^gsa\.apple\.com$/,
  /^developerservices2\.apple\.com$/,
  // Official Apple host for the Apple Music Android APK, whose native
  // libraries (libstoreservicescore.so, libCoreADI.so) back anisette.
  /^apps\.mzstatic\.com$/,
];

/** The only TCP port the proxy will connect to. */
export const ALLOWED_TCP_PORT = 443;

function looksLikeIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

/**
 * Whether an outbound WISP stream to `host:port` is permitted.
 * Normalizes case and a single trailing dot; rejects IP literals outright.
 */
export function isAllowedHost(host: string, port: number): boolean {
  if (port !== ALLOWED_TCP_PORT) {
    return false;
  }
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  if (!normalized || looksLikeIpLiteral(normalized)) {
    return false;
  }
  return APPLE_HOST_PATTERNS.some((pattern) => pattern.test(normalized));
}

/** True for any request path this worker treats as a WISP endpoint candidate. */
export function isWispRoute(path: string): boolean {
  return path.startsWith("/wisp");
}

/**
 * True only for the canonical WISP endpoint path (exactly "/wisp/").
 * Anything else under /wisp is routed into the WISP branch (see
 * isWispRoute) and rejected with 404.
 */
export function isWispPath(path: string): boolean {
  return path === "/wisp/";
}

const encoder = new TextEncoder();

/** Constant-time string comparison to avoid leaking the token via timing. */
export function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  if (aBytes.length !== bBytes.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < aBytes.length; i += 1) {
    diff |= aBytes[i] ^ bBytes[i];
  }
  return diff === 0;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export interface TokenEnv {
  ACCESS_TOKEN_HASH?: string | null;
  ACCESS_PASSWORD?: string | null;
}

/**
 * Whether the token supplied via `?token=` authorizes a WISP session.
 * If neither ACCESS_TOKEN_HASH nor ACCESS_PASSWORD is configured, the
 * endpoint is public and any (or no) token is accepted.
 */
export async function isValidToken(
  provided: string | null | undefined,
  env: TokenEnv,
): Promise<boolean> {
  const hash = (env.ACCESS_TOKEN_HASH ?? "").trim();
  let expected = "";
  if (hash) {
    expected = hash;
  } else {
    const password = (env.ACCESS_PASSWORD ?? "").trim();
    if (!password) {
      return true; // no token configured -> public endpoint
    }
    expected = await sha256Hex(password);
  }
  const supplied = (provided ?? "").replace(/\/+$/, "");
  return timingSafeEqual(supplied, expected);
}
