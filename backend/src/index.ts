/**
 * sideimpactor-backend: Cloudflare Worker hosting the WISP-over-WebSocket
 * TCP proxy used by the frontend's libcurl WASM to reach Apple servers.
 *
 * Endpoint: WS /wisp/?token=<token>
 *   - Plain TLS passthrough (cloudflare:sockets), hostname allowlist limited
 *     to the Apple endpoints needed for login/signing.
 *   - UDP disabled, only TCP/443, no direct IPs (SSRF hardening).
 * GET /healthz -> "ok"
 * Everything else -> static frontend from ASSETS (SPA fallback).
 */

import { connect } from "cloudflare:sockets";
import { server as wisp } from "@mercuryworkshop/wisp-js/server";
import {
  ALLOWED_TCP_PORT,
  APPLE_HOST_PATTERNS,
  isValidToken,
  isWispPath,
  isWispRoute,
} from "./wisp-policy";

// Restrict the embedded wisp-js server. Belt and braces: wisp-policy.ts
// exposes the same rules as pure functions for unit tests, while these
// runtime options are what wisp-js enforces on every stream it opens.
wisp.options.hostname_whitelist = [...APPLE_HOST_PATTERNS];
wisp.options.port_whitelist = [ALLOWED_TCP_PORT];
wisp.options.allow_direct_ip = false;
wisp.options.allow_private_ips = false;
wisp.options.allow_loopback_ips = false;
wisp.options.allow_tcp_streams = true;
wisp.options.allow_udp_streams = false;
wisp.options.wisp_version = 1;
// wisp-js's stream filter performs a Node-style DNS lookup
// (node:dns/promises) on every CONNECT to guard against DNS rebinding.
// Cloudflare Workers only ships a non-functional dns stub, so that lookup
// never settles and every stream hangs silently with no CLOSE packet.
// This worker already restricts streams to an explicit Apple hostname
// allowlist with no direct IPs, and cloudflare:sockets performs its own
// DNS resolution for the actual connection, so bypass wisp-js's lookup.
wisp.options.dns_method = async (hostname: string) => hostname;

/** Single-consumer async queue bridging the socket reader to wisp-js recv(). */
class MessagePump<T> {
  private buffered: T[] = [];
  private waiters: Array<(value: T | null) => void> = [];
  private drained = false;

  push(value: T): void {
    if (this.drained) {
      return;
    }
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter(value);
      return;
    }
    this.buffered.push(value);
  }

  async next(): Promise<T | null> {
    if (this.buffered.length > 0) {
      return this.buffered.shift() ?? null;
    }
    if (this.drained) {
      return null;
    }
    return new Promise<T | null>((resolve) => {
      this.waiters.push(resolve);
    });
  }

  drain(): void {
    if (this.drained) {
      return;
    }
    this.drained = true;
    for (const waiter of this.waiters.splice(0)) {
      waiter(null);
    }
    this.buffered.length = 0;
  }
}

/** TCP stream socket backed by cloudflare:sockets for wisp-js. */
class CfTcpSocket {
  readonly hostname: string;
  readonly port: number;

  private socket: Socket | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private incoming = new MessagePump<Uint8Array>();

  constructor(hostname: string, port: number) {
    this.hostname = hostname;
    this.port = port;
  }

  async connect(): Promise<void> {
    // TLS is handled by the WISP client itself; open a raw TCP socket.
    this.socket = connect(
      { hostname: this.hostname, port: this.port },
      { secureTransport: "off", allowHalfOpen: false },
    );
    this.reader = this.socket.readable.getReader();
    this.writer = this.socket.writable.getWriter();
    void this.forwardInbound();
  }

  private async forwardInbound(): Promise<void> {
    try {
      while (this.reader) {
        const { value, done } = await this.reader.read();
        if (done) {
          break;
        }
        if (value && value.length > 0) {
          this.incoming.push(value);
        }
      }
    } catch {
      // Read errors surface as stream close to wisp-js.
    } finally {
      this.incoming.drain();
      await this.close();
    }
  }

  async recv(): Promise<Uint8Array | null> {
    return this.incoming.next();
  }

  async send(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void> {
    if (!this.writer) {
      throw new Error("TCP socket is not connected");
    }
    const chunk =
      data instanceof Uint8Array
        ? data
        : new Uint8Array(
            data instanceof ArrayBuffer ? data : data.buffer,
            data instanceof ArrayBuffer ? 0 : data.byteOffset,
            data instanceof ArrayBuffer ? data.byteLength : data.byteLength,
          );
    await this.writer.write(chunk);
  }

  async close(): Promise<void> {
    this.incoming.drain();
    try {
      await this.reader?.cancel();
    } catch {
      /* already closed */
    }
    try {
      await this.writer?.close();
    } catch {
      /* already closed */
    }
    try {
      await this.socket?.close();
    } catch {
      /* already closed */
    }
    this.reader = null;
    this.writer = null;
    this.socket = null;
  }

  pause(): void {
    // Cloudflare sockets have no manual backpressure hooks; no-op.
  }

  resume(): void {
    // Cloudflare sockets have no manual backpressure hooks; no-op.
  }
}

/**
 * Adapts a Cloudflare server-side WebSocket to the ws-like interface
 * wisp-js's AsyncWebSocket drives (property handlers + OPEN/readyState).
 */
class WsAdapter {
  readonly OPEN = 1;

  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  private readonly socket: WebSocket;

  constructor(socket: WebSocket) {
    this.socket = socket;
    this.socket.addEventListener("open", (event) => this.onopen?.(event));
    this.socket.addEventListener("message", (event) => {
      const handler = this.onmessage;
      if (!handler) {
        return;
      }
      const data = (event as MessageEvent).data;
      // Server-side WebSocket message data may arrive as a Blob (workerd
      // default binaryType) instead of an ArrayBuffer. wisp-js does
      // `new Uint8Array(event.data)`, which yields an empty view for a Blob
      // and every packet then fails to parse. Normalize to ArrayBuffer.
      if (typeof Blob !== "undefined" && data instanceof Blob) {
        data.arrayBuffer().then(
          (buffer) => handler({ data: buffer } as MessageEvent),
          () => handler({ data: new ArrayBuffer(0) } as MessageEvent),
        );
        return;
      }
      handler(event as MessageEvent);
    });
    this.socket.addEventListener("close", (event) =>
      this.onclose?.(event as CloseEvent),
    );
  }

  get readyState(): number {
    return this.socket.readyState;
  }

  get bufferedAmount(): number {
    // The Workers server-side socket does not reliably report
    // bufferedAmount; 0 keeps wisp-js out of its throttle loop.
    return 0;
  }

  send(message: ArrayBuffer | ArrayBufferView | string): void {
    this.socket.send(message);
  }

  close(code?: number, reason?: string): void {
    this.socket.close(code, reason);
  }
}

/** UDP is disabled; any attempt to open a UDP stream fails fast. */
class DisabledUdpSocket {
  readonly hostname: string;
  readonly port: number;

  constructor(hostname: string, port: number) {
    this.hostname = hostname;
    this.port = port;
  }

  async connect(): Promise<void> {
    throw new Error("UDP streams are disabled on this proxy");
  }

  async recv(): Promise<null> {
    return null;
  }

  async send(): Promise<void> {
    throw new Error("UDP streams are disabled on this proxy");
  }

  async close(): Promise<void> {}

  pause(): void {}

  resume(): void {}
}

function isWebSocketUpgrade(request: Request): boolean {
  return request.headers.get("Upgrade")?.toLowerCase() === "websocket";
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function runWispSession(serverSocket: WebSocket, path: string): Promise<void> {
  const adapter = new WsAdapter(serverSocket);
  const connection = new wisp.ServerConnection(adapter, path, {
    TCPSocket: CfTcpSocket,
    UDPSocket: DisabledUdpSocket,
    ping_interval: 30,
    wisp_version: 1,
  });
  await connection.setup();
  await connection.run();
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return new Response("ok", { status: 200 });
    }

    if (url.pathname === "/") {
      return json(200, {
        ok: true,
        service: "sideimpactor-backend",
        now: new Date().toISOString(),
      });
    }

    // Apple API reverse proxy. Browsers cannot open raw TLS sockets to Apple,
    // and the WISP path (Mbed TLS in WASM over cloudflare:sockets) gets HTTP
    // 503 from gsa.apple.com/grandslam/GsService2 — Apple's WAF rejects that
    // egress path (IPv6 / non-standard TLS fingerprint), while a plain
    // Workers fetch() to the same URL returns 200. So Apple API traffic goes
    // through this same-origin proxy instead of WISP/libcurl.
    if (url.pathname.startsWith("/apple-proxy/")) {
      const rest = url.pathname.slice("/apple-proxy/".length);
      let target: URL;
      try {
        target = new URL("https://" + rest + url.search);
      } catch {
        return json(400, { ok: false, error: "invalid target" });
      }
      if (!APPLE_HOST_PATTERNS.some((p) => p.test(target.hostname.toLowerCase()))) {
        return json(403, { ok: false, error: "host not allowed" });
      }
      const fwdHeaders = new Headers();
      request.headers.forEach((value, key) => {
        const lk = key.toLowerCase();
        // Don't forward Content-Type on GET/HEAD: altsign.js sets
        // `Content-Type: text/x-xml-plist` even on GETs, which confuses
        // Apple's 2FA endpoints into returning HTML instead of triggering.
        if (lk === "content-type" && (request.method === "GET" || request.method === "HEAD")) {
          return;
        }
        if (
          lk === "content-type" ||
          lk === "accept" ||
          lk === "accept-language" ||
          lk === "user-agent" ||
          lk === "security-code" ||
          lk === "x-http-method-override" ||
          lk.startsWith("x-apple-") ||
          lk.startsWith("x-mme-")
        ) {
          fwdHeaders.set(key, value);
        }
      });
      const p = target.pathname;
      // For 2FA endpoints, use isideload's exact headers (from
      // isideload/src/auth/grandslam.rs base_headers + apple_account.rs
      // build_2fa_headers). Total 11 headers:
      //   base: Content-Type, Accept, X-Mme-Client-Info, User-Agent,
      //         X-Xcode-Version, X-Apple-App-Info
      //   2fa:  X-Mme-Device-Id, X-Apple-I-MD, X-Apple-I-MD-M,
      //         X-Apple-Identity-Token, X-Apple-I-MD-RINFO (+ security-code)
      // Key insight: X-Mme-Client-Info and User-Agent must mimic `akd`
      // (Apple Keychain Daemon), NOT Xcode. Apple ignores 2FA requests
      // that don't look like they come from akd.
      const is2fa = p.startsWith("/grandslam/GsService2/validate") || p.startsWith("/auth/verify/");
      // SMS 2FA endpoints use JSON, not plist (isideload apple_account.rs).
      // Don't apply the plist Content-Type override to them.
      const isSms2fa = p.startsWith("/auth/verify/phone");
      // isideload uses akd-mimicking headers for ALL developer API requests
      // (not just 2FA). From isideload/src/dev/developer_session.rs get_headers()
      // + grandslam.rs base_headers: 11 headers total.
      const isDevApi = target.hostname === "developerservices2.apple.com";
      let finalHeaders = fwdHeaders;
      if ((is2fa && !isSms2fa) || isDevApi) {
        const isideload = new Headers();
        // base_headers from grandslam.rs
        isideload.set("Content-Type", "text/x-xml-plist");
        isideload.set("Accept", "text/x-xml-plist");
        isideload.set("X-Mme-Client-Info", "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>");
        isideload.set("User-Agent", "akd/1.0 CFNetwork/808.1.4");
        isideload.set("X-Xcode-Version", "27.0 (27A5218g)");
        isideload.set("X-Apple-App-Info", "com.apple.gs.xcode.auth");
        if (is2fa) {
          // build_2fa_headers from apple_account.rs (values from frontend)
          for (const k of ["x-mme-device-id", "x-apple-i-md", "x-apple-i-md-m", "x-apple-i-md-rinfo", "x-apple-identity-token", "security-code"]) {
            const v = fwdHeaders.get(k);
            if (v) isideload.set(k, v);
          }
        } else {
          // Developer API: from developer_session.rs get_headers()
          // (anisette values + GS token + identity ID from frontend)
          for (const k of ["x-mme-device-id", "x-apple-i-md", "x-apple-i-md-m", "x-apple-gs-token", "x-apple-i-identity-id", "x-http-method-override"]) {
            const v = fwdHeaders.get(k);
            if (v) isideload.set(k, v);
          }
        }
        finalHeaders = isideload;
      } else if (target.hostname === "gsa.apple.com") {
        fwdHeaders.set(
          "User-Agent",
          "AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)",
        );
      }
      // Replace blocked Xcode client identifier in X-MMe-Client-Info (non-2FA only;
      // 2FA uses minimal headers without X-MMe-Client-Info).
      // The browser-side replacement in network.ts may miss it (altsign.js
      // uses mixed-case `X-MMe-Client-Info`), so enforce it here as well.
      // Apple's GSA edge rejects `com.apple.dt.Xcode` with 503 since Sep 2026
      // (nab138/isideload#11).
      if (!is2fa) {
        const mmeInfo = finalHeaders.get("X-MMe-Client-Info");
        if (mmeInfo && mmeInfo.includes("com.apple.dt.Xcode")) {
          finalHeaders.set(
            "X-MMe-Client-Info",
            mmeInfo.replace(/com\.apple\.dt\.Xcode\/[\d.]+/, "com.apple.akd/1.0"),
          );
        }
      }
      // Debug: log non-sensitive headers for 2FA endpoints (no tokens)
      if (is2fa) {
        console.log(`[2fa-debug] ${request.method} ${p} accept=${finalHeaders.get("accept")} ua=${finalHeaders.get("user-agent")} has-identity-token=${finalHeaders.has("x-apple-identity-token")}`);
      }
      const upstream = await fetch(
        new Request(target.toString(), {
          method: request.method,
          headers: finalHeaders,
          body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
          redirect: "manual",
        }),
      );
      const respHeaders = new Headers();
      const contentType = upstream.headers.get("content-type");
      if (contentType) respHeaders.set("content-type", contentType);
      return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
    }

    if (isWispRoute(url.pathname)) {
      if (!isWebSocketUpgrade(request)) {
        return json(426, {
          ok: false,
          error: "WebSocket upgrade required for /wisp/",
        });
      }
      if (!isWispPath(url.pathname)) {
        return json(404, {
          ok: false,
          error: "Only /wisp/ is served by this endpoint",
        });
      }
      if (!(await isValidToken(url.searchParams.get("token"), env))) {
        return json(401, { ok: false, error: "Invalid or missing token" });
      }

      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      server.accept();

      ctx.waitUntil(
        runWispSession(server, url.pathname).catch((error) => {
          console.error("WISP session failed:", error);
          try {
            server.close(1011, "Internal WISP error");
          } catch {
            /* already closed */
          }
        }),
      );

      return new Response(null, { status: 101, webSocket: client });
    }

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
