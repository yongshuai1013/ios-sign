// Minimal typings for the untyped @mercuryworkshop/wisp-js/server entrypoint.
// Only the surface this worker uses is declared.

declare module "@mercuryworkshop/wisp-js/server" {
  export namespace server {
    interface WispServerOptions {
      hostname_blacklist: RegExp[] | null;
      hostname_whitelist: RegExp[] | null;
      port_blacklist: number[] | null;
      port_whitelist: number[] | null;
      allow_direct_ip: boolean;
      allow_private_ips: boolean;
      allow_loopback_ips: boolean;
      allow_udp_streams: boolean;
      allow_tcp_streams: boolean;
      wisp_version: number;
      /**
       * How wisp-js resolves hostnames for its SSRF rebind check. The
       * default "lookup" uses node:dns/promises, which never settles on
       * Cloudflare Workers; a function bypasses it. (The worker's own
       * hostname allowlist plus cloudflare:sockets' resolution remain.)
       */
      dns_method: "lookup" | "resolve" | ((hostname: string) => Promise<string>);
    }

    const options: WispServerOptions;

    /** Stream socket factory shape expected by ServerConnection. */
    interface StreamSocket {
      connect(): Promise<void>;
      recv(): Promise<Uint8Array | null>;
      send(data: Uint8Array | ArrayBuffer | ArrayBufferView): Promise<void>;
      close(): Promise<void>;
      pause(): void;
      resume(): void;
    }

    interface StreamSocketCtor {
      new (hostname: string, port: number): StreamSocket;
    }

    interface ServerConnectionOptions {
      TCPSocket?: StreamSocketCtor;
      UDPSocket?: StreamSocketCtor;
      ping_interval?: number;
      wisp_version?: number;
    }

    /** ws-like object the server connection drives via property handlers. */
    interface WsLike {
      OPEN: number;
      readyState: number;
      bufferedAmount: number;
      onopen: ((event: Event) => void) | null;
      onmessage: ((event: MessageEvent) => void) | null;
      onclose: ((event: CloseEvent) => void) | null;
      send(message: ArrayBuffer | ArrayBufferView | string): void;
      close(code?: number, reason?: string): void;
    }

    class ServerConnection {
      constructor(ws: WsLike, path: string, opts?: ServerConnectionOptions);
      setup(): Promise<void>;
      run(): Promise<void>;
    }
  }
}
