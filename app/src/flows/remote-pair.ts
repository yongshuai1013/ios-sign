/**
 * Remote (Wi-Fi) pairing flow.
 *
 * The device must be on the same network with "Sync with this iPhone over
 * Wi-Fi" enabled; the 6-digit code shown under Settings → General → VPN &
 * Device Management (or the Wi-Fi sync pairing sheet) is entered here.
 *
 * Transport: browsers cannot open raw TCP sockets, so the `RpTransport` is
 * bridged through the WISP backend (WebSocket → TCP proxy, see `backend/`).
 * The backend must be deployed and `VITE_WISP_URL` configured; otherwise
 * this flow throws a descriptive error instead of failing silently.
 *
 * On success the `pairingFile.plist` (Ed25519 keys + identifier) is returned
 * for download / localStorage persistence.
 */
import { RemotePairingClient, type RpTransport } from '@pairing/remote-pairing';
import { RpPairingFile } from '@pairing/pairing-file';

export interface RemotePairingCallbacks {
  log: (message: string) => void;
}

/** iOS Remote Pairing listens on TCP 62742 (remotepairingdeviced). */
export const REMOTE_PAIRING_PORT = 62742;

export class RemotePairingUnavailableError extends Error {
  constructor(reason: string) {
    super(`Remote pairing unavailable: ${reason}`);
    this.name = 'RemotePairingUnavailableError';
  }
}

/**
 * `RpTransport` over a WebSocket that proxies raw TCP via the WISP backend.
 *
 * Protocol: the backend exposes `ws(s)://<host>/wisp?host=<device>&port=62742`
 * and forwards binary WebSocket messages to the TCP socket (this matches the
 * backend's WISP proxy contract in `backend/`).
 */
export class WispRpTransport implements RpTransport {
  private socket: WebSocket | null = null;
  private pending = new Uint8Array(0);
  private waiters: Array<{ n: number; resolve: (data: Uint8Array) => void; reject: (err: Error) => void }> = [];
  private closed = false;

  constructor(
    private readonly wispUrl: string,
    private readonly deviceHost: string,
    private readonly devicePort: number = REMOTE_PAIRING_PORT,
  ) {}

  async connect(): Promise<void> {
    if (!this.wispUrl) {
      throw new RemotePairingUnavailableError(
        'VITE_WISP_URL is not configured — deploy backend/ and set the env var.',
      );
    }
    const url = `${this.wispUrl.replace(/\/$/, '')}/wisp?host=${encodeURIComponent(this.deviceHost)}&port=${this.devicePort}`;
    await new Promise<void>((resolve, reject) => {
      const socket = new WebSocket(url);
      socket.binaryType = 'arraybuffer';
      const onError = () => {
        cleanup();
        reject(new RemotePairingUnavailableError(`cannot reach WISP proxy at ${this.wispUrl}`));
      };
      const onOpen = () => {
        cleanup();
        this.socket = socket;
        socket.onmessage = (event) => this.onMessage(event.data);
        socket.onclose = () => this.onClose();
        socket.onerror = () => this.onClose();
        resolve();
      };
      const cleanup = () => {
        socket.removeEventListener('open', onOpen);
        socket.removeEventListener('error', onError);
      };
      socket.addEventListener('open', onOpen);
      socket.addEventListener('error', onError);
    });
  }

  private onMessage(data: unknown): void {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(0);
    if (bytes.length === 0) return;
    const merged = new Uint8Array(this.pending.length + bytes.length);
    merged.set(this.pending, 0);
    merged.set(bytes, this.pending.length);
    this.pending = merged;
    this.drain();
  }

  private onClose(): void {
    this.closed = true;
    const err = new Error('WISP transport closed');
    for (const waiter of this.waiters.splice(0)) waiter.reject(err);
  }

  private drain(): void {
    while (this.waiters.length > 0 && this.pending.length >= this.waiters[0].n) {
      const waiter = this.waiters.shift();
      if (!waiter) break;
      const out = this.pending.slice(0, waiter.n);
      this.pending = this.pending.slice(waiter.n);
      waiter.resolve(out);
    }
  }

  async write(data: Uint8Array): Promise<void> {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('WISP transport is not connected');
    }
    this.socket.send(data as BufferSource);
  }

  readExact(n: number): Promise<Uint8Array> {
    if (this.closed) return Promise.reject(new Error('WISP transport closed'));
    if (this.pending.length >= n) {
      const out = this.pending.slice(0, n);
      this.pending = this.pending.slice(n);
      return Promise.resolve(out);
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
    });
  }

  close(): void {
    this.closed = true;
    try {
      this.socket?.close();
    } catch {
      // ignore
    }
    this.socket = null;
  }
}

export interface RemotePairSetupRequest {
  /** Device hostname or IP on the local network. */
  deviceHost: string;
  /** 6-digit code shown on the device. */
  pin: string;
  /** WISP proxy base URL, e.g. wss://example.workers.dev */
  wispUrl: string;
  log: (message: string) => void;
}

function wispUrlFromEnv(): string {
  // `import.meta.env` is typed via vite/client.
  return (import.meta.env?.['VITE_WISP_URL'] as string | undefined) ?? '';
}

/**
 * Runs the remote pairing session: `handshake()` then
 * `startSession()` (pair-verify with X25519/Ed25519, falling back to
 * pair-setup with SRP-3072/SHA-512 using the on-device PIN).
 * Returns the pairing file to persist.
 */
export async function remotePairSetupFlow(req: RemotePairSetupRequest): Promise<RpPairingFile> {
  const wispUrl = req.wispUrl || wispUrlFromEnv();
  req.log(`remote-pair: connecting to ${req.deviceHost}:${REMOTE_PAIRING_PORT} via WISP...`);
  const transport = new WispRpTransport(wispUrl, req.deviceHost);
  await transport.connect();
  req.log('remote-pair: transport connected');
  try {
    const host = window.location.hostname || 'sideimpactor';
    const pairingFile = RpPairingFile.generate(host);
    const client = new RemotePairingClient(transport, pairingFile, host);
    req.log('remote-pair: handshake + pair-verify (or pair-setup with PIN)...');
    await client.startSession(req.pin);
    req.log('remote-pair: paired and verified');
    return client.pairingFile ?? pairingFile;
  } finally {
    transport.close();
  }
}
