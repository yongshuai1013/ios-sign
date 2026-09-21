/**
 * WebUSB direct MUX transport — browser-side USB multiplexing for iOS devices.
 *
 * TypeScript port of the MUX handshake + TCP-over-MUX logic from SideImpactor's
 * webmuxd `DirectUsbMuxClient`
 * (`dependencies/webmuxd/src/core/imobiledevice-client.ts`), reworked so a
 * browser can drive an iOS device's usbmux USB interface directly via WebUSB
 * without a usbmuxd daemon in the middle.
 *
 * Layering:
 *   WebUsbMux        — owns the USBDevice: interface/endpoint setup, the
 *                      transferIn read loop, MUX framing, per-sport demux.
 *   MuxTcpConnection — one TCP-over-MUX stream; implements {@link ByteTransport}
 *                      so it plugs into the same client code as usbmuxd.ts.
 *   WebUsbMuxDevice  — high-level facade over WebUsbMux implementing the
 *                      {@link Transport} interface: requestDevice() -> open()
 *                      -> createTcpConnection(deviceId, port).
 *   TcpTransport     — same {@link Transport} interface over node:net TCP,
 *                      for Node/bun environments without WebUSB.
 *
 * Typical flow:
 *   const device = await WebUsbMuxDevice.requestDevice();
 *   await device.open();
 *   const lockdown = await device.createTcpConnection(0, LOCKDOWN_PORT);
 *   // `lockdown` is a Transport carrying the raw lockdownd stream.
 *
 * Byte order note: every multi-byte MUX/TCP header field is big-endian,
 * exactly mirroring webmuxd's DirectUsbMuxClient (DataView with
 * littleEndian=false), which is proven against real iOS hardware. A
 * little-endian encoding could never complete the VERSION handshake against
 * a real device (the length field would parse as 0x14000000), so big-endian
 * is the on-the-wire format.
 *
 * WebUSB typing note: this project's TypeScript DOM lib ships no WebUSB
 * types, so this module declares minimal structural types (UsbDeviceLike,
 * UsbLike, …). A real browser USBDevice is structurally assignable to them.
 */

/* ------------------------------------------------------------------ */
/* Shared transport abstractions                                       */
/* ------------------------------------------------------------------ */

/** Minimal byte-stream both clients run on (mirrors usbmuxd.ts). */
export interface ByteTransport {
  write(data: Uint8Array): Promise<void>;
  readExact(n: number): Promise<Uint8Array>;
  close(): void;
}

/**
 * Byte-stream transport with `read(n)` semantics: resolves with exactly n
 * bytes, waiting for more data if necessary — the same guarantee as
 * ByteTransport.readExact, plus a promise-returning close().
 */
export interface Transport {
  write(data: Uint8Array): Promise<void>;
  read(n: number): Promise<Uint8Array>;
  close(): Promise<void>;
}

/** Errors raised by this module (handshake failures, refused connections,
 *  detached devices, bad arguments, missing WebUSB, …). */
export class WebUsbMuxError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'WebUsbMuxError';
  }
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

/** Apple USB vendor ID used for the browser device picker. */
export const APPLE_VENDOR_ID = 0x05ac;

/** USB descriptor matching for the usbmux interface (from webusb-transport.ts). */
export const USBMUX_INTERFACE_CLASS = 0xff;
export const USBMUX_INTERFACE_SUBCLASS = 254;
export const USBMUX_INTERFACE_PROTOCOL = 2;

/** MUX protocol numbers (mirrors DirectUsbMuxClient). */
export const MUX_PROTO_VERSION = 0;
export const MUX_PROTO_CONTROL = 1;
export const MUX_PROTO_SETUP = 2;
export const MUX_PROTO_TCP = 6;

/** Magic word the host puts in v2 MUX headers. */
export const MUX_MAGIC_HOST = 0xfeedface;
/** Alternate magic word accepted from the device. */
export const MUX_MAGIC_DEVICE_ALT = 0xfaceface;

/** Simplified TCP flags used by the MUX TCP header. */
export const TCP_FLAG_FIN = 0x01;
export const TCP_FLAG_SYN = 0x02;
export const TCP_FLAG_RST = 0x04;
export const TCP_FLAG_PSH = 0x08;
export const TCP_FLAG_ACK = 0x10;

/** lockdownd's TCP port on the device. */
export const LOCKDOWN_PORT = 62078;

const MAX_MUX_PACKET = 262144;
const MUX_V2_HEADER_SIZE = 16;
const MUX_LEGACY_HEADER_SIZE = 8;
const TCP_HEADER_SIZE = 20;
const DEFAULT_TRANSFER_SIZE = 16384;
const EMPTY = new Uint8Array(0);

/* ------------------------------------------------------------------ */
/* Minimal structural WebUSB types (the TS DOM lib has none)           */
/* ------------------------------------------------------------------ */

/** Filter for navigator.usb.requestDevice(). */
export interface UsbDeviceFilter {
  vendorId?: number;
  productId?: number;
}

export interface UsbEndpointLike {
  readonly endpointNumber: number;
  readonly direction: 'in' | 'out';
  readonly type: 'bulk' | 'interrupt' | 'isochronous';
}

export interface UsbAlternateInterfaceLike {
  readonly interfaceClass: number;
  readonly interfaceSubclass: number;
  readonly interfaceProtocol: number;
  readonly endpoints: UsbEndpointLike[];
}

export interface UsbInterfaceLike {
  readonly interfaceNumber: number;
  readonly claimed: boolean;
  readonly alternates: UsbAlternateInterfaceLike[];
}

export interface UsbConfigurationLike {
  readonly configurationValue: number;
  readonly interfaces: UsbInterfaceLike[];
}

export interface UsbInTransferResultLike {
  readonly data?: DataView;
  readonly status: string;
}

export interface UsbOutTransferResultLike {
  readonly status: string;
}

/**
 * Structural subset of the browser's USBDevice. A real USBDevice is
 * assignable; tests can substitute a fake.
 */
export interface UsbDeviceLike {
  readonly vendorId: number;
  readonly productId: number;
  readonly productName?: string;
  readonly opened: boolean;
  readonly configuration?: UsbConfigurationLike;
  readonly configurations: UsbConfigurationLike[];
  open(): Promise<void>;
  close(): Promise<void>;
  selectConfiguration(configurationValue: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  releaseInterface(interfaceNumber: number): Promise<void>;
  clearHalt?(direction: 'in' | 'out', endpointNumber: number): Promise<void>;
  transferIn(endpointNumber: number, length: number): Promise<UsbInTransferResultLike>;
  transferOut(endpointNumber: number, data: BufferSource): Promise<UsbOutTransferResultLike>;
}

/** Structural subset of navigator.usb. */
export interface UsbLike {
  requestDevice(options: { filters: UsbDeviceFilter[] }): Promise<UsbDeviceLike>;
  getDevices(): Promise<UsbDeviceLike[]>;
  addEventListener(
    type: 'disconnect',
    listener: (event: { device?: UsbDeviceLike }) => void,
  ): void;
  removeEventListener(
    type: 'disconnect',
    listener: (event: { device?: UsbDeviceLike }) => void,
  ): void;
}

function getWebUsbApi(): UsbLike | null {
  if (typeof navigator === 'undefined') return null;
  const candidate = (navigator as unknown as { usb?: UsbLike }).usb;
  return candidate ?? null;
}

/** Device-disconnect notification signature. */
export type UsbDisconnectHandler = (reason: unknown) => void;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function dataViewOf(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** USBDeviceRequestOptions filters used to pick an iOS device. Exported so the
 *  filter construction can be unit-tested without real WebUSB hardware. */
export function buildAppleUsbFilters(): UsbDeviceFilter[] {
  return [{ vendorId: APPLE_VENDOR_ID }];
}

/* ------------------------------------------------------------------ */
/* MUX packet codec (pure functions, big-endian on the wire)           */
/* ------------------------------------------------------------------ */

export interface MuxEncodeOptions {
  /** Negotiated MUX version; >= 2 selects the 16-byte header (default 1). */
  version?: number;
  /** v2 only: host transmit sequence number placed in the header. */
  txSeq?: number;
  /** v2 only: last device transmit sequence number seen. */
  rxSeq?: number;
}

/**
 * Encodes one MUX packet header (without payload).
 * Legacy: 8 bytes  = u32be protocol, u32be totalLength.
 * v2:     16 bytes = u32be protocol, u32be totalLength, u32be magic
 *                      (0xfeedface), u16be txSeq, u16be rxSeq.
 */
export function encodeMuxHeader(
  protocol: number,
  totalLength: number,
  options: MuxEncodeOptions,
): Uint8Array {
  const v2 = (options.version ?? 1) >= 2;
  const header = new Uint8Array(v2 ? MUX_V2_HEADER_SIZE : MUX_LEGACY_HEADER_SIZE);
  const view = dataViewOf(header);
  view.setUint32(0, protocol >>> 0, false);
  view.setUint32(4, totalLength >>> 0, false);
  if (v2) {
    view.setUint32(8, MUX_MAGIC_HOST, false);
    view.setUint16(12, (options.txSeq ?? 0) & 0xffff, false);
    view.setUint16(14, (options.rxSeq ?? 0xffff) & 0xffff, false);
  }
  return header;
}

/** Encodes one full MUX packet: header + payload. */
export function encodeMuxPacket(
  protocol: number,
  payload: Uint8Array,
  options: MuxEncodeOptions,
): Uint8Array {
  const v2 = (options.version ?? 1) >= 2;
  const headerSize = v2 ? MUX_V2_HEADER_SIZE : MUX_LEGACY_HEADER_SIZE;
  const header = encodeMuxHeader(protocol, headerSize + payload.byteLength, options);
  const packet = new Uint8Array(header.length + payload.byteLength);
  packet.set(header, 0);
  packet.set(payload, header.length);
  return packet;
}

export interface DecodedMuxHeader {
  protocol: number;
  /** Total packet length including the header. */
  length: number;
  /** v2 only; 0 for legacy headers. */
  magic: number;
  /** v2 only: the u16 at header offset 12. */
  txSeq: number;
  /** v2 only: the u16 at header offset 14. */
  rxSeq: number;
}

/** Decodes a MUX packet header. `version` selects the 8- vs 16-byte layout. */
export function decodeMuxHeader(packet: Uint8Array, version: number): DecodedMuxHeader {
  const v2 = version >= 2;
  const headerSize = v2 ? MUX_V2_HEADER_SIZE : MUX_LEGACY_HEADER_SIZE;
  if (packet.byteLength < headerSize) {
    throw new Error(`MUX packet shorter than ${headerSize}-byte header`);
  }
  const view = dataViewOf(packet);
  const decoded: DecodedMuxHeader = {
    protocol: view.getUint32(0, false),
    length: view.getUint32(4, false),
    magic: 0,
    txSeq: 0,
    rxSeq: 0,
  };
  if (v2) {
    decoded.magic = view.getUint32(8, false);
    decoded.txSeq = view.getUint16(12, false);
    decoded.rxSeq = view.getUint16(14, false);
  }
  return decoded;
}

/* ------------------------------------------------------------------ */
/* Simplified TCP-over-MUX codec (pure functions, big-endian)          */
/* ------------------------------------------------------------------ */

export interface TcpHeaderFields {
  sport: number;
  dport: number;
  seq: number;
  ack: number;
  flags: number;
  window: number;
}

/**
 * Encodes one 20-byte simplified TCP header + payload.
 * Layout (all big-endian): u16 sport, u16 dport, u32 seq, u32 ack,
 * u8 dataOffset(5)<<4, u8 flags, u16 window, u16 checksum(0), u16 urg(0).
 */
export function encodeTcpPacket(header: TcpHeaderFields, payload: Uint8Array): Uint8Array {
  const packet = new Uint8Array(TCP_HEADER_SIZE + payload.byteLength);
  const view = dataViewOf(packet);
  view.setUint16(0, header.sport & 0xffff, false);
  view.setUint16(2, header.dport & 0xffff, false);
  view.setUint32(4, header.seq >>> 0, false);
  view.setUint32(8, header.ack >>> 0, false);
  packet[12] = 5 << 4; // data offset: 5 x 32-bit words = 20 bytes
  packet[13] = header.flags & 0xff;
  view.setUint16(14, Math.min(header.window, 0xffff), false);
  view.setUint16(16, 0, false); // checksum: unused by the device stack
  view.setUint16(18, 0, false); // urgent pointer
  packet.set(payload, TCP_HEADER_SIZE);
  return packet;
}

/** Decodes one TCP-over-MUX packet into its header and payload. */
export function decodeTcpPacket(packet: Uint8Array): {
  header: TcpHeaderFields;
  payload: Uint8Array;
} {
  if (packet.byteLength < TCP_HEADER_SIZE) {
    throw new Error(`TCP packet shorter than ${TCP_HEADER_SIZE}-byte header`);
  }
  const view = dataViewOf(packet);
  const headerSize = (((packet[12] ?? 0) >> 4) & 0x0f) * 4;
  if (headerSize < TCP_HEADER_SIZE || packet.byteLength < headerSize) {
    throw new Error(`invalid TCP data offset: ${headerSize}`);
  }
  const header: TcpHeaderFields = {
    sport: view.getUint16(0, false),
    dport: view.getUint16(2, false),
    seq: view.getUint32(4, false),
    ack: view.getUint32(8, false),
    flags: packet[13] ?? 0,
    window: view.getUint16(14, false),
  };
  return { header, payload: packet.slice(headerSize) };
}

/* ------------------------------------------------------------------ */
/* TCP-over-MUX connection (handshake state machine)                   */
/* ------------------------------------------------------------------ */

export type MuxTcpState = 'connecting' | 'connected' | 'closed';

/** Receives one TCP frame (header + payload) for transmission. */
export type TcpFrameSink = (header: TcpHeaderFields, payload: Uint8Array) => Promise<void>;

interface PendingRead {
  n: number;
  resolve: (data: Uint8Array) => void;
  reject: (err: Error) => void;
}

/**
 * One TCP-over-MUX stream. The handshake state machine (SYN -> SYN+ACK -> ACK)
 * and the seq/ack accounting mirror `DirectUsbMuxClient`; the actual byte
 * transport is injected via `sink` so the logic is testable without USB.
 */
export class MuxTcpConnection implements ByteTransport {
  state: MuxTcpState = 'connecting';

  private txSeq = 0;
  private txAck = 0;
  private readonly txWin = 131072;
  private rxBuffer: Uint8Array = EMPTY;
  private readonly pendingReads: PendingRead[] = [];
  private connectResolve: (() => void) | null = null;
  private connectReject: ((err: Error) => void) | null = null;
  private connectTimer: ReturnType<typeof setTimeout> | null = null;
  private closeError: Error | null = null;

  constructor(
    readonly sport: number,
    readonly dport: number,
    private readonly sink: TcpFrameSink,
    private readonly onTerminated?: (conn: MuxTcpConnection) => void,
  ) {}

  get isConnected(): boolean {
    return this.state === 'connected';
  }

  /** Sends SYN and resolves once the SYN+ACK handshake completes. */
  async open(timeoutMs = 5000): Promise<void> {
    const initialState: MuxTcpState = this.state;
    if (initialState !== 'connecting') {
      throw new Error(`TCP connection is not openable (state=${initialState})`);
    }
    await this.sendFrame(TCP_FLAG_SYN, EMPTY);
    // The SYN+ACK may already have been processed before the waiter is armed
    // (e.g. with loopback fakes in tests). Re-read through an explicitly
    // typed local so narrowing of the mutable property does not leak across
    // the await.
    const stateAfterSyn: MuxTcpState = this.state;
    if (stateAfterSyn === 'connected') {
      return;
    }
    if (stateAfterSyn === 'closed') {
      throw this.closeError ?? new Error('TCP connection closed before handshake completed');
    }
    await new Promise<void>((resolve, reject) => {
      this.connectResolve = resolve;
      this.connectReject = reject;
      this.connectTimer = setTimeout(() => {
        this.terminate(
          new Error(`TCP connect timeout after ${timeoutMs}ms (sport=${this.sport}, dport=${this.dport})`),
        );
      }, timeoutMs);
    });
  }

  /**
   * Feeds one inbound TCP packet into the state machine. Called by the MUX
   * demux loop; sends ACKs as needed.
   */
  async handlePacket(header: TcpHeaderFields, payload: Uint8Array): Promise<void> {
    if (header.sport !== this.dport || header.dport !== this.sport) {
      return; // not ours
    }
    if (this.state === 'connecting') {
      if (header.flags === (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        this.txSeq = (this.txSeq + 1) >>> 0; // SYN consumes one sequence number
        this.txAck = (header.seq + 1) >>> 0;
        this.state = 'connected';
        this.clearConnectTimer();
        await this.sendFrame(TCP_FLAG_ACK, EMPTY);
        const resolve = this.connectResolve;
        this.connectResolve = null;
        this.connectReject = null;
        resolve?.();
      } else if ((header.flags & TCP_FLAG_RST) !== 0) {
        this.terminate(new Error('TCP connect refused by device'));
      }
      return;
    }
    if (this.state !== 'connected') {
      return;
    }
    if ((header.flags & TCP_FLAG_RST) !== 0) {
      this.terminate(new Error('TCP reset from device'));
      return;
    }
    if (payload.byteLength > 0) {
      this.txAck = (header.seq + payload.byteLength) >>> 0;
      this.appendRx(payload);
      await this.sendFrame(TCP_FLAG_ACK, EMPTY);
    }
  }

  async write(data: Uint8Array): Promise<void> {
    if (this.state !== 'connected') {
      throw new Error('TCP connection is not connected');
    }
    // Mirrors DirectUsbMuxClient: data frames carry ACK (no PSH).
    await this.sendFrame(TCP_FLAG_ACK, data);
  }

  async readExact(n: number): Promise<Uint8Array> {
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(`invalid read length ${n}`);
    }
    if (n === 0) {
      return EMPTY;
    }
    if (this.rxBuffer.byteLength >= n) {
      return this.takeBytes(n);
    }
    if (this.state === 'closed') {
      throw this.closeError ?? new Error('TCP connection is closed');
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pendingReads.push({ n, resolve, reject });
    });
  }

  /** Sends RST (best effort) and releases all waiters. */
  close(): void {
    if (this.state === 'closed') {
      return;
    }
    void this.sendFrame(TCP_FLAG_RST, EMPTY).catch(() => undefined);
    this.terminate(new Error('TCP connection closed by local host'));
  }

  /** Terminates without sending RST (transport already gone). */
  abort(reason: Error): void {
    if (this.state === 'closed') {
      return;
    }
    this.terminate(reason);
  }

  private async sendFrame(flags: number, payload: Uint8Array): Promise<void> {
    const header: TcpHeaderFields = {
      sport: this.sport,
      dport: this.dport,
      seq: this.txSeq,
      ack: this.txAck,
      flags,
      window: Math.min(this.txWin, 0xffff),
    };
    await this.sink(header, payload);
    if (payload.byteLength > 0) {
      this.txSeq = (this.txSeq + payload.byteLength) >>> 0;
    }
  }

  private terminate(err: Error): void {
    this.state = 'closed';
    this.closeError = err;
    this.clearConnectTimer();
    const connectReject = this.connectReject;
    this.connectResolve = null;
    this.connectReject = null;
    connectReject?.(err);
    const pending = this.pendingReads.splice(0);
    for (const read of pending) {
      read.reject(err);
    }
    this.onTerminated?.(this);
  }

  private clearConnectTimer(): void {
    if (this.connectTimer !== null) {
      clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
  }

  private appendRx(data: Uint8Array): void {
    if (this.rxBuffer.byteLength === 0) {
      this.rxBuffer = data.slice();
    } else {
      const merged = new Uint8Array(this.rxBuffer.byteLength + data.byteLength);
      merged.set(this.rxBuffer, 0);
      merged.set(data, this.rxBuffer.byteLength);
      this.rxBuffer = merged;
    }
    this.pumpReads();
  }

  private pumpReads(): void {
    while (this.pendingReads.length > 0) {
      const read = this.pendingReads[0];
      if (!read || this.rxBuffer.byteLength < read.n) {
        break;
      }
      this.pendingReads.shift();
      read.resolve(this.takeBytes(read.n));
    }
  }

  private takeBytes(n: number): Uint8Array {
    const out = this.rxBuffer.slice(0, n);
    this.rxBuffer = this.rxBuffer.slice(n);
    return out;
  }
}

/* ------------------------------------------------------------------ */
/* WebUSB MUX link                                                     */
/* ------------------------------------------------------------------ */

export interface WebUsbMuxOptions {
  /** transferIn chunk size; defaults to 16384. */
  transferSize?: number;
  log?: (message: string) => void;
}

export interface MuxConnectOptions {
  /**
   * SYN attempts; defaults to 1 for lockdownd and 6 for other services,
   * mirroring DirectUsbMuxClient.
   */
  maxAttempts?: number;
  /** Per-attempt SYN -> SYN+ACK timeout in ms; defaults to 5000. */
  timeoutMs?: number;
  /** Base backoff between attempts in ms; defaults to 900. */
  retryBaseMs?: number;
}

function findUsbmuxInterface(
  device: UsbDeviceLike,
): { configuration: UsbConfigurationLike; usbInterface: UsbInterfaceLike } | null {
  for (const configuration of device.configurations) {
    for (const usbInterface of configuration.interfaces) {
      for (const alternate of usbInterface.alternates) {
        if (
          alternate.interfaceClass === USBMUX_INTERFACE_CLASS &&
          alternate.interfaceSubclass === USBMUX_INTERFACE_SUBCLASS &&
          alternate.interfaceProtocol === USBMUX_INTERFACE_PROTOCOL
        ) {
          return { configuration, usbInterface };
        }
      }
    }
  }
  return null;
}

function findBulkEndpoints(usbInterface: UsbInterfaceLike): {
  in: UsbEndpointLike | null;
  out: UsbEndpointLike | null;
} {
  let inEp: UsbEndpointLike | null = null;
  let outEp: UsbEndpointLike | null = null;
  for (const alternate of usbInterface.alternates) {
    for (const endpoint of alternate.endpoints) {
      if (endpoint.type !== 'bulk') {
        continue;
      }
      if (endpoint.direction === 'in' && !inEp) {
        inEp = endpoint;
      } else if (endpoint.direction === 'out' && !outEp) {
        outEp = endpoint;
      }
    }
  }
  return { in: inEp, out: outEp };
}

/**
 * Owns one USBDevice's usbmux interface: USB setup, MUX handshake, the
 * transferIn read loop with MUX framing, and demux of TCP streams by sport.
 */
export class WebUsbMux {
  private readonly transferSize: number;
  private readonly log: (message: string) => void;
  private interfaceNumber = -1;
  private inEndpointNumber = 0;
  private outEndpointNumber = 0;
  private readBuffer: Uint8Array = EMPTY;
  private muxVersion = 0;
  private muxTxSeq = 0;
  private muxRxSeq = 0xffff;
  private sportCounter = 32000;
  private writeChain: Promise<void> = Promise.resolve();
  private packetChain: Promise<void> = Promise.resolve();
  private readonly connections = new Map<number, MuxTcpConnection>();
  private versionWaiter: {
    resolve: (version: number) => void;
    reject: (err: Error) => void;
  } | null = null;
  private reading = false;
  private closed = false;
  private handshakeDone = false;
  private readonly disconnectHandlers = new Set<UsbDisconnectHandler>();

  protected constructor(
    private readonly device: UsbDeviceLike,
    options: WebUsbMuxOptions = {},
  ) {
    this.transferSize = options.transferSize ?? DEFAULT_TRANSFER_SIZE;
    this.log = options.log ?? (() => undefined);
  }

  get isHandshakeDone(): boolean {
    return this.handshakeDone;
  }

  get negotiatedVersion(): number {
    return this.muxVersion;
  }

  /** Wraps an already-picked USB device without opening it yet. */
  static fromDevice(device: UsbDeviceLike, options: WebUsbMuxOptions = {}): WebUsbMux {
    return new WebUsbMux(device, options);
  }

  /**
   * Prompts the user to pick an iOS device, then opens it, selects the
   * configuration holding the usbmux interface, claims the interface and
   * resolves its bulk IN/OUT endpoints. Call {@link handshake} next.
   */
  static async requestDevice(options: WebUsbMuxOptions = {}): Promise<WebUsbMux> {
    const usb = getWebUsbApi();
    if (!usb) {
      throw new Error('WebUSB is not available in this environment');
    }
    const device = await usb.requestDevice({ filters: buildAppleUsbFilters() });
    const mux = new WebUsbMux(device, options);
    await mux.openUsb();
    return mux;
  }

  /**
   * Reconnects to an already-authorized Apple device without prompting the
   * user. Uses `navigator.usb.getDevices()` to find a previously granted
   * device. Throws if none is found.
   */
  static async reconnect(options: WebUsbMuxOptions = {}): Promise<WebUsbMux> {
    const usb = getWebUsbApi();
    if (!usb) {
      throw new Error('WebUSB is not available in this environment');
    }
    const devices = await usb.getDevices();
    const device = devices.find((d: UsbDeviceLike) => d.vendorId === APPLE_VENDOR_ID);
    if (!device) {
      throw new Error('reconnect: no authorized Apple device found; please re-plug and select the device');
    }
    const mux = WebUsbMux.fromDevice(device, options);
    await mux.openUsb();
    await mux.handshake();
    return mux;
  }

  /**
   * Opens the USB device: open -> selectConfiguration -> claimInterface,
   * resolves the bulk endpoints and starts the read loop. Idempotent.
   */
  async openUsb(): Promise<void> {
    if (this.reading) {
      return;
    }
    const found = findUsbmuxInterface(this.device);
    if (!found) {
      throw new Error('No usbmux USB interface found (class 255 / subclass 254 / protocol 2)');
    }
    if (!this.device.opened) {
      await this.device.open();
    }
    const selected = this.device.configuration?.configurationValue ?? null;
    if (selected !== found.configuration.configurationValue) {
      // iOS devices normally expose the usbmux interface on configuration 1.
      await this.device.selectConfiguration(found.configuration.configurationValue);
    }
    if (!found.usbInterface.claimed) {
      await this.device.claimInterface(found.usbInterface.interfaceNumber);
    }
    const endpoints = findBulkEndpoints(found.usbInterface);
    if (!endpoints.in || !endpoints.out) {
      throw new Error('usbmux bulk IN/OUT endpoints not found');
    }
    this.interfaceNumber = found.usbInterface.interfaceNumber;
    this.inEndpointNumber = endpoints.in.endpointNumber;
    this.outEndpointNumber = endpoints.out.endpointNumber;

    this.reading = true;
    this.closed = false;
    getWebUsbApi()?.addEventListener('disconnect', this.usbDisconnectListener);
    void this.readLoop();
  }

  /**
   * Runs the MUX handshake: legacy 8-byte VERSION request, then — when the
   * device reports version >= 2 — switches to 16-byte headers and sends SETUP.
   * Returns the negotiated version.
   */
  async handshake(timeoutMs = 4000): Promise<number> {
    if (this.handshakeDone) {
      return this.muxVersion;
    }
    if (this.closed) {
      throw new Error('WebUSB MUX is closed');
    }

    const payload = new Uint8Array(12);
    dataViewOf(payload).setUint32(0, 2, false); // request MUX v2 (minor/pad = 0)

    let resolve!: (version: number) => void;
    let reject!: (err: Error) => void;
    const promise = new Promise<number>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const timer = setTimeout(() => {
      this.versionWaiter = null;
      reject(new Error(`MUX version timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    this.versionWaiter = {
      resolve: (version: number) => {
        clearTimeout(timer);
        resolve(version);
      },
      reject: (err: Error) => {
        clearTimeout(timer);
        reject(err);
      },
    };

    try {
      // muxVersion is still 0 here, so this goes out with a legacy 8-byte header.
      await this.sendMuxPacket(MUX_PROTO_VERSION, payload);
      const version = await promise;
      if (version >= 2) {
        // Switch to 16-byte headers; SETUP resets the sequence numbers.
        await this.sendMuxPacket(MUX_PROTO_SETUP, new Uint8Array([0x07]), { resetSeq: true });
      }
      this.handshakeDone = true;
      this.log(`MUX handshake complete (version=${version}).`);
      return version;
    } finally {
      clearTimeout(timer);
      this.versionWaiter = null;
    }
  }

  /**
   * Opens a TCP-over-MUX connection to `port` on the device and returns it.
   * Retries the SYN on timeout/refusal according to `options` (defaults
   * mirror DirectUsbMuxClient).
   */
  async connect(port: number, options: MuxConnectOptions = {}): Promise<MuxTcpConnection> {
    if (!this.handshakeDone) {
      throw new Error('MUX handshake is not completed');
    }
    if (this.closed) {
      throw new Error('WebUSB MUX is closed');
    }
    const timeoutMs = options.timeoutMs ?? 5000;
    const retryBaseMs = options.retryBaseMs ?? 900;
    const maxAttempts = options.maxAttempts ?? (port === LOCKDOWN_PORT ? 1 : 6);
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const sport = this.nextSport();
      const conn = new MuxTcpConnection(
        sport,
        port,
        (header, payload) => this.sendTcpMuxPacket(header, payload),
        (terminated) => {
          this.connections.delete(terminated.sport);
        },
      );
      this.connections.set(sport, conn);
      try {
        await conn.open(timeoutMs);
        return conn;
      } catch (error) {
        this.connections.delete(sport);
        const err = error instanceof Error ? error : new Error(String(error));
        lastError = err;
        const retryable = /refused|timeout/i.test(err.message);
        if (attempt < maxAttempts && retryable) {
          await sleep(Math.min(retryBaseMs * attempt, 4000));
          continue;
        }
        throw err;
      }
    }
    throw lastError ?? new Error(`TCP connect failed (dport=${port})`);
  }

  /** Convenience: connect to lockdownd (port 62078). */
  async connectLockdown(): Promise<MuxTcpConnection> {
    return this.connect(LOCKDOWN_PORT, { maxAttempts: 1 });
  }

  /**
   * Registers a device-disconnect listener. The underlying mechanism is the
   * `disconnect` event on navigator.usb (the `navigator.usb.ondisconnect`
   * handler slot). Returns an unsubscribe function.
   */
  onDisconnect(handler: UsbDisconnectHandler): () => void {
    this.disconnectHandlers.add(handler);
    return () => {
      this.disconnectHandlers.delete(handler);
    };
  }

  /** Releases the interface, stops the read loop and RSTs open connections. */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.reading = false;
    getWebUsbApi()?.removeEventListener('disconnect', this.usbDisconnectListener);
    const conns = Array.from(this.connections.values());
    this.connections.clear();
    for (const conn of conns) {
      try {
        conn.close();
      } catch {
        /* ignore */
      }
    }
    this.versionWaiter?.reject(new Error('WebUSB MUX closed'));
    this.versionWaiter = null;
    this.packetChain = Promise.resolve();
    try {
      if (this.device.opened) {
        if (this.interfaceNumber >= 0) {
          await this.device.releaseInterface(this.interfaceNumber).catch(() => undefined);
        }
        await this.device.close();
      }
    } catch {
      /* ignore */
    }
  }

  private nextSport(): number {
    for (;;) {
      this.sportCounter += 1;
      if (this.sportCounter > 65000) {
        this.sportCounter = 32000;
      }
      if (!this.connections.has(this.sportCounter)) {
        return this.sportCounter;
      }
    }
  }

  private async sendTcpMuxPacket(header: TcpHeaderFields, payload: Uint8Array): Promise<void> {
    await this.sendMuxPacket(MUX_PROTO_TCP, encodeTcpPacket(header, payload));
  }

  private async sendMuxPacket(
    protocol: number,
    payload: Uint8Array,
    options: { resetSeq?: boolean } = {},
  ): Promise<void> {
    const v2 = this.muxVersion >= 2;
    if (v2 && options.resetSeq) {
      this.muxTxSeq = 0;
      this.muxRxSeq = 0xffff;
    }
    const packet = encodeMuxPacket(protocol, payload, {
      version: this.muxVersion,
      txSeq: this.muxTxSeq,
      rxSeq: this.muxRxSeq,
    });
    if (v2) {
      this.muxTxSeq = (this.muxTxSeq + 1) & 0xffff;
    }
    // Copy to a standalone ArrayBuffer: transferOut must not see a view over a
    // larger or shared buffer.
    const bytes = packet.slice().buffer as ArrayBuffer;
    // Serialize USB writes; a failed write must not break the chain.
    const task = this.writeChain
      .then(() => this.device.transferOut(this.outEndpointNumber, bytes))
      .then((result) => {
        if (result.status !== 'ok') {
          throw new Error(`USB transferOut failed with status "${result.status}"`);
        }
      });
    this.writeChain = task.catch(() => undefined);
    await task;
  }

  private async readLoop(): Promise<void> {
    while (this.reading && !this.closed) {
      let result: UsbInTransferResultLike;
      try {
        result = await this.device.transferIn(this.inEndpointNumber, this.transferSize);
      } catch (error) {
        if (this.reading && !this.closed) {
          this.handleDisconnect(error);
        }
        return;
      }
      if (!this.reading || this.closed) {
        return;
      }
      if (result.status === 'ok' && result.data) {
        const view = result.data;
        this.onUsbData(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
      } else if (result.status === 'stall') {
        try {
          await this.device.clearHalt?.('in', this.inEndpointNumber);
        } catch {
          /* ignore */
        }
      }
    }
  }

  private onUsbData(data: Uint8Array): void {
    if (data.byteLength === 0) {
      return;
    }
    const merged = new Uint8Array(this.readBuffer.byteLength + data.byteLength);
    merged.set(this.readBuffer, 0);
    merged.set(data, this.readBuffer.byteLength);
    this.readBuffer = merged;
    this.drainMuxPackets();
  }

  private drainMuxPackets(): void {
    const buf = this.readBuffer;
    let offset = 0;
    while (buf.byteLength - offset >= MUX_LEGACY_HEADER_SIZE) {
      const length = dataViewOf(buf).getUint32(offset + 4, false);
      if (length < MUX_LEGACY_HEADER_SIZE || length > MAX_MUX_PACKET) {
        this.readBuffer = EMPTY;
        return;
      }
      if (buf.byteLength - offset < length) {
        break;
      }
      const packet = buf.slice(offset, offset + length);
      offset += length;
      this.enqueuePacket(packet);
    }
    if (offset > 0) {
      this.readBuffer = buf.slice(offset);
    }
  }

  private enqueuePacket(packet: Uint8Array): void {
    const task = this.packetChain.then(() => this.handleMuxPacket(packet));
    this.packetChain = task.catch((error) => {
      this.log(`MUX packet handler error: ${error instanceof Error ? error.message : String(error)}`);
    });
  }

  private async handleMuxPacket(packet: Uint8Array): Promise<void> {
    const v2 = this.muxVersion >= 2;
    const header = decodeMuxHeader(packet, this.muxVersion);
    if (v2) {
      if (header.magic !== MUX_MAGIC_HOST && header.magic !== MUX_MAGIC_DEVICE_ALT) {
        this.log(`Unexpected MUX magic: 0x${header.magic.toString(16)}.`);
      }
      // Mirrors DirectUsbMuxClient: the host's rx_seq tracks the u16 at
      // header offset 14 of incoming v2 packets.
      this.muxRxSeq = header.rxSeq;
    }
    const payload = packet.slice(v2 ? MUX_V2_HEADER_SIZE : MUX_LEGACY_HEADER_SIZE);
    switch (header.protocol) {
      case MUX_PROTO_VERSION:
        this.handleVersionPacket(payload);
        return;
      case MUX_PROTO_CONTROL:
        return; // nothing to do
      case MUX_PROTO_TCP:
        await this.handleTcpPayload(payload);
        return;
      default:
        this.log(`Unhandled MUX protocol=${header.protocol}, len=${payload.byteLength}.`);
    }
  }

  private handleVersionPacket(payload: Uint8Array): void {
    const waiter = this.versionWaiter;
    this.versionWaiter = null;
    if (!waiter) {
      return;
    }
    if (payload.byteLength < 12) {
      waiter.reject(new Error('MUX version packet too small'));
      return;
    }
    const major = dataViewOf(payload).getUint32(0, false);
    this.muxVersion = major;
    waiter.resolve(major);
  }

  private async handleTcpPayload(payload: Uint8Array): Promise<void> {
    let decoded: { header: TcpHeaderFields; payload: Uint8Array };
    try {
      decoded = decodeTcpPacket(payload);
    } catch {
      return;
    }
    const conn = this.connections.get(decoded.header.dport);
    if (!conn || conn.dport !== decoded.header.sport) {
      return;
    }
    await conn.handlePacket(decoded.header, decoded.payload);
  }

  private readonly usbDisconnectListener = (event: { device?: UsbDeviceLike }): void => {
    if (event.device === this.device) {
      this.handleDisconnect(new Error('USB device disconnected'));
    }
  };

  private handleDisconnect(reason: unknown): void {
    if (this.closed) {
      return;
    }
    const err = reason instanceof Error ? reason : new Error(`USB disconnected: ${String(reason)}`);
    this.log(`USB disconnected: ${err.message}`);
    this.closed = true;
    this.reading = false;
    getWebUsbApi()?.removeEventListener('disconnect', this.usbDisconnectListener);
    this.versionWaiter?.reject(err);
    this.versionWaiter = null;
    const conns = Array.from(this.connections.values());
    this.connections.clear();
    for (const conn of conns) {
      try {
        conn.abort(err);
      } catch {
        /* ignore */
      }
    }
    this.packetChain = Promise.resolve();
    for (const handler of this.disconnectHandlers) {
      try {
        handler(err);
      } catch {
        /* listener errors must not break teardown */
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* WebUsbMuxDevice — high-level facade implementing Transport           */
/* ------------------------------------------------------------------ */

export interface WebUsbMuxDeviceOptions extends WebUsbMuxOptions {
  /** USB vendor ID for the browser picker; defaults to Apple (0x05ac). */
  vendorId?: number;
}

/**
 * High-level WebUSB MUX device handle implementing {@link Transport}.
 *
 * Flow:
 * ```ts
 * const device = await WebUsbMuxDevice.requestDevice(); // browser picker
 * await device.open();                                  // USB + MUX handshake
 * const lockdown = await device.createTcpConnection(0, LOCKDOWN_PORT);
 * // `lockdown` is a Transport over the lockdownd stream.
 * ```
 *
 * `read`/`write` on the device itself target the active TCP connection
 * (this implementation multiplexes a single TCP stream at a time, like
 * webmuxd's DirectUsbMuxClient); `close()` tears down the whole USB link.
 */
export class WebUsbMuxDevice extends WebUsbMux implements Transport {
  private channel: MuxTcpChannel | null = null;

  constructor(device: UsbDeviceLike, options: WebUsbMuxDeviceOptions = {}) {
    super(device, options);
  }

  /** Whether WebUSB is available (Chromium + navigator.usb). */
  static isSupported(): boolean {
    return getWebUsbApi() !== null;
  }

  /**
   * Shows the browser's USB device picker (Apple vendor filter). Resolves
   * with an unopened device — call {@link open} next.
   *
   * Throws {@link WebUsbMuxError} with a clear message when WebUSB is
   * unavailable or when the user cancels the picker (instead of the raw
   * NotFoundError DOMException).
   */
  static async requestDevice(options: WebUsbMuxDeviceOptions = {}): Promise<WebUsbMuxDevice> {
    const usb = getWebUsbApi();
    if (!usb) {
      throw new WebUsbMuxError(
        'WebUSB 無法使用：請使用支援 WebUSB 的 Chromium 瀏覽器（Chrome / Edge），' +
          '並以 HTTPS 或 localhost 開啟本頁面。',
      );
    }
    const vendorId = options.vendorId ?? APPLE_VENDOR_ID;
    let device: UsbDeviceLike;
    try {
      device = await usb.requestDevice({ filters: [{ vendorId }] });
    } catch (err) {
      if (typeof DOMException !== 'undefined' && err instanceof DOMException && err.name === 'NotFoundError') {
        throw new WebUsbMuxError(
          '已取消 USB 裝置選擇：請在瀏覽器彈出的裝置清單中選擇你的 iPhone / iPad。',
          { cause: err },
        );
      }
      throw new WebUsbMuxError(
        `USB 裝置選擇失敗：${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    return new WebUsbMuxDevice(device, options);
  }

  /**
   * Opens the USB device (open -> selectConfiguration -> claimInterface)
   * and runs the MUX VERSION/SETUP handshake.
   */
  async open(): Promise<void> {
    await this.openUsb();
    await this.handshake();
  }

  /**
   * Opens one TCP-over-MUX connection to `port` on the device (e.g.
   * lockdownd's 62078) and returns it as a {@link Transport}.
   *
   * @param deviceId Device ID. On a direct WebUSB link there is exactly one
   *   device, so this is only validated as a non-negative integer (kept for
   *   signature compatibility with the usbmuxd daemon's multi-device model).
   */
  async createTcpConnection(deviceId: number, port: number): Promise<Transport> {
    if (!Number.isInteger(deviceId) || deviceId < 0) {
      throw new WebUsbMuxError(`deviceId 必須是非負整數（收到 ${String(deviceId)}）`);
    }
    if (!Number.isInteger(port) || port <= 0 || port > 0xffff) {
      throw new WebUsbMuxError(`port 必須是 1–65535 的整數（收到 ${String(port)}）`);
    }
    if (!this.isHandshakeDone) {
      throw new WebUsbMuxError('請先呼叫 open() 完成 MUX 交握，才能建立 TCP 連線');
    }
    if (this.channel) {
      throw new WebUsbMuxError(
        'MUX 上已有作用中的 TCP 連線；本實作一次只支援一條連線，請先關閉舊連線',
      );
    }
    const conn = await this.connect(port);
    const channel = new MuxTcpChannel(conn, this);
    this.channel = channel;
    return channel;
  }

  /** Whether a TCP connection is currently active. */
  get hasTcpConnection(): boolean {
    return this.channel !== null;
  }

  /** Releases a channel handle (called by MuxTcpChannel.close()). */
  releaseChannel(channel: MuxTcpChannel): void {
    if (this.channel === channel) {
      this.channel = null;
    }
  }

  /* ---------------- Transport (targets the active TCP connection) ---------------- */

  /** Writes to the active TCP connection (chunked into TCP frames). */
  async write(data: Uint8Array): Promise<void> {
    return this.requireChannel().write(data);
  }

  /** Reads exactly n bytes from the active TCP connection. */
  async read(n: number): Promise<Uint8Array> {
    return this.requireChannel().read(n);
  }

  /** Alias of read(), compatible with usbmuxd.ts's ByteTransport. */
  readExact(n: number): Promise<Uint8Array> {
    return this.requireChannel().read(n);
  }

  /** Closes the TCP connection (if any) and the whole USB link. */
  async close(): Promise<void> {
    this.channel = null;
    await super.close();
  }

  private requireChannel(): MuxTcpChannel {
    const channel = this.channel;
    if (!channel) {
      throw new WebUsbMuxError('沒有作用中的 TCP 連線：請先呼叫 createTcpConnection()');
    }
    return channel;
  }
}

/**
 * The {@link Transport} returned by
 * {@link WebUsbMuxDevice.createTcpConnection}. `close()` only tears down this
 * TCP stream (sends RST); the USB device and MUX session stay open so a new
 * connection can be created afterwards.
 */
export class MuxTcpChannel implements Transport {
  constructor(
    private readonly conn: MuxTcpConnection,
    private readonly owner: WebUsbMuxDevice,
  ) {}

  get isConnected(): boolean {
    return this.conn.isConnected;
  }

  write(data: Uint8Array): Promise<void> {
    return this.conn.write(data);
  }

  read(n: number): Promise<Uint8Array> {
    return this.conn.readExact(n);
  }

  /** Alias of read(), compatible with usbmuxd.ts's ByteTransport. */
  readExact(n: number): Promise<Uint8Array> {
    return this.conn.readExact(n);
  }

  async close(): Promise<void> {
    try {
      this.conn.close();
    } finally {
      this.owner.releaseChannel(this);
    }
  }
}

/* ------------------------------------------------------------------ */
/* TcpTransport — node:net TCP transport for non-WebUSB environments    */
/* ------------------------------------------------------------------ */

interface NodeNetSocketLike {
  once(event: 'connect' | 'error', listener: (err?: unknown) => void): unknown;
  on(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  on(event: 'error' | 'close', listener: () => void): unknown;
  write(data: Uint8Array, callback?: (err?: Error) => void): boolean;
  destroy(): void;
}

interface NodeNetModuleLike {
  createConnection(options: { host: string; port: number }): NodeNetSocketLike;
}

async function loadNodeNet(): Promise<NodeNetModuleLike> {
  // usbmuxd.ts in this project already carries an ambient
  // `declare module 'node:net'`; cast through unknown so this module does
  // not couple itself to that declaration's exact shape.
  const mod = await import('node:net');
  return mod as unknown as NodeNetModuleLike;
}

interface PendingTcpRead {
  n: number;
  resolve: (data: Uint8Array) => void;
  reject: (reason?: unknown) => void;
}

/**
 * {@link Transport} over a node:net TCP socket, for Node.js / bun
 * environments without WebUSB — e.g. talking to a local usbmuxd daemon at
 * 127.0.0.1:27015 and handing the transport to usbmuxd.ts's UsbmuxdClient.
 *
 * The connection is established lazily on first read/write, or eagerly via
 * {@link connect}.
 */
export class TcpTransport implements Transport {
  private socket: NodeNetSocketLike | null = null;
  private dialing: Promise<NodeNetSocketLike> | null = null;
  private recvBuffer: Uint8Array = new Uint8Array(0);
  private readonly waiters: PendingTcpRead[] = [];
  private closed = false;

  constructor(
    private readonly host: string,
    private readonly port: number,
  ) {
    if (typeof host !== 'string' || host.length === 0) {
      throw new WebUsbMuxError('TcpTransport 的 host 不可為空');
    }
    if (!Number.isInteger(port) || port <= 0 || port > 0xffff) {
      throw new WebUsbMuxError(`TcpTransport 的 port 必須是 1–65535 的整數（收到 ${String(port)}）`);
    }
  }

  get isConnected(): boolean {
    return this.socket !== null;
  }

  /** Establishes the TCP connection now (otherwise done lazily). */
  async connect(): Promise<void> {
    await this.ensureConnected();
  }

  async write(data: Uint8Array): Promise<void> {
    const socket = await this.ensureConnected();
    if (this.closed) {
      throw new WebUsbMuxError('TcpTransport 已關閉，無法寫入');
    }
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    await new Promise<void>((resolve, reject) => {
      socket.write(copy, (err?: Error) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /** Reads exactly n bytes, waiting for more data if necessary. */
  async read(n: number): Promise<Uint8Array> {
    if (!Number.isInteger(n) || n <= 0) {
      throw new WebUsbMuxError(`read 的長度必須是正整數（收到 ${String(n)}）`);
    }
    await this.ensureConnected();
    if (this.closed) {
      throw new WebUsbMuxError('TcpTransport 已關閉，無法讀取');
    }
    if (this.recvBuffer.byteLength >= n) {
      const out = this.recvBuffer.slice(0, n);
      this.recvBuffer = this.recvBuffer.slice(n);
      return out;
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
    });
  }

  /** Alias of read(), compatible with usbmuxd.ts's ByteTransport. */
  readExact(n: number): Promise<Uint8Array> {
    return this.read(n);
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.failAll(new WebUsbMuxError('TcpTransport 已關閉'));
    this.dialing = null;
    const socket = this.socket;
    this.socket = null;
    try {
      socket?.destroy();
    } catch {
      /* ignore */
    }
  }

  private ensureConnected(): Promise<NodeNetSocketLike> {
    if (this.socket) {
      return Promise.resolve(this.socket);
    }
    if (this.closed) {
      return Promise.reject(new WebUsbMuxError('TcpTransport 已關閉，無法再連線'));
    }
    if (!this.dialing) {
      this.dialing = this.dial().catch((err: unknown) => {
        this.dialing = null;
        throw err;
      });
    }
    return this.dialing;
  }

  private async dial(): Promise<NodeNetSocketLike> {
    let net: NodeNetModuleLike;
    try {
      net = await loadNodeNet();
    } catch (err) {
      throw new WebUsbMuxError('TcpTransport 需要 Node.js / bun 環境（無法載入 node:net）', {
        cause: err,
      });
    }
    const socket = net.createConnection({ host: this.host, port: this.port });
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      socket.once('connect', () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      });
      socket.once('error', (err) => {
        if (!settled) {
          settled = true;
          reject(err instanceof Error ? err : new WebUsbMuxError(`TCP 連線失敗：${String(err)}`));
        }
      });
    });
    if (this.closed) {
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      throw new WebUsbMuxError('TcpTransport 在連線完成前已關閉');
    }
    socket.on('data', (chunk) => this.onSocketData(chunk));
    // A 'close' always follows 'error'; onSocketClose() owns cleanup, and
    // this empty error listener prevents an unhandled 'error' throw.
    socket.on('error', () => undefined);
    socket.on('close', () => this.onSocketClose());
    this.socket = socket;
    return socket;
  }

  private onSocketData(chunk: Uint8Array): void {
    this.recvBuffer = concatBytes(this.recvBuffer, new Uint8Array(chunk));
    while (this.waiters.length > 0) {
      const waiter = this.waiters[0];
      if (!waiter || this.recvBuffer.byteLength < waiter.n) {
        break;
      }
      this.waiters.shift();
      const out = this.recvBuffer.slice(0, waiter.n);
      this.recvBuffer = this.recvBuffer.slice(waiter.n);
      waiter.resolve(out);
    }
  }

  private onSocketClose(): void {
    this.socket = null;
    if (this.closed) {
      return;
    }
    this.failAll(new WebUsbMuxError('TCP 連線已中斷（socket close）'));
  }

  private failAll(err: unknown): void {
    const waiters = this.waiters.splice(0);
    for (const waiter of waiters) {
      waiter.reject(err);
    }
  }
}

/** Concatenates two byte arrays (returns a copy). */
function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) {
    return right.slice();
  }
  if (right.byteLength === 0) {
    return left.slice();
  }
  const merged = new Uint8Array(left.byteLength + right.byteLength);
  merged.set(left, 0);
  merged.set(right, left.byteLength);
  return merged;
}
