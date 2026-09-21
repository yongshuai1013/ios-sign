/**
 * usbmuxd client — TypeScript port of the Rust `idevice` crate's `usbmuxd`
 * module (`usbmuxd/mod.rs`, `usbmuxd/raw_packet.rs`), plus the `PlistSocket`
 * framing used by lockdownd / installation_proxy.
 *
 * usbmuxd (USB Multiplexing Daemon, default TCP 127.0.0.1:27015) manages
 * connections to iOS devices over USB/network and stores host pairing records.
 *
 * Wire format (mirrors `RawPacket`):
 *   header = 4 x little-endian u32: length (includes the 16-byte header),
 *            version, message type, tag
 *   body   = XML plist
 * Requests use version=1 (XML) and message type=8 (PLIST message).
 *
 * After `UsbmuxdClient.connect()` succeeds, the underlying TCP connection is
 * redirected to the device; the returned {@link PlistSocket} then speaks the
 * 4-byte big-endian length-prefixed XML plist framing used by lockdownd and
 * installation_proxy.
 */

import plist from 'plist';
import type { PlistObject } from 'plist';

/* ------------------------------------------------------------------ */
/* Transport abstraction                                               */
/* ------------------------------------------------------------------ */

/**
 * Minimal byte-stream every client in this package runs on.
 *
 * `read(n)` resolves with **exactly** `n` bytes (buffering internally as
 * needed) and rejects if the stream ends before `n` bytes arrive.
 * Browser code supplies its own implementation (e.g. over WebUSB); Node or
 * Electron-main code can use {@link createNodeTcpTransport}.
 */
export interface Transport {
  read(n: number): Promise<Uint8Array>;
  write(data: Uint8Array): Promise<void>;
  close(): void;
}

/** Backwards-compatible alias kept for sibling modules. */
export type ByteTransport = Transport;

// Minimal structural types for `node:net` so that the dynamic import below
// typechecks without `@types/node` installed. Only used by
// `createNodeTcpTransport`, which never runs in the browser.
declare module 'node:net' {
  interface NodeTcpSocket {
    once(event: 'connect', listener: () => void): this;
    once(event: 'error', listener: (err: Error) => void): this;
    on(event: 'data', listener: (chunk: Uint8Array) => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
    on(event: 'close', listener: () => void): this;
    write(data: Uint8Array, cb?: (err?: Error) => void): boolean;
    destroy(): this;
  }
  function createConnection(options: { host: string; port: number }): NodeTcpSocket;
}

/**
 * Creates a {@link Transport} over a Node TCP socket.
 * Node/Electron-main only — keep the static import graph browser-safe by
 * importing `node:net` dynamically.
 */
export async function createNodeTcpTransport(host: string, port: number): Promise<Transport> {
  const net = await import('node:net');
  const socket = net.createConnection({ host, port });
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('error', (err) => reject(err));
  });

  let buffered = new Uint8Array(0);
  let waiters: Array<{
    n: number;
    resolve: (data: Uint8Array) => void;
    reject: (err: Error) => void;
  }> = [];

  const pump = (): void => {
    while (waiters.length > 0 && buffered.length >= waiters[0].n) {
      const w = waiters.shift()!;
      const out = buffered.subarray(0, w.n);
      buffered = buffered.subarray(w.n);
      w.resolve(out);
    }
  };
  const failAll = (err: Error): void => {
    const pending = waiters;
    waiters = [];
    for (const w of pending) w.reject(err);
  };

  socket.on('data', (chunk: Uint8Array) => {
    const next = new Uint8Array(buffered.length + chunk.length);
    next.set(buffered, 0);
    next.set(chunk, buffered.length);
    buffered = next;
    pump();
  });
  socket.on('error', (err) => failAll(err));
  socket.on('close', () => failAll(new Error('socket closed while reading')));

  return {
    read: (n: number) =>
      new Promise<Uint8Array>((resolve, reject) => {
        if (!Number.isInteger(n) || n < 0) {
          reject(new Error(`invalid read length ${n}`));
          return;
        }
        waiters.push({ n, resolve, reject });
        pump();
      }),
    write: (data: Uint8Array) =>
      new Promise<void>((resolve, reject) => {
        socket.write(data, (err?: Error) => (err ? reject(err) : resolve()));
      }),
    close: () => {
      socket.destroy();
    },
  };
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/** Return a copy backed by exactly `src.byteLength` bytes.
 *  (`plist.build` base64-encodes a typed array's whole underlying buffer,
 *  so views with a nonzero offset must be copied first.) */
export function copyBytes(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(src.byteLength);
  out.set(src);
  return out;
}

function dataViewOf(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/* ------------------------------------------------------------------ */
/* usbmuxd packet codec                                                */
/* ------------------------------------------------------------------ */

/** Default usbmuxd TCP port. */
export const USBMUXD_DEFAULT_PORT = 27015;
/** Default lockdownd TCP port on the device. */
export const LOCKDOWN_PORT = 62078;

/** XML plist protocol version (`UsbmuxdConnection::XML_PLIST_VERSION`). */
const USBMUXD_VERSION_XML = 1;
/** PLIST message type (`UsbmuxdConnection::PLIST_MESSAGE_TYPE`). */
const USBMUXD_MESSAGE_PLIST = 8;

export interface UsbmuxdPacket {
  length: number;
  version: number;
  message: number;
  tag: number;
  dict: Record<string, unknown>;
}

/** Serializes one usbmuxd packet: 16-byte LE header + XML plist body. */
export function encodeUsbmuxdPacket(dict: Record<string, unknown>, tag: number): Uint8Array {
  const body = new TextEncoder().encode(plist.build(dict as unknown as PlistObject));
  const packet = new Uint8Array(16 + body.length);
  const view = dataViewOf(packet);
  view.setUint32(0, body.length + 16, true); // length includes the header
  view.setUint32(4, USBMUXD_VERSION_XML, true);
  view.setUint32(8, USBMUXD_MESSAGE_PLIST, true);
  view.setUint32(12, tag >>> 0, true);
  packet.set(body, 16);
  return packet;
}

/** Parses one usbmuxd packet. */
export function decodeUsbmuxdPacket(packet: Uint8Array): UsbmuxdPacket {
  if (packet.length < 16) {
    throw new UsbmuxdError(-1, 'usbmuxd packet shorter than 16-byte header');
  }
  const view = dataViewOf(packet);
  const length = view.getUint32(0, true);
  if (packet.length < length) {
    throw new UsbmuxdError(-1, 'truncated usbmuxd packet');
  }
  const xml = new TextDecoder().decode(packet.subarray(16, length));
  return {
    length,
    version: view.getUint32(4, true),
    message: view.getUint32(8, true),
    tag: view.getUint32(12, true),
    dict: plist.parse(xml) as Record<string, unknown>,
  };
}

/* ------------------------------------------------------------------ */
/* PlistSocket: 4-byte length-prefixed plist framing                   */
/* ------------------------------------------------------------------ */

/** Maximum accepted plist frame body (8 MiB); guards against corrupt lengths. */
export const MAX_PLIST_FRAME = 8 * 1024 * 1024;

/**
 * A plist request/response channel over a raw device stream (lockdownd,
 * installation_proxy). Frames are `u32 big-endian length + XML plist body`,
 * mirroring Rust `Idevice::send_plist` / `read_plist_value`.
 *
 * Construct one directly, or obtain one from {@link UsbmuxdClient.connect}.
 * The socket never reads past a frame boundary, so the underlying
 * {@link Transport} can be re-wrapped (e.g. for the StartSession TLS
 * upgrade) after the socket is discarded.
 */
export class PlistSocket {
  constructor(readonly transport: Transport) {}

  /** Sends one length-prefixed XML plist. Binary values are copied so
   *  `plist.build` cannot leak adjacent buffer bytes. */
  async sendPlist(obj: Record<string, unknown>): Promise<void> {
    const body = new TextEncoder().encode(plist.build(sanitizeForPlist(obj) as unknown as PlistObject));
    const frame = new Uint8Array(4 + body.length);
    dataViewOf(frame).setUint32(0, body.length, false);
    frame.set(body, 4);
    await this.transport.write(frame);
  }

  /** Receives one length-prefixed XML plist. */
  async recvPlist(): Promise<Record<string, unknown>> {
    const header = await this.transport.read(4);
    const length = dataViewOf(header).getUint32(0, false);
    if (length > MAX_PLIST_FRAME) {
      throw new Error(`plist frame too large: ${length} bytes`);
    }
    const body = await this.transport.read(length);
    return plist.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
  }
}

/** Deep-copies every Uint8Array in a plist-bound object. */
function sanitizeForPlist(value: unknown): unknown {
  if (value instanceof Uint8Array) return copyBytes(value);
  if (Array.isArray(value)) return value.map(sanitizeForPlist);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sanitizeForPlist(v);
    }
    return out;
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* Usbmuxd client                                                      */
/* ------------------------------------------------------------------ */

/** Error from a usbmuxd `Connect` result (or local framing failures, code -1). */
export class UsbmuxdError extends Error {
  constructor(
    public readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = 'UsbmuxdError';
  }
}

// Mirrors `usbmuxd::errors::UsbmuxdError` mapping in `connect_to_device`.
const CONNECT_ERROR_NAMES: Record<number, string> = {
  1: 'BadCommand',
  2: 'BadDevice',
  3: 'ConnectionRefused',
  6: 'BadVersion',
};

export interface DeviceInfo {
  deviceId: number;
  udid: string;
}

/** Backwards-compatible alias. */
export type UsbmuxdDeviceInfo = DeviceInfo;

export class UsbmuxdClient {
  private tag = 1;

  /** `transport` must already be connected to usbmuxd (127.0.0.1:27015). */
  constructor(private readonly transport: Transport) {}

  /** Sends one request and reads the response dictionary. Tags increment from 1. */
  private async roundTrip(message: Record<string, unknown>): Promise<Record<string, unknown>> {
    const tag = this.tag++;
    await this.transport.write(encodeUsbmuxdPacket(message, tag));
    const header = await this.transport.read(16);
    const totalLength = dataViewOf(header).getUint32(0, true);
    if (totalLength < 16) {
      throw new UsbmuxdError(-1, `invalid usbmuxd packet length ${totalLength}`);
    }
    const body = await this.transport.read(totalLength - 16);
    return plist.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
  }

  /** Reads the host BUID (`ReadBUID`). */
  async readBUID(): Promise<string> {
    const res = await this.roundTrip({ MessageType: 'ReadBUID' });
    const buid = res['BUID'];
    if (typeof buid !== 'string') {
      throw new UsbmuxdError(-1, 'missing BUID string in ReadBUID response');
    }
    return buid;
  }

  /** Alias with the historical lowercase spelling. */
  readBuid(): Promise<string> {
    return this.readBUID();
  }

  /**
   * Connects to a TCP port on the device (`Connect`) and returns a
   * {@link PlistSocket} speaking the device-side protocol on it.
   * `port` is given in host byte order; it is byte-swapped to network byte
   * order for `PortNumber`, mirroring Rust's `port.to_be()`.
   * A non-zero `Number` result throws {@link UsbmuxdError}.
   *
   * After success the transport is owned by the returned socket — do not
   * issue further usbmuxd requests on this client with the same transport.
   */
  async connect(deviceId: number, port: number): Promise<PlistSocket> {
    const portNumber = (((port << 8) & 0xff00) | ((port >> 8) & 0xff)) >>> 0;
    const res = await this.roundTrip({
      MessageType: 'Connect',
      DeviceID: deviceId >>> 0,
      PortNumber: portNumber,
    });
    const number = res['Number'];
    if (number === 0) return new PlistSocket(this.transport);
    const code = typeof number === 'number' ? number : -1;
    const name = CONNECT_ERROR_NAMES[code] ?? 'Unknown';
    throw new UsbmuxdError(code, `usbmuxd Connect failed: ${name} (${code})`);
  }

  /** Lists attached devices (`ListDevices`). */
  async listDevices(): Promise<DeviceInfo[]> {
    const res = await this.roundTrip({
      MessageType: 'ListDevices',
      ClientVersionString: 'sideimpactor',
      kLibUSBMuxVersion: 3,
    });
    const list = res['DeviceList'];
    if (!Array.isArray(list)) {
      throw new UsbmuxdError(-1, 'missing DeviceList in ListDevices response');
    }
    const devices: DeviceInfo[] = [];
    for (const entry of list) {
      const e = entry as Record<string, unknown>;
      const props = e['Properties'] as Record<string, unknown> | undefined;
      const deviceId = e['DeviceID'];
      const udid = props?.['SerialNumber'];
      if (typeof deviceId === 'number' && typeof udid === 'string') {
        devices.push({ deviceId, udid });
      }
    }
    return devices;
  }

  /** Reads a stored pairing record (`ReadPairRecord`); returns raw plist bytes. */
  async getPairRecord(udid: string): Promise<Uint8Array> {
    const res = await this.roundTrip({
      MessageType: 'ReadPairRecord',
      PairRecordID: udid,
    });
    const data = res['PairRecordData'];
    if (!(data instanceof Uint8Array)) {
      throw new UsbmuxdError(-1, 'missing PairRecordData in pair record response');
    }
    return copyBytes(data);
  }

  /** Stores a pairing record (`SavePairRecord`); `data` is a serialized plist. */
  async savePairRecord(udid: string, data: Uint8Array): Promise<void> {
    const res = await this.roundTrip({
      MessageType: 'SavePairRecord',
      PairRecordData: copyBytes(data),
      PairRecordID: udid,
    });
    this.expectSuccess(res, 'SavePairRecord');
  }

  /** Deletes a stored pairing record (`DeletePairRecord`). */
  async deletePairRecord(udid: string): Promise<void> {
    const res = await this.roundTrip({
      MessageType: 'DeletePairRecord',
      PairRecordID: udid,
    });
    this.expectSuccess(res, 'DeletePairRecord');
  }

  private expectSuccess(res: Record<string, unknown>, op: string): void {
    if (res['Number'] !== 0) {
      throw new UsbmuxdError(-1, `${op} did not return success (Number=${String(res['Number'])})`);
    }
  }
}
