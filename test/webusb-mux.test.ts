/**
 * Unit tests for the pure-logic parts of webusb-mux.ts plus the Node-side
 * transports. Everything here runs without real USB hardware.
 *
 * NOTE on byte order: the MUX and TCP header fields are big-endian on the
 * wire, exactly mirroring SideImpactor's webmuxd `DirectUsbMuxClient`
 * (DataView with littleEndian=false), which is proven against real iOS
 * hardware. The little-endian variant could never complete the VERSION
 * handshake against a real device (the length field would parse as
 * 0x14000000), so big-endian is the on-the-wire format.
 */
import { describe, expect, test } from 'bun:test';
import {
  APPLE_VENDOR_ID,
  LOCKDOWN_PORT,
  MUX_MAGIC_HOST,
  MUX_PROTO_TCP,
  MUX_PROTO_VERSION,
  TCP_FLAG_ACK,
  TCP_FLAG_RST,
  TCP_FLAG_SYN,
  WebUsbMuxDevice,
  WebUsbMuxError,
  TcpTransport,
  buildAppleUsbFilters,
  decodeMuxHeader,
  decodeTcpPacket,
  encodeMuxHeader,
  encodeMuxPacket,
  encodeTcpPacket,
  MuxTcpConnection,
  type MuxEncodeOptions,
  type TcpHeaderFields,
  type UsbDeviceLike,
} from '../src/pairing/webusb-mux.js';

/* ---------------- small async helpers (bun:test has no rejects.toThrow here) ---- */

async function captureReject(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (err) {
    return err;
  }
  return null;
}

async function expectRejects(fn: () => Promise<unknown>, match?: RegExp): Promise<void> {
  const err = await captureReject(fn);
  expect(err instanceof Error).toBe(true);
  if (match) {
    expect(match.test((err as Error).message)).toBe(true);
  }
}

function expectThrowsSync(fn: () => unknown, match: RegExp): void {
  let err: unknown = null;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  expect(err instanceof Error).toBe(true);
  expect(match.test((err as Error).message)).toBe(true);
}

/* ------------------------------------------------------------------ */

describe('MUX framing (big-endian)', () => {
  test('v2 16-byte header round trip', () => {
    const header = encodeMuxHeader(MUX_PROTO_TCP, 16 + 20, { version: 2, txSeq: 7, rxSeq: 0xffff });
    expect(header.length).toBe(16);
    // protocol + total length, big-endian
    expect(header[0]).toBe(0);
    expect(header[3]).toBe(MUX_PROTO_TCP);
    expect(header[4]).toBe(0);
    expect(header[7]).toBe(36);
    // magic 0xfeedface, big-endian
    expect(Array.from(header.slice(8, 12))).toEqual([0xfe, 0xed, 0xfa, 0xce]);
    expect(MUX_MAGIC_HOST).toBe(0xfeedface);
    // tx_seq = 7, rx_seq = 0xffff, big-endian
    expect(header[12]).toBe(0);
    expect(header[13]).toBe(7);
    expect(header[14]).toBe(0xff);
    expect(header[15]).toBe(0xff);

    const decoded = decodeMuxHeader(header, 2);
    expect(decoded.protocol).toBe(MUX_PROTO_TCP);
    expect(decoded.length).toBe(36);
    expect(decoded.magic).toBe(0xfeedface);
    expect(decoded.txSeq).toBe(7);
    expect(decoded.rxSeq).toBe(0xffff);
  });

  test('legacy 8-byte header round trip', () => {
    const header = encodeMuxHeader(MUX_PROTO_VERSION, 20, { version: 0 });
    expect(header.length).toBe(8);
    expect(header[0]).toBe(0);
    expect(header[3]).toBe(MUX_PROTO_VERSION);
    expect(header[4]).toBe(0);
    expect(header[7]).toBe(20); // length 20, big-endian

    const decoded = decodeMuxHeader(header, 1);
    expect(decoded.protocol).toBe(MUX_PROTO_VERSION);
    expect(decoded.length).toBe(20);
    expect(decoded.magic).toBe(0);
  });

  test('encodeMuxPacket concatenates header + payload and round trips', () => {
    const payload = new Uint8Array([1, 2, 3, 4]);
    const options: MuxEncodeOptions = { version: 2, txSeq: 3, rxSeq: 9 };
    const packet = encodeMuxPacket(MUX_PROTO_TCP, payload, options);
    expect(packet.length).toBe(20);
    expect(Array.from(packet.slice(16))).toEqual([1, 2, 3, 4]);

    const decoded = decodeMuxHeader(packet, 2);
    expect(decoded.protocol).toBe(MUX_PROTO_TCP);
    expect(decoded.length).toBe(20);
    expect(decoded.txSeq).toBe(3);
    expect(decoded.rxSeq).toBe(9);
  });

  test('decodeMuxHeader rejects truncated packets', () => {
    expectThrowsSync(() => decodeMuxHeader(new Uint8Array(15), 2), /shorter than 16-byte header/);
    expectThrowsSync(() => decodeMuxHeader(new Uint8Array(7), 1), /shorter than 8-byte header/);
  });
});

describe('TCP-over-MUX codec (big-endian)', () => {
  test('encode/decode round trip preserves fields and payload', () => {
    const header: TcpHeaderFields = {
      sport: 32001,
      dport: LOCKDOWN_PORT,
      seq: 0x12345678,
      ack: 42,
      flags: TCP_FLAG_ACK,
      window: 131072,
    };
    const payload = new Uint8Array([9, 8, 7]);
    const packet = encodeTcpPacket(header, payload);
    expect(packet.length).toBe(23);

    // sport 32001 = 0x7d01, big-endian
    expect(packet[0]).toBe(0x7d);
    expect(packet[1]).toBe(0x01);
    // seq 0x12345678, big-endian
    expect(Array.from(packet.slice(4, 8))).toEqual([0x12, 0x34, 0x56, 0x78]);
    // data offset byte: 5 words << 4
    expect(packet[12]).toBe(0x50);
    expect(packet[13]).toBe(TCP_FLAG_ACK);

    const decoded = decodeTcpPacket(packet);
    expect(decoded.header.sport).toBe(32001);
    expect(decoded.header.dport).toBe(LOCKDOWN_PORT);
    expect(decoded.header.seq).toBe(0x12345678);
    expect(decoded.header.ack).toBe(42);
    expect(decoded.header.flags).toBe(TCP_FLAG_ACK);
    expect(decoded.header.window).toBe(0xffff); // clamped to u16
    expect(Array.from(decoded.payload)).toEqual([9, 8, 7]);
  });

  test('decodeTcpPacket rejects truncated packets', () => {
    expectThrowsSync(() => decodeTcpPacket(new Uint8Array(19)), /shorter than 20-byte header/);
    const short = encodeTcpPacket(
      { sport: 1, dport: 2, seq: 0, ack: 0, flags: 0, window: 0 },
      EMPTY_TAIL,
    );
    short[12] = 0x60; // claim a 24-byte header
    expectThrowsSync(() => decodeTcpPacket(short), /invalid TCP data offset/);
  });
});

const EMPTY_TAIL = new Uint8Array(0);

describe('MuxTcpConnection handshake + data path', () => {
  function makePair() {
    const sent: Array<{ header: TcpHeaderFields; payload: Uint8Array }> = [];
    const conn = new MuxTcpConnection(32001, LOCKDOWN_PORT, async (header, payload) => {
      sent.push({ header, payload });
    });
    return { conn, sent };
  }

  /** Builds an inbound packet as the device would send it. */
  function devicePacket(
    flags: number,
    sport: number,
    dport: number,
    seq: number,
    payload: Uint8Array,
  ): { header: TcpHeaderFields; payload: Uint8Array } {
    const wire = encodeTcpPacket({ sport, dport, seq, ack: 0, flags, window: 0xffff }, payload);
    return decodeTcpPacket(wire);
  }

  test('open() sends SYN; SYN+ACK completes the handshake with an ACK', async () => {
    const { conn, sent } = makePair();
    const opened = conn.open(1000);
    expect(sent.length).toBe(1);
    expect(sent[0]?.header.flags).toBe(TCP_FLAG_SYN);

    const inbound = devicePacket(TCP_FLAG_SYN | TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 7000, EMPTY_TAIL);
    await conn.handlePacket(inbound.header, inbound.payload);

    await opened;
    expect(conn.isConnected).toBe(true);
    expect(sent.length).toBe(2);
    const ack = sent[1]?.header;
    expect(ack?.flags).toBe(TCP_FLAG_ACK);
    expect(ack?.seq).toBe(1); // SYN consumed one sequence number
    expect(ack?.ack).toBe(7001);
  });

  test('RST during handshake rejects open()', async () => {
    const { conn } = makePair();
    const opened = conn.open(1000);
    const inbound = devicePacket(TCP_FLAG_RST, LOCKDOWN_PORT, 32001, 0, EMPTY_TAIL);
    await conn.handlePacket(inbound.header, inbound.payload);
    await expectRejects(() => opened, /refused/);
    expect(conn.state).toBe('closed');
  });

  test('open() times out without a response', async () => {
    const { conn } = makePair();
    await expectRejects(() => conn.open(30), /timeout/);
    expect(conn.state).toBe('closed');
  });

  test('incoming data is buffered, ACKed, and readable via readExact', async () => {
    const { conn, sent } = makePair();
    const opened = conn.open(1000);
    const synAck = devicePacket(TCP_FLAG_SYN | TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 5000, EMPTY_TAIL);
    await conn.handlePacket(synAck.header, synAck.payload);
    await opened;

    const chunk = new Uint8Array([10, 20, 30]);
    const inbound = devicePacket(TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 5001, chunk);
    await conn.handlePacket(inbound.header, inbound.payload);

    // Last frame is the ACK for the received data.
    const last = sent[sent.length - 1]?.header;
    expect(last?.flags).toBe(TCP_FLAG_ACK);
    expect(last?.ack).toBe(5004);

    const data = await conn.readExact(3);
    expect(Array.from(data)).toEqual([10, 20, 30]);
  });

  test('write() sends data with advancing sequence numbers', async () => {
    const { conn, sent } = makePair();
    const opened = conn.open(1000);
    const synAck = devicePacket(TCP_FLAG_SYN | TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 5000, EMPTY_TAIL);
    await conn.handlePacket(synAck.header, synAck.payload);
    await opened;

    await conn.write(new Uint8Array([1, 2]));
    await conn.write(new Uint8Array([3]));
    const dataFrames = sent.filter((f) => f.payload.byteLength > 0);
    expect(dataFrames.length).toBe(2);
    expect(dataFrames[0]?.header.seq).toBe(1);
    expect(dataFrames[1]?.header.seq).toBe(3);
    expect(Array.from(dataFrames[1]?.payload ?? [])).toEqual([3]);
  });

  test('close() sends RST and readExact rejects afterwards', async () => {
    const { conn, sent } = makePair();
    const opened = conn.open(1000);
    const synAck = devicePacket(TCP_FLAG_SYN | TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 5000, EMPTY_TAIL);
    await conn.handlePacket(synAck.header, synAck.payload);
    await opened;

    conn.close();
    const last = sent[sent.length - 1]?.header;
    expect(last?.flags).toBe(TCP_FLAG_RST);
    await expectRejects(() => conn.readExact(1), /closed by local host/);
  });

  test('remote abort fails pending reads', async () => {
    const { conn } = makePair();
    const opened = conn.open(1000);
    const synAck = devicePacket(TCP_FLAG_SYN | TCP_FLAG_ACK, LOCKDOWN_PORT, 32001, 5000, EMPTY_TAIL);
    await conn.handlePacket(synAck.header, synAck.payload);
    await opened;

    const pending = conn.readExact(4);
    conn.abort(new Error('USB device disconnected'));
    await expectRejects(() => pending, /disconnected/);
  });
});

describe('buildAppleUsbFilters', () => {
  test('targets the Apple vendor ID', () => {
    expect(APPLE_VENDOR_ID).toBe(0x05ac);
    expect(buildAppleUsbFilters()).toEqual([{ vendorId: 0x05ac }]);
  });
});

describe('WebUsbMuxDevice (no WebUSB in bun)', () => {
  /** Minimal fake device — only used for argument validation paths that never touch USB. */
  function fakeDevice(): UsbDeviceLike {
    return {
      opened: false,
      vendorId: 0x05ac,
      productId: 0x12a8,
      configurations: [],
      open: async () => undefined,
      close: async () => undefined,
      selectConfiguration: async () => undefined,
      claimInterface: async () => undefined,
      releaseInterface: async () => undefined,
      transferIn: async () => ({ status: 'eof' }),
      transferOut: async () => ({ status: 'ok' }),
    };
  }

  test('isSupported() is false without navigator.usb', () => {
    expect(WebUsbMuxDevice.isSupported()).toBe(false);
  });

  test('requestDevice() rejects with a clear WebUSB error, not a raw DOMException', async () => {
    const err = await captureReject(() => WebUsbMuxDevice.requestDevice());
    expect(err instanceof WebUsbMuxError).toBe(true);
    expect((err as Error).message).toContain('WebUSB');
  });

  test('createTcpConnection validates arguments before touching USB', async () => {
    const dev = new WebUsbMuxDevice(fakeDevice());
    await expectRejects(() => dev.createTcpConnection(-1, LOCKDOWN_PORT), /deviceId/);
    await expectRejects(() => dev.createTcpConnection(1.5, LOCKDOWN_PORT), /deviceId/);
    await expectRejects(() => dev.createTcpConnection(0, 0), /port/);
    await expectRejects(() => dev.createTcpConnection(0, 70000), /port/);
  });

  test('createTcpConnection requires open() first', async () => {
    const dev = new WebUsbMuxDevice(fakeDevice());
    await expectRejects(() => dev.createTcpConnection(0, LOCKDOWN_PORT), /open\(\)/);
  });

  test('read/write without a connection reject with a helpful message', async () => {
    const dev = new WebUsbMuxDevice(fakeDevice());
    await expectRejects(() => dev.read(1), /createTcpConnection/);
    await expectRejects(() => dev.write(new Uint8Array([1])), /createTcpConnection/);
  });

  test('onDisconnect returns an unsubscribe function', () => {
    const dev = new WebUsbMuxDevice(fakeDevice());
    const unsubscribe = dev.onDisconnect(() => undefined);
    expect(typeof unsubscribe).toBe('function');
    unsubscribe();
  });
});

describe('TcpTransport', () => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  interface EchoSocketLike {
    on(event: 'data', listener: (data: Uint8Array) => void): void;
    write(data: Uint8Array): void;
  }

  async function startEchoServer(): Promise<{ port: number; close: () => Promise<void> }> {
    const net = (await import('node:net')) as unknown as {
      createServer(handler: (socket: EchoSocketLike) => unknown): {
        listen(port: number, host: string, cb: () => void): unknown;
        address(): { port: number } | null;
        close(cb: () => void): unknown;
      };
    };
    const server = net.createServer((socket) => {
      socket.on('data', (data) => socket.write(data));
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const port = server.address()?.port ?? 0;
    expect(port > 0).toBe(true);
    return {
      port,
      close: () =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    };
  }

  async function closedPort(): Promise<number> {
    const server = await startEchoServer();
    await server.close();
    return server.port;
  }

  test('constructor validates arguments', () => {
    expectThrowsSync(() => new TcpTransport('', 80), /host/);
    expectThrowsSync(() => new TcpTransport('127.0.0.1', 0), /port/);
    expectThrowsSync(() => new TcpTransport('127.0.0.1', 70000), /port/);
  });

  test('reads and writes against a local echo server', async () => {
    const { port, close } = await startEchoServer();
    const transport = new TcpTransport('127.0.0.1', port);
    try {
      expect(transport.isConnected).toBe(false);
      await transport.connect();
      expect(transport.isConnected).toBe(true);

      await transport.write(enc.encode('hello '));
      await transport.write(enc.encode('world'));
      const data = await transport.read(11);
      expect(dec.decode(data)).toBe('hello world');

      // read() waits for exactly n bytes even when they arrive split up.
      await transport.write(enc.encode('ab'));
      const pending = transport.read(4);
      await transport.write(enc.encode('cd'));
      expect(dec.decode(await pending)).toBe('abcd');

      // readExact alias behaves the same.
      await transport.write(enc.encode('xyz'));
      expect(dec.decode(await transport.readExact(3))).toBe('xyz');
    } finally {
      await transport.close();
      await close();
    }
    expect(transport.isConnected).toBe(false);
  });

  test('write connects lazily without an explicit connect()', async () => {
    const { port, close } = await startEchoServer();
    const transport = new TcpTransport('127.0.0.1', port);
    try {
      await transport.write(enc.encode('ping'));
      expect(dec.decode(await transport.read(4))).toBe('ping');
      expect(transport.isConnected).toBe(true);
    } finally {
      await transport.close();
      await close();
    }
  });

  test('connection refused rejects reads', async () => {
    const port = await closedPort();
    const transport = new TcpTransport('127.0.0.1', port);
    try {
      const err = await captureReject(() => transport.read(1));
      expect(err instanceof Error).toBe(true);
    } finally {
      await transport.close();
    }
  });

  test('read after close rejects', async () => {
    const { port, close } = await startEchoServer();
    const transport = new TcpTransport('127.0.0.1', port);
    await transport.close();
    await expectRejects(() => transport.read(1), /關閉/);
    await close();
  });

  test('read validates length', async () => {
    const { port, close } = await startEchoServer();
    const transport = new TcpTransport('127.0.0.1', port);
    try {
      await expectRejects(() => transport.read(0), /正整數/);
    } finally {
      await transport.close();
      await close();
    }
  });

  test('close() is idempotent', async () => {
    const { port, close } = await startEchoServer();
    const transport = new TcpTransport('127.0.0.1', port);
    await transport.connect();
    await transport.close();
    await transport.close();
    await close();
  });
});
