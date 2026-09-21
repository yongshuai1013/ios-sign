/**
 * Tests for src/pairing/usbmuxd.ts and src/pairing/lockdown.ts.
 *
 * Uses a MockTransport (in-memory inbound queue + recorded writes) so no
 * device or usbmuxd daemon is needed.
 */
import { describe, expect, test } from 'bun:test';
import plist from 'plist';
import {
  PlistSocket,
  UsbmuxdClient,
  UsbmuxdError,
  copyBytes,
  decodeUsbmuxdPacket,
  encodeUsbmuxdPacket,
  type Transport,
} from '../src/pairing/usbmuxd.js';
import {
  LockdownClient,
  LockdownError,
  PairingPendingError,
  pairDevice,
  pairRecordToDict,
  type LockdownPairRecord,
} from '../src/pairing/lockdown.js';

/* ------------------------------------------------------------------ */
/* Mock transport + framing helpers                                    */
/* ------------------------------------------------------------------ */

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

class MockTransport implements Transport {
  private inbound: Uint8Array[] = [];
  readonly written: Uint8Array[] = [];
  closed = false;

  enqueue(chunk: Uint8Array): void {
    this.inbound.push(chunk);
  }

  async read(n: number): Promise<Uint8Array> {
    let out: Uint8Array = new Uint8Array(0);
    while (out.length < n) {
      const chunk = this.inbound.shift();
      if (!chunk) throw new Error('mock transport: out of inbound data');
      out = concat(out, chunk);
    }
    if (out.length > n) {
      this.inbound.unshift(out.subarray(n));
      out = out.subarray(0, n);
    }
    return copyBytes(out);
  }

  async write(data: Uint8Array): Promise<void> {
    this.written.push(copyBytes(data));
  }

  close(): void {
    this.closed = true;
  }
}

/** One usbmuxd response packet (16-byte LE header + XML plist). */
function usbmuxdResponse(dict: Record<string, unknown>, tag = 1): Uint8Array {
  return encodeUsbmuxdPacket(dict, tag);
}

/** One lockdownd/installation_proxy response frame (BE32 length + XML). */
function plistFrame(obj: Record<string, unknown>): Uint8Array {
  const body = new TextEncoder().encode(plist.build(obj as never));
  const frame = new Uint8Array(4 + body.length);
  new DataView(frame.buffer).setUint32(0, body.length, false);
  frame.set(body, 4);
  return frame;
}

/** Decodes the XML payload of the n-th raw write as a plist frame. */
function writtenPlistFrame(t: MockTransport, index: number): Record<string, unknown> {
  const w = t.written[index];
  const len = new DataView(w.buffer, w.byteOffset, w.byteLength).getUint32(0, false);
  const xml = new TextDecoder().decode(w.subarray(4, 4 + len));
  return plist.parse(xml) as Record<string, unknown>;
}

function sampleRecord(): LockdownPairRecord {
  const enc = new TextEncoder();
  return {
    hostId: 'HOST-ID-1',
    systemBuid: 'SYSTEM-BUID-1',
    hostCertificate: enc.encode('HOST-CERT-PEM'),
    hostPrivateKey: enc.encode('HOST-KEY-PEM'),
    rootCertificate: enc.encode('ROOT-CERT-PEM'),
    rootPrivateKey: enc.encode('ROOT-KEY-PEM'),
    deviceCertificate: enc.encode('DEV-CERT-PEM'),
    devicePublicKey: enc.encode('-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----'),
    wifiMacAddress: 'aa:bb:cc:dd:ee:ff',
  };
}

/* ------------------------------------------------------------------ */
/* usbmuxd packet codec                                                */
/* ------------------------------------------------------------------ */

describe('usbmuxd packet codec', () => {
  test('encode/decode round-trip', () => {
    const pkt = encodeUsbmuxdPacket({ MessageType: 'ReadBUID', Foo: 42 }, 7);
    const dec = decodeUsbmuxdPacket(pkt);
    expect(dec.length).toBe(pkt.length);
    expect(dec.version).toBe(1);
    expect(dec.message).toBe(8);
    expect(dec.tag).toBe(7);
    expect(dec.dict['MessageType']).toBe('ReadBUID');
    expect(dec.dict['Foo']).toBe(42);
  });

  test('decode rejects truncated packets', () => {
    expect(() => decodeUsbmuxdPacket(new Uint8Array(10))).toThrow();
    const pkt = encodeUsbmuxdPacket({ a: 1 }, 1);
    expect(() => decodeUsbmuxdPacket(pkt.subarray(0, pkt.length - 4))).toThrow();
  });
});

/* ------------------------------------------------------------------ */
/* UsbmuxdClient                                                       */
/* ------------------------------------------------------------------ */

describe('UsbmuxdClient', () => {
  test('readBUID sends ReadBUID and returns BUID', async () => {
    const t = new MockTransport();
    t.enqueue(usbmuxdResponse({ BUID: 'TEST-BUID-123' }));
    const client = new UsbmuxdClient(t);
    const buid = await client.readBUID();
    expect(buid).toBe('TEST-BUID-123');

    const sent = decodeUsbmuxdPacket(t.written[0]);
    expect(sent.dict['MessageType']).toBe('ReadBUID');
    expect(sent.tag).toBe(1);
  });

  test('readBUID throws when BUID is missing', async () => {
    const t = new MockTransport();
    t.enqueue(usbmuxdResponse({}));
    const client = new UsbmuxdClient(t);
    await expect(client.readBUID()).rejects.toThrow(UsbmuxdError);
  });

  test('connect byte-swaps the port and returns a PlistSocket', async () => {
    const t = new MockTransport();
    t.enqueue(usbmuxdResponse({ Number: 0 }));
    const client = new UsbmuxdClient(t);
    const socket = await client.connect(42, 62078);
    expect(socket).toBeInstanceOf(PlistSocket);

    const sent = decodeUsbmuxdPacket(t.written[0]);
    expect(sent.dict['MessageType']).toBe('Connect');
    expect(sent.dict['DeviceID']).toBe(42);
    // 62078 = 0xF27E -> network order 0x7EF2
    expect(sent.dict['PortNumber']).toBe(0x7ef2);
  });

  test('connect throws UsbmuxdError on non-zero Number', async () => {
    const t = new MockTransport();
    t.enqueue(usbmuxdResponse({ Number: 3 }));
    const client = new UsbmuxdClient(t);
    const err = await client.connect(42, 62078).catch((e) => e);
    expect(err).toBeInstanceOf(UsbmuxdError);
    expect((err as UsbmuxdError).code).toBe(3);
  });

  test('listDevices parses the device list', async () => {
    const t = new MockTransport();
    t.enqueue(
      usbmuxdResponse({
        DeviceList: [
          { DeviceID: 5, Properties: { SerialNumber: 'UDID-AAA' } },
          { DeviceID: 9, Properties: { SerialNumber: 'UDID-BBB' } },
        ],
      }),
    );
    const client = new UsbmuxdClient(t);
    const devices = await client.listDevices();
    expect(devices).toEqual([
      { deviceId: 5, udid: 'UDID-AAA' },
      { deviceId: 9, udid: 'UDID-BBB' },
    ]);
  });
});

/* ------------------------------------------------------------------ */
/* PlistSocket                                                         */
/* ------------------------------------------------------------------ */

describe('PlistSocket', () => {
  test('sendPlist/recvPlist framing round-trip', async () => {
    const t = new MockTransport();
    const socket = new PlistSocket(t);
    const payload = { Request: 'GetValue', Key: 'UniqueDeviceID', Blob: new Uint8Array([1, 2, 3]) };
    await socket.sendPlist(payload);

    // Frame layout: BE32 length + XML body.
    const w = t.written[0];
    const len = new DataView(w.buffer, w.byteOffset, w.byteLength).getUint32(0, false);
    expect(len).toBe(w.length - 4);

    // Feed the same bytes back as inbound and receive them.
    t.enqueue(w);
    const back = await socket.recvPlist();
    expect(back['Request']).toBe('GetValue');
    expect(back['Key']).toBe('UniqueDeviceID');
    expect(back['Blob']).toBeInstanceOf(Uint8Array);
  });

  test('recvPlist rejects oversized frames', async () => {
    const t = new MockTransport();
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, 0xffff_ffff, false);
    t.enqueue(header);
    const socket = new PlistSocket(t);
    await expect(socket.recvPlist()).rejects.toThrow(/too large/);
  });
});

/* ------------------------------------------------------------------ */
/* LockdownClient                                                      */
/* ------------------------------------------------------------------ */

describe('LockdownClient', () => {
  test('getValue sends GetValue and returns Value', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Value: 'SOME-UDID' }));
    const client = new LockdownClient(t, 'test-label');

    const value = await client.getValue('UniqueDeviceID');
    expect(value).toBe('SOME-UDID');

    const sent = writtenPlistFrame(t, 0);
    expect(sent['Request']).toBe('GetValue');
    expect(sent['Key']).toBe('UniqueDeviceID');
    expect(sent['Label']).toBe('test-label');
  });

  test('getValue throws when Value is missing', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({}));
    const client = new LockdownClient(t);
    await expect(client.getValue('Foo')).rejects.toThrow(LockdownError);
  });

  test('getValue maps device errors', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'InvalidKey' }));
    const client = new LockdownClient(t);
    const err = await client.getValue('Foo').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as LockdownError).code).toBe('Unknown');
  });

  test('pair sends the Pair request structure and returns escrowBag', async () => {
    const t = new MockTransport();
    const escrow = new Uint8Array([9, 8, 7]);
    t.enqueue(plistFrame({ EscrowBag: escrow }));
    const client = new LockdownClient(t, 'test-label');

    const record = sampleRecord();
    const res = await client.pair(record, 'BUID-OVERRIDE');
    expect(res.success).toBe(true);
    expect(res.escrowBag).toBeInstanceOf(Uint8Array);
    expect(Array.from(res.escrowBag!)).toEqual([9, 8, 7]);

    const sent = writtenPlistFrame(t, 0);
    expect(sent['Request']).toBe('Pair');
    expect(sent['ProtocolVersion']).toBe('2');
    expect(sent['PairingOptions']).toMatchObject({ ExtendedPairingErrors: true });

    const pr = sent['PairRecord'] as Record<string, unknown>;
    expect(pr['HostID']).toBe('HOST-ID-1');
    expect(pr['SystemBUID']).toBe('BUID-OVERRIDE');
    expect(pr['WiFiMACAddress']).toBe('aa:bb:cc:dd:ee:ff');
    for (const k of [
      'DevicePublicKey',
      'DeviceCertificate',
      'HostCertificate',
      'RootCertificate',
      'RootPrivateKey',
    ]) {
      expect(pr[k]).toBeInstanceOf(Uint8Array);
    }
    // HostPrivateKey must NOT be sent in the Pair request.
    expect('HostPrivateKey' in pr).toBe(false);
    expect('EscrowBag' in pr).toBe(false);
  });

  test('pair throws PairingPendingError on PairingDialogResponsePending', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'PairingDialogResponsePending' }));
    const client = new LockdownClient(t);

    const err = await client.pair(sampleRecord(), '').catch((e) => e);
    expect(err).toBeInstanceOf(PairingPendingError);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as LockdownError).code).toBe('PairingDialogResponsePending');
  });

  test('pair throws LockdownError on UserDeniedPairing', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'UserDeniedPairing' }));
    const client = new LockdownClient(t);
    const err = await client.pair(sampleRecord(), '').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as LockdownError).code).toBe('UserDeniedPairing');
    expect(err).not.toBeInstanceOf(PairingPendingError);
  });

  test('validatePair returns true/false based on Error field', async () => {
    const t1 = new MockTransport();
    t1.enqueue(plistFrame({}));
    expect(await new LockdownClient(t1).validatePair('H1')).toBe(true);
    expect((writtenPlistFrame(t1, 0)['Request'])).toBe('ValidatePair');

    const t2 = new MockTransport();
    t2.enqueue(plistFrame({ Error: 'InvalidHostID' }));
    expect(await new LockdownClient(t2).validatePair('H1')).toBe(false);
  });

  test('startSession parses SessionID and EnableSessionSSL', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ SessionID: 'SESSION-1', EnableSessionSSL: true }));
    const client = new LockdownClient(t);

    const res = await client.startSession('H1', 'B1');
    expect(res).toMatchObject({ success: true, enableSessionSSL: true, sessionId: 'SESSION-1' });

    const sent = writtenPlistFrame(t, 0);
    expect(sent['Request']).toBe('StartSession');
    expect(sent['HostID']).toBe('H1');
    expect(sent['SystemBUID']).toBe('B1');
  });

  test('startSession throws when SessionID is missing', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ EnableSessionSSL: true }));
    await expect(new LockdownClient(t).startSession('H1', 'B1')).rejects.toThrow(LockdownError);
  });

  test('startService returns port and ssl flag', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Port: 54321, EnableServiceSSL: false }));
    const res = await new LockdownClient(t).startService('com.apple.afc');
    expect(res).toMatchObject({ port: 54321, enableServiceSSL: false });

    const sent = writtenPlistFrame(t, 0);
    expect(sent['Request']).toBe('StartService');
    expect(sent['Service']).toBe('com.apple.afc');
  });

  test('startService throws on invalid Port', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({}));
    await expect(new LockdownClient(t).startService('com.apple.afc')).rejects.toThrow(LockdownError);
  });

  test('stopSession sends StopSession with the remembered SessionID', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ SessionID: 'S-9', EnableSessionSSL: false }));
    t.enqueue(plistFrame({}));
    const client = new LockdownClient(t);

    await client.startSession('H1', 'B1');
    await client.stopSession();

    const sent = writtenPlistFrame(t, 1);
    expect(sent['Request']).toBe('StopSession');
    expect(sent['SessionID']).toBe('S-9');
  });

  test('LockdownClient accepts a raw Transport (wraps in PlistSocket)', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Value: 1 }));
    const client = new LockdownClient(t);
    expect(client.plistSocket).toBeInstanceOf(PlistSocket);
    expect(await client.getValue('K')).toBe(1);
  });

  test('LockdownClient accepts an existing PlistSocket', async () => {
    const t = new MockTransport();
    const socket = new PlistSocket(t);
    t.enqueue(plistFrame({ Value: 'x' }));
    const client = new LockdownClient(socket);
    expect(client.plistSocket).toBe(socket);
    expect(await client.getValue('K')).toBe('x');
  });
});

/* ------------------------------------------------------------------ */
/* pairRecordToDict                                                      */
/* ------------------------------------------------------------------ */

describe('pairRecordToDict', () => {
  test('matches the Rust build_pair_request dictionary', () => {
    const dict = pairRecordToDict(sampleRecord());
    expect(Object.keys(dict).sort()).toEqual(
      [
        'DeviceCertificate',
        'DevicePublicKey',
        'HostCertificate',
        'HostID',
        'RootCertificate',
        'RootPrivateKey',
        'SystemBUID',
        'WiFiMACAddress',
      ].sort(),
    );
    expect('HostPrivateKey' in dict).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* pairDevice (full flow with trust retry)                             */
/* ------------------------------------------------------------------ */

describe('pairDevice', () => {
  const mockCa = {
    generateCertificates: async (_pem: string | Uint8Array) => ({
      hostCert: new TextEncoder().encode('HOST-CERT'),
      devCert: new TextEncoder().encode('DEV-CERT'),
      privateKey: new TextEncoder().encode('PRIVATE-KEY'),
    }),
  };

  test('retries on PairingDialogResponsePending then succeeds with EscrowBag', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'PairingDialogResponsePending' }));
    t.enqueue(plistFrame({ EscrowBag: new Uint8Array([1, 1, 1]) }));
    const client = new LockdownClient(t);

    let trustCalls = 0;
    const record = await pairDevice(
      client,
      new TextEncoder().encode('-----BEGIN RSA PUBLIC KEY-----\nX\n-----END RSA PUBLIC KEY-----'),
      'aa:bb:cc:dd:ee:ff',
      'HOST-1',
      'BUID-1',
      mockCa,
      { retryDelayMs: 1, onTrustPending: () => (trustCalls += 1) },
    );

    expect(trustCalls).toBe(1);
    expect(record.hostId).toBe('HOST-1');
    expect(record.systemBuid).toBe('BUID-1');
    expect(record.wifiMacAddress).toBe('aa:bb:cc:dd:ee:ff');
    expect(new TextDecoder().decode(record.hostPrivateKey)).toBe('PRIVATE-KEY');
    expect(new TextDecoder().decode(record.deviceCertificate)).toBe('DEV-CERT');
    // Root cert/key mirror the host CA material (Rust build_pair_request).
    expect(new TextDecoder().decode(record.rootCertificate)).toBe('HOST-CERT');
    expect(new TextDecoder().decode(record.rootPrivateKey)).toBe('PRIVATE-KEY');
    expect(record.escrowBag).toBeInstanceOf(Uint8Array);
    // Two Pair attempts were made.
    expect(t.written.length).toBe(2);
  });

  test('gives up after maxAttempts', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'PairingDialogResponsePending' }));
    t.enqueue(plistFrame({ Error: 'PairingDialogResponsePending' }));
    const client = new LockdownClient(t);

    const err = await pairDevice(
      client,
      new TextEncoder().encode('PUBKEY'),
      'aa:bb:cc:dd:ee:ff',
      'HOST-1',
      'BUID-1',
      mockCa,
      { retryDelayMs: 1, maxAttempts: 2 },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(PairingPendingError);
    expect(t.written.length).toBe(2);
  });

  test('propagates non-pending errors immediately', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'UserDeniedPairing' }));
    const client = new LockdownClient(t);

    const err = await pairDevice(
      client,
      new TextEncoder().encode('PUBKEY'),
      'aa:bb:cc:dd:ee:ff',
      'HOST-1',
      'BUID-1',
      mockCa,
      { retryDelayMs: 1 },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as LockdownError).code).toBe('UserDeniedPairing');
    expect(t.written.length).toBe(1);
  });

  test('aborts via AbortSignal', async () => {
    const t = new MockTransport();
    t.enqueue(plistFrame({ Error: 'PairingDialogResponsePending' }));
    const client = new LockdownClient(t);
    const controller = new AbortController();

    const pending = pairDevice(
      client,
      new TextEncoder().encode('PUBKEY'),
      'aa:bb:cc:dd:ee:ff',
      'HOST-1',
      'BUID-1',
      mockCa,
      { retryDelayMs: 50, signal: controller.signal },
    );
    controller.abort();
    const err = await pending.catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
  });
});
