/**
 * Transport + pairing flow tests for `src/pairing/usbmuxd.ts` and
 * `src/pairing/lockdown.ts`, using an in-memory fake transport with
 * pre-recorded responses.
 *
 * Migrated to the task-specified API:
 * - `Transport.read(n)` (exact-n reads)
 * - `UsbmuxdClient.connect()` returns a `PlistSocket`
 * - `LockdownClient.pair(pairRecord, buid)` is single-shot and throws
 *   `PairingPendingError` on `PairingDialogResponsePending`
 * - `pairDevice()` drives the full trust-retry flow
 */
import { describe, test, expect } from 'bun:test';
import plist from 'plist';
import type { PlistObject } from 'plist';
import type { Transport } from '../src/pairing/usbmuxd.js';
import type { LockdownPairRecord } from '../src/pairing/lockdown.js';

const usbmuxd = await import('../src/pairing/usbmuxd.js');
const lockdown = await import('../src/pairing/lockdown.js');

const {
  UsbmuxdClient,
  UsbmuxdError,
  PlistSocket,
  encodeUsbmuxdPacket,
  decodeUsbmuxdPacket,
} = usbmuxd;
const { LockdownClient, LockdownError, PairingPendingError, pairDevice } = lockdown;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** In-memory transport: serves pre-recorded response chunks, records writes. */
class FakeTransport implements Transport {
  written: Uint8Array[] = [];
  private buffered = new Uint8Array(0);
  closed = false;

  constructor(chunks: Uint8Array[] = []) {
    for (const c of chunks) this.feed(c);
  }

  feed(chunk: Uint8Array): void {
    const next = new Uint8Array(this.buffered.length + chunk.length);
    next.set(this.buffered, 0);
    next.set(chunk, this.buffered.length);
    this.buffered = next;
  }

  async write(data: Uint8Array): Promise<void> {
    const copy = new Uint8Array(data.length);
    copy.set(data);
    this.written.push(copy);
  }

  /** Resolves with exactly `n` bytes (buffering across fed chunks). */
  async read(n: number): Promise<Uint8Array> {
    while (this.buffered.length < n) {
      throw new Error(`FakeTransport: wanted ${n} bytes, only ${this.buffered.length} buffered`);
    }
    // subarray keeps a nonzero byteOffset on later reads, exercising the
    // clients' DataView offset handling.
    const out = this.buffered.subarray(0, n);
    this.buffered = this.buffered.subarray(n);
    const copy = new Uint8Array(out.length);
    copy.set(out);
    return copy;
  }

  close(): void {
    this.closed = true;
  }
}

function usbmuxdResponse(dict: Record<string, unknown>): Uint8Array {
  // Responses use the same framing; the client ignores the header message type.
  return encodeUsbmuxdPacket(dict, 1);
}

function lockdownResponse(dict: Record<string, unknown>): Uint8Array {
  const body = new TextEncoder().encode(plist.build(dict as unknown as PlistObject));
  const frame = new Uint8Array(4 + body.length);
  new DataView(frame.buffer).setUint32(0, body.length, false); // big-endian length
  frame.set(body, 4);
  return frame;
}

function decodeLockdownFrame(frame: Uint8Array): Record<string, unknown> {
  const len = new DataView(frame.buffer, frame.byteOffset, 4).getUint32(0, false);
  const xml = new TextDecoder().decode(frame.subarray(4, 4 + len));
  return plist.parse(xml) as Record<string, unknown>;
}

const FAKE_PUBKEY = new TextEncoder().encode(
  '-----BEGIN RSA PUBLIC KEY-----\nZmFrZQ==\n-----END RSA PUBLIC KEY-----\n',
);

function sampleRecord(): LockdownPairRecord {
  const enc = new TextEncoder();
  return {
    hostId: 'host-id-1',
    systemBuid: 'system-buid-1',
    hostCertificate: enc.encode('HOSTCERT-PEM'),
    hostPrivateKey: enc.encode('PRIVATEKEY-PEM'),
    rootCertificate: enc.encode('HOSTCERT-PEM'),
    rootPrivateKey: enc.encode('PRIVATEKEY-PEM'),
    deviceCertificate: enc.encode('DEVCERT-PEM'),
    devicePublicKey: FAKE_PUBKEY,
    wifiMacAddress: 'aa:bb:cc:dd:ee:ff',
  };
}

const mockCa = {
  generateCertificates: async (_pem: string | Uint8Array) => ({
    hostCert: new TextEncoder().encode('HOSTCERT-PEM'),
    devCert: new TextEncoder().encode('DEVCERT-PEM'),
    privateKey: new TextEncoder().encode('PRIVATEKEY-PEM'),
  }),
};

/* ------------------------------------------------------------------ */
/* usbmuxd                                                             */
/* ------------------------------------------------------------------ */

describe('usbmuxd framing', () => {
  test('header encode/decode roundtrip', async () => {
    const transport = new FakeTransport([usbmuxdResponse({ BUID: 'BUID-123' })]);
    const client = new UsbmuxdClient(transport);

    expect(await client.readBUID()).toBe('BUID-123');

    const written = transport.written[0];
    const pkt = decodeUsbmuxdPacket(written);
    expect(pkt.length).toBe(written.length);
    expect(pkt.version).toBe(1); // XML plist version
    expect(pkt.message).toBe(8); // PLIST message type
    expect(pkt.tag).toBe(1); // tags start at 1
    expect(pkt.dict['MessageType']).toBe('ReadBUID');

    // Re-encoding the decoded packet reproduces the exact bytes.
    expect([...encodeUsbmuxdPacket(pkt.dict, pkt.tag)]).toEqual([...written]);
  });

  test('connect byte-swaps the port, returns PlistSocket, throws on non-zero Number', async () => {
    const transport = new FakeTransport([usbmuxdResponse({ Number: 0 })]);
    const socket = await new UsbmuxdClient(transport).connect(42, 62078);
    expect(socket).toBeInstanceOf(PlistSocket);

    const req = decodeUsbmuxdPacket(transport.written[0]);
    expect(req.dict['MessageType']).toBe('Connect');
    expect(req.dict['DeviceID']).toBe(42);
    // ((62078 << 8) & 0xFF00) | ((62078 >> 8) & 0xFF) = 0x7EF2 = 32498
    expect(req.dict['PortNumber']).toBe(32498);

    const failing = new FakeTransport([usbmuxdResponse({ Number: 3 })]);
    const err = await new UsbmuxdClient(failing).connect(42, 62078).catch((e) => e);
    expect(err).toBeInstanceOf(UsbmuxdError);
    expect((err as InstanceType<typeof UsbmuxdError>).code).toBe(3);
  });

  test('listDevices maps DeviceList entries', async () => {
    const transport = new FakeTransport([
      usbmuxdResponse({
        DeviceList: [
          { DeviceID: 7, Properties: { SerialNumber: 'UDID-XYZ', ConnectionType: 'USB' } },
        ],
      }),
    ]);
    const devices = await new UsbmuxdClient(transport).listDevices();
    expect(devices).toEqual([{ deviceId: 7, udid: 'UDID-XYZ' }]);
  });

  test('get/save/delete pair record', async () => {
    const recordBytes = new Uint8Array([9, 8, 7]);
    const transport = new FakeTransport([
      usbmuxdResponse({ PairRecordData: recordBytes }),
      usbmuxdResponse({ Number: 0 }),
      usbmuxdResponse({ Number: 0 }),
    ]);
    const client = new UsbmuxdClient(transport);

    const got = await client.getPairRecord('UDID-1');
    expect([...got]).toEqual([9, 8, 7]);

    await client.savePairRecord('UDID-1', recordBytes);
    const saveReq = decodeUsbmuxdPacket(transport.written[1]);
    expect(saveReq.dict['MessageType']).toBe('SavePairRecord');
    expect(saveReq.dict['PairRecordID']).toBe('UDID-1');
    expect([...(saveReq.dict['PairRecordData'] as Uint8Array)]).toEqual([9, 8, 7]);

    await client.deletePairRecord('UDID-1');
    const delReq = decodeUsbmuxdPacket(transport.written[2]);
    expect(delReq.dict['MessageType']).toBe('DeletePairRecord');
    expect(delReq.dict['PairRecordID']).toBe('UDID-1');
  });
});

/* ------------------------------------------------------------------ */
/* lockdownd                                                           */
/* ------------------------------------------------------------------ */

describe('lockdownd framing', () => {
  test('u32 big-endian length prefix + XML plist roundtrip', async () => {
    const transport = new FakeTransport([lockdownResponse({ Value: 'iPhone' })]);
    const client = new LockdownClient(transport);

    expect(await client.getValue('DeviceName')).toBe('iPhone');

    const written = transport.written[0];
    const len = new DataView(written.buffer, written.byteOffset, 4).getUint32(0, false);
    expect(len).toBe(written.length - 4);

    const req = decodeLockdownFrame(written);
    expect(req['Label']).toBe('sideimpactor');
    expect(req['Request']).toBe('GetValue');
    expect(req['Key']).toBe('DeviceName');
  });

  test('unknown Error values are wrapped in LockdownError', async () => {
    const transport = new FakeTransport([
      lockdownResponse({ Error: 'WeirdError', ErrorDescription: 'boom' }),
    ]);
    const err = await new LockdownClient(transport).getValue('DeviceName').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as InstanceType<typeof LockdownError>).code).toBe('Unknown');
    expect((err as Error).message).toContain('WeirdError');
  });
});

describe('pairing flow', () => {
  test('pair() sends the Pair request structure and returns success + EscrowBag', async () => {
    const escrowBag = new Uint8Array([1, 2, 3, 4]);
    const transport = new FakeTransport([lockdownResponse({ EscrowBag: escrowBag })]);
    const client = new LockdownClient(transport);

    const res = await client.pair(sampleRecord(), 'system-buid-1');
    expect(res.success).toBe(true);
    expect(res.escrowBag).toBeInstanceOf(Uint8Array);
    expect([...res.escrowBag!]).toEqual([1, 2, 3, 4]);

    const f = decodeLockdownFrame(transport.written[0]);
    expect(f['Label']).toBe('sideimpactor');
    expect(f['Request']).toBe('Pair');
    expect(f['ProtocolVersion']).toBe('2');
    expect((f['PairingOptions'] as Record<string, unknown>)['ExtendedPairingErrors']).toBe(true);
    const sentRecord = f['PairRecord'] as Record<string, unknown>;
    expect(sentRecord['HostID']).toBe('host-id-1');
    expect(sentRecord['SystemBUID']).toBe('system-buid-1');
    expect(sentRecord['WiFiMACAddress']).toBe('aa:bb:cc:dd:ee:ff');
    expect([...(sentRecord['DevicePublicKey'] as Uint8Array)]).toEqual([...FAKE_PUBKEY]);
    // HostPrivateKey is merged only after the device accepts — never sent.
    expect(sentRecord['HostPrivateKey']).toBeUndefined();
  });

  test('pair() throws PairingPendingError on PairingDialogResponsePending', async () => {
    const transport = new FakeTransport([
      lockdownResponse({ Error: 'PairingDialogResponsePending' }),
    ]);
    const err = await new LockdownClient(transport).pair(sampleRecord(), '').catch((e) => e);
    expect(err).toBeInstanceOf(PairingPendingError);
    expect((err as InstanceType<typeof LockdownError>).code).toBe('PairingDialogResponsePending');
    // Single-shot: no retry, exactly one Pair request went out.
    expect(transport.written.length).toBe(1);
  });

  test('pair() surfaces UserDeniedPairing immediately', async () => {
    const transport = new FakeTransport([lockdownResponse({ Error: 'UserDeniedPairing' })]);
    const err = await new LockdownClient(transport).pair(sampleRecord(), '').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as InstanceType<typeof LockdownError>).code).toBe('UserDeniedPairing');
    expect(err).not.toBeInstanceOf(PairingPendingError);
  });

  test('pairDevice() retries on PairingDialogResponsePending and merges keys + EscrowBag', async () => {
    const escrowBag = new Uint8Array([1, 2, 3, 4]);
    const transport = new FakeTransport([
      lockdownResponse({ Error: 'PairingDialogResponsePending' }), // 1st attempt
      lockdownResponse({ EscrowBag: escrowBag }), // 2nd attempt: success
    ]);
    const client = new LockdownClient(transport);

    let trustCalls = 0;
    const record = await pairDevice(client, FAKE_PUBKEY, 'aa:bb:cc:dd:ee:ff', 'host-id-1', 'system-buid-1', mockCa, {
      retryDelayMs: 1,
      onTrustPending: () => (trustCalls += 1),
    });

    expect(trustCalls).toBe(1);
    expect(record.hostId).toBe('host-id-1');
    expect(record.systemBuid).toBe('system-buid-1');
    expect(record.wifiMacAddress).toBe('aa:bb:cc:dd:ee:ff');
    expect(new TextDecoder().decode(record.hostPrivateKey)).toBe('PRIVATEKEY-PEM');
    expect(new TextDecoder().decode(record.deviceCertificate)).toBe('DEVCERT-PEM');
    expect(new TextDecoder().decode(record.rootCertificate)).toBe('HOSTCERT-PEM');
    expect([...(record.escrowBag as Uint8Array)]).toEqual([1, 2, 3, 4]);
    expect([...record.devicePublicKey]).toEqual([...FAKE_PUBKEY]);

    // The Pair request was sent twice; neither copy carries HostPrivateKey.
    expect(transport.written.length).toBe(2);
    for (const w of transport.written) {
      const f = decodeLockdownFrame(w);
      expect(f['Request']).toBe('Pair');
      expect((f['PairRecord'] as Record<string, unknown>)['HostPrivateKey']).toBeUndefined();
    }
  });

  test('pairDevice() surfaces UserDeniedPairing immediately', async () => {
    const transport = new FakeTransport([lockdownResponse({ Error: 'UserDeniedPairing' })]);
    const err = await pairDevice(
      new LockdownClient(transport),
      FAKE_PUBKEY,
      'aa:bb:cc:dd:ee:ff',
      'h',
      'b',
      mockCa,
      { retryDelayMs: 1 },
    ).catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as InstanceType<typeof LockdownError>).code).toBe('UserDeniedPairing');
    expect(transport.written.length).toBe(1);
  });
});

describe('session management', () => {
  test('startSession returns success, sessionId and ssl flag', async () => {
    const transport = new FakeTransport([
      lockdownResponse({ SessionID: 'sess-1', EnableSessionSSL: true }),
    ]);
    const res = await new LockdownClient(transport).startSession('h', 'b');
    expect(res).toEqual({ success: true, enableSessionSSL: true, sessionId: 'sess-1' });

    const req = decodeLockdownFrame(transport.written[0]);
    expect(req['Request']).toBe('StartSession');
    expect(req['HostID']).toBe('h');
    expect(req['SystemBUID']).toBe('b');
  });

  test('startSession reports enableSessionSSL=false when the device disables SSL', async () => {
    const transport = new FakeTransport([
      lockdownResponse({ SessionID: 'sess-2', EnableSessionSSL: false }),
    ]);
    const res = await new LockdownClient(transport).startSession('h', 'b');
    expect(res).toEqual({ success: true, enableSessionSSL: false, sessionId: 'sess-2' });
  });

  test('startSession throws when SessionID is missing', async () => {
    const transport = new FakeTransport([lockdownResponse({ EnableSessionSSL: true })]);
    const err = await new LockdownClient(transport).startSession('h', 'b').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as Error).message).toContain('SessionID');
  });

  test('stopSession sends StopSession with the session id', async () => {
    const transport = new FakeTransport([
      lockdownResponse({ SessionID: 'sess-3', EnableSessionSSL: false }),
      lockdownResponse({}),
    ]);
    const client = new LockdownClient(transport);
    await client.startSession('h', 'b');
    await client.stopSession();

    const req = decodeLockdownFrame(transport.written[1]);
    expect(req['Request']).toBe('StopSession');
    expect(req['SessionID']).toBe('sess-3');
  });
});

describe('startService', () => {
  test('returns port and enableServiceSSL', async () => {
    const transport = new FakeTransport([lockdownResponse({ Port: 12345, EnableServiceSSL: true })]);
    const res = await new LockdownClient(transport).startService('com.apple.afc');
    expect(res).toEqual({ port: 12345, enableServiceSSL: true });

    const req = decodeLockdownFrame(transport.written[0]);
    expect(req['Label']).toBe('sideimpactor');
    expect(req['Request']).toBe('StartService');
    expect(req['Service']).toBe('com.apple.afc');
  });

  test('EnableServiceSSL defaults to false when absent', async () => {
    const transport = new FakeTransport([lockdownResponse({ Port: 23456 })]);
    const res = await new LockdownClient(transport).startService(
      'com.apple.mobile.installation_proxy',
    );
    expect(res).toEqual({ port: 23456, enableServiceSSL: false });
  });

  test('throws when Port is missing', async () => {
    const transport = new FakeTransport([lockdownResponse({ EnableServiceSSL: false })]);
    const err = await new LockdownClient(transport).startService('com.apple.afc').catch((e) => e);
    expect(err).toBeInstanceOf(LockdownError);
    expect((err as Error).message).toContain('Port');
  });
});
