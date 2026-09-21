// Tests for the pairing-format modules: TLV8, OPACK, PairingFile, RpPairingFile.
import { describe, expect, test } from 'bun:test';
import { build as buildPlist } from 'plist';
import type { PlistObject } from 'plist';
import {
  PairingDataComponentType,
  serializeTlv8,
  deserializeTlv8,
  collectComponentData,
  containsComponent,
  type TLV8Entry,
} from '../src/pairing/tlv.js';
import {
  plistToOpack,
  opackToPlist,
  type PlistValue,
} from '../src/pairing/opack.js';
import { PairingFile, RpPairingFile } from '../src/pairing/pairing-file.js';

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('odd-length hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Deep equality for PlistValue (Uint8Array compared by content). */
function plistDeepEqual(a: PlistValue, b: PlistValue): boolean {
  if (typeof a !== typeof b) {
    return false;
  }
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    return (
      a instanceof Uint8Array &&
      b instanceof Uint8Array &&
      a.length === b.length &&
      a.every((v, i) => v === (b as Uint8Array)[i])
    );
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((v, i) => plistDeepEqual(v, (b as PlistValue[])[i]))
    );
  }
  if (typeof a === 'object' && a !== null) {
    const ao = a as Record<string, PlistValue>;
    const bo = b as Record<string, PlistValue>;
    const aKeys = Object.keys(ao);
    const bKeys = Object.keys(bo);
    return (
      aKeys.length === bKeys.length &&
      aKeys.every((k) => plistDeepEqual(ao[k], bo[k]))
    );
  }
  return a === b;
}

// ---------------------------------------------------------------------------
// TLV8
// ---------------------------------------------------------------------------

describe('tlv8', () => {
  test('serializes entries as type/length/value', () => {
    const entries: TLV8Entry[] = [
      { type: PairingDataComponentType.Identifier, data: new Uint8Array([1, 2, 3]) },
      { type: PairingDataComponentType.Separator, data: new Uint8Array(0) },
    ];
    expect(serializeTlv8(entries)).toEqual(
      new Uint8Array([0x01, 0x03, 0x01, 0x02, 0x03, 0xff, 0x00]),
    );
  });

  test('round-trips entries', () => {
    const entries: TLV8Entry[] = [
      { type: PairingDataComponentType.Method, data: new Uint8Array([0x05]) },
      {
        type: PairingDataComponentType.PublicKey,
        data: new Uint8Array(32).fill(0xab),
      },
      { type: PairingDataComponentType.State, data: utf8Encoder.encode('ok') },
    ];
    const back = deserializeTlv8(serializeTlv8(entries));
    expect(back.length).toBe(entries.length);
    for (let i = 0; i < entries.length; i++) {
      expect(back[i].type).toBe(entries[i].type);
      expect(back[i].data).toEqual(entries[i].data);
    }
  });

  test('rejects unknown component type bytes', () => {
    expect(() => deserializeTlv8(new Uint8Array([0x1e, 0x00]))).toThrow(
      /unknown TLV8/,
    );
    expect(() => deserializeTlv8(new Uint8Array([0x42, 0x01, 0x00]))).toThrow(
      /unknown TLV8/,
    );
  });

  test('rejects truncated entries', () => {
    expect(() => deserializeTlv8(new Uint8Array([0x01, 0x05, 0x01, 0x02]))).toThrow(
      /malformed TLV8/,
    );
  });

  test('collectComponentData concatenates matching payloads', () => {
    const entries: TLV8Entry[] = [
      { type: PairingDataComponentType.Method, data: new Uint8Array([1]) },
      { type: PairingDataComponentType.Identifier, data: new Uint8Array([2, 3]) },
      { type: PairingDataComponentType.Method, data: new Uint8Array([4, 5]) },
    ];
    expect(
      collectComponentData(entries, PairingDataComponentType.Method),
    ).toEqual(new Uint8Array([1, 4, 5]));
    expect(
      collectComponentData(entries, PairingDataComponentType.Salt),
    ).toEqual(new Uint8Array(0));
  });

  test('containsComponent reports presence', () => {
    const entries: TLV8Entry[] = [
      { type: PairingDataComponentType.Identifier, data: new Uint8Array([9]) },
    ];
    expect(containsComponent(entries, PairingDataComponentType.Identifier)).toBe(true);
    expect(containsComponent(entries, PairingDataComponentType.Salt)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// OPACK
// ---------------------------------------------------------------------------

// Rust opack.rs test t1/t2 vector.
const T1_HEX =
  'e7 46 61 6c 74 49 52 4b 80 e9 e8 2d c0 6a 49 79 6b 56 6f 54 00 19 b1 c7 7b ' +
  '46 62 74 41 64 64 72 51 31 31 3a 32 32 3a 33 33 3a 34 34 3a 35 35 3a 36 36 ' +
  '43 6d 61 63 76 11 22 33 44 55 66 ' +
  '5b 72 65 6d 6f 74 65 70 61 69 72 69 6e 67 5f 73 65 72 69 61 6c 5f 6e 75 6d 62 65 72 ' +
  '4c 41 41 41 41 41 41 41 41 41 41 41 41 ' +
  '49 61 63 63 6f 75 6e 74 49 44 48 6c 6f 6c 73 73 73 73 73 ' +
  '45 6d 6f 64 65 6c 4e 63 6f 6d 70 75 74 65 72 2d 6d 6f 64 65 6c ' +
  '44 6e 61 6d 65 46 72 65 65 65 65 65';

function t1Value(): PlistValue {
  // Insertion order matches the Rust test's dict literal.
  return {
    altIRK: hexToBytes('e9e82dc06a49796b566f540019b1c77b'),
    btAddr: '11:22:33:44:55:66',
    mac: hexToBytes('112233445566'),
    remotepairing_serial_number: 'AAAAAAAAAAAA',
    accountID: 'lolsssss',
    model: 'computer-model',
    name: 'reeeee',
  };
}

describe('opack', () => {
  test('t1: encodes the reference dict to the exact byte vector', () => {
    expect(plistToOpack(t1Value())).toEqual(hexToBytes(T1_HEX));
  });

  test('t2: decodes the reference vector back to the dict', () => {
    expect(plistDeepEqual(opackToPlist(hexToBytes(T1_HEX)), t1Value())).toBe(true);
  });

  test('back-references resolve against earlier scalars', () => {
    // {"a": "b", "c": {"d": "a"}, "d": true} — 0xA0 points at "a", 0xA3 at "d".
    const v = hexToBytes('e3 41 61 41 62 41 63 e1 41 64 a0 a3 01');
    const expected: PlistValue = { a: 'b', c: { d: 'a' }, d: true };
    expect(plistDeepEqual(opackToPlist(v), expected)).toBe(true);
  });

  test('repeated scalars do not take a second slot', () => {
    // ["x", "x", "y", <ref 1>] — "x" is only interned once, so slot 1 is "y".
    const v = hexToBytes('d4 41 78 41 78 41 79 a1');
    expect(plistDeepEqual(opackToPlist(v), ['x', 'x', 'y', 'y'])).toBe(true);
  });

  test('out-of-range back-reference is an error', () => {
    expect(() => opackToPlist(hexToBytes('d2 41 61 a4'))).toThrow(/out of range/);
  });

  test('parses a real pair record with back-referenced name', () => {
    const v = hexToBytes(
      'e946616c7449524b80eb5231c54575ca469fd23ca59e2f080e' +
        '5272656d6f746570616972696e675f65636964331c00853e36111200' +
        '466274416464725133343a32623a36653a32323a36363a3861' +
        '5b72656d6f746570616972696e675f73657269616c5f6e756d6265724a52324351485133365936' +
        '496163636f756e744944612439393031463534422d443336302d344544382d423444392d383043353535353135353337' +
        '456d6f64656c486950616431362c33' +
        '5272656d6f746570616972696e675f756469645930303030383133322d30303132313133363345383530303143' +
        '446e616d65ab' +
        '5b6c6173745365656e5769726550726f746f636f6c56657273696f6e22',
    );
    const res = opackToPlist(v) as Record<string, PlistValue>;
    expect(res['model']).toBe('iPad16,3');
    expect(res['name']).toBe('iPad16,3');
    expect(res['remotepairing_udid']).toBe('00008132-001211363E85001C');
    expect(res['remotepairing_ecid']).toBe(5085474255601692);
    expect((res['altIRK'] as Uint8Array).length).toBe(16);
    expect(res['lastSeenWireProtocolVersion']).toBe(26);
  });

  test('round-trips mixed scalars, arrays, and dicts', () => {
    const value: PlistValue = {
      str: 'hello',
      smallInt: 5,
      byteInt: 200,
      wordInt: 70000,
      bigInt: 5000000000,
      f32: 1.5,
      f64: 3.14,
      flag: true,
      data: new Uint8Array([1, 2, 3]),
      arr: [1, 'two', false],
      nested: { a: 1 },
    };
    expect(plistDeepEqual(opackToPlist(plistToOpack(value)), value)).toBe(true);
  });

  test('rejects trailing bytes and unknown tags', () => {
    expect(() => opackToPlist(hexToBytes('01 02'))).toThrow(/trailing bytes/);
    expect(() => opackToPlist(hexToBytes('ff'))).toThrow(/unsupported OPACK tag/);
    expect(() => opackToPlist(hexToBytes('03'))).toThrow(/terminator/);
  });
});

// ---------------------------------------------------------------------------
// PairingFile
// ---------------------------------------------------------------------------

function fakePairingFile(): PairingFile {
  return new PairingFile({
    // Valid base64 text without PEM headers: wrapped as-is.
    deviceCertificate: utf8Encoder.encode('ZmFrZS1kZXZpY2UtY2VydA=='),
    // Raw bytes that are not base64: base64-encoded before wrapping.
    hostPrivateKey: utf8Encoder.encode('fake-host-key-der!!'),
    hostCertificate: utf8Encoder.encode('aG9zdC1jZXJ0'),
    rootPrivateKey: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    rootCertificate: utf8Encoder.encode('cm9vdC1jZXJ0'),
    systemBuid: 'TEST-BUID-1234',
    hostId: 'TEST-HOST-ID',
    escrowBag: new Uint8Array([9, 9, 9]),
    wifiMacAddress: 'aa:bb:cc:dd:ee:ff',
    udid: 'TEST-UDID',
  });
}

describe('PairingFile', () => {
  test('serialize adds missing PEM headers and round-trips via fromBytes', () => {
    const pf = fakePairingFile();
    const bytes = pf.serialize();

    const pf2 = PairingFile.fromBytes(bytes);
    expect(pf2.systemBuid).toBe('TEST-BUID-1234');
    expect(pf2.hostId).toBe('TEST-HOST-ID');
    expect(pf2.wifiMacAddress).toBe('aa:bb:cc:dd:ee:ff');
    expect(pf2.udid).toBe('TEST-UDID');
    expect(pf2.escrowBag).toEqual(new Uint8Array([9, 9, 9]));

    // PEM headers were added automatically.
    const deviceCert = utf8Decoder.decode(pf2.deviceCertificate);
    expect(deviceCert).toBe(
      '-----BEGIN CERTIFICATE-----\nZmFrZS1kZXZpY2UtY2VydA==\n-----END CERTIFICATE-----',
    );
    const hostKey = utf8Decoder.decode(pf2.hostPrivateKey);
    expect(hostKey.startsWith('-----BEGIN PRIVATE KEY-----\n')).toBe(true);
    expect(hostKey.endsWith('\n-----END PRIVATE KEY-----')).toBe(true);
    // 'fake-host-key-der!!' is not base64 text, so it was base64-encoded.
    expect(hostKey).toContain(btoa('fake-host-key-der!!'));
    const rootKey = utf8Decoder.decode(pf2.rootPrivateKey);
    expect(rootKey.startsWith('-----BEGIN PRIVATE KEY-----\n')).toBe(true);
    expect(rootKey).toContain(btoa(String.fromCharCode(0xde, 0xad, 0xbe, 0xef)));
  });

  test('already PEM-formatted data passes through unchanged', () => {
    const pem = utf8Encoder.encode(
      '-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----',
    );
    const pf = new PairingFile({
      deviceCertificate: pem,
      hostPrivateKey: pem,
      hostCertificate: pem,
      rootPrivateKey: pem,
      rootCertificate: pem,
      systemBuid: 'B',
      hostId: 'H',
      wifiMacAddress: '00:00:00:00:00:00',
    });
    const pf2 = PairingFile.fromBytes(pf.serialize());
    expect(pf2.deviceCertificate).toEqual(pem);
    expect(pf2.hostPrivateKey).toEqual(pem);
    expect(pf2.escrowBag).toBeUndefined();
    expect(pf2.udid).toBeUndefined();
  });

  test('fromValue validates required fields', () => {
    expect(() => PairingFile.fromValue({})).toThrow(/missing required field/);
  });

  test('debug output redacts private key material', () => {
    const dbg = fakePairingFile().toDebugString();
    expect(dbg).toContain('TEST-BUID-1234');
    expect(dbg).toContain('<redacted>');
    expect(dbg).not.toContain('fake-host-key-der!!');
  });
});

// ---------------------------------------------------------------------------
// RpPairingFile
// ---------------------------------------------------------------------------

const UUID_V3_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('RpPairingFile', () => {
  test('generate creates keys and a v3 UUID identifier', () => {
    const f = RpPairingFile.generate('my-test-host');
    expect(f.privateKey.length).toBe(32);
    expect(f.publicKey.length).toBe(32);
    expect(f.identifier).toMatch(UUID_V3_RE);
    expect(f.altIrk).toBeUndefined();
    // UUID v3 is deterministic per host.
    expect(RpPairingFile.generate('my-test-host').identifier).toBe(f.identifier);
    // Keys are random per generation.
    expect(RpPairingFile.generate('my-test-host').privateKey).not.toEqual(
      f.privateKey,
    );
  });

  test('toBytes/fromBytes round-trips', () => {
    const f = RpPairingFile.generate('round-trip-host');
    const back = RpPairingFile.fromBytes(f.toBytes());
    expect(back.privateKey).toEqual(f.privateKey);
    expect(back.publicKey).toEqual(f.publicKey);
    expect(back.identifier).toBe(f.identifier);
    expect(back.altIrk).toBeUndefined();

    f.altIrk = new Uint8Array(16).fill(7);
    const back2 = RpPairingFile.fromBytes(f.toBytes());
    expect(back2.altIrk).toEqual(new Uint8Array(16).fill(7));
  });

  test('recreateSigningKeys rotates keys and clears altIrk', () => {
    const f = RpPairingFile.generate('rotate-host');
    f.altIrk = new Uint8Array(16).fill(1);
    const oldPublic = f.publicKey.slice();
    const oldPrivate = f.privateKey.slice();
    f.recreateSigningKeys();
    expect(f.altIrk).toBeUndefined();
    expect(f.publicKey).not.toEqual(oldPublic);
    expect(f.privateKey).not.toEqual(oldPrivate);
    expect(f.publicKey.length).toBe(32);
  });

  test('fromBytes validates key lengths', () => {
    const bad = utf8Encoder.encode(
      buildPlist({
        public_key: new Uint8Array(31),
        private_key: new Uint8Array(32),
        identifier: 'x',
      } as unknown as PlistObject),
    );
    expect(() => RpPairingFile.fromBytes(bad)).toThrow(/32 bytes/);

    const missingId = utf8Encoder.encode(
      buildPlist({
        public_key: new Uint8Array(32),
        private_key: new Uint8Array(32),
      } as unknown as PlistObject),
    );
    expect(() => RpPairingFile.fromBytes(missingId)).toThrow(/identifier/);
  });

  test('debug output redacts the private key', () => {
    const f = RpPairingFile.generate('debug-host');
    const dbg = f.toDebugString();
    expect(dbg).toContain(f.identifier);
    expect(dbg).toContain('<32 bytes>');
    const privB64 = btoa(String.fromCharCode(...f.privateKey));
    expect(dbg).not.toContain(privB64);
  });
});

// ---------------------------------------------------------------------------
// encodeTLV / decodeTLV (fragmenting numeric API)
// ---------------------------------------------------------------------------

import {
  encodeTLV,
  decodeTLV,
} from '../src/pairing/tlv.js';
import {
  encode as opackEncode,
  decode as opackDecode,
} from '../src/pairing/opack.js';
import {
  parseLockdownPairRecord,
  serializeLockdownPairRecord,
  parseRemotePairingFile,
  serializeRemotePairingFile,
  generateRemotePairingFile,
  generateHostID,
  generateSystemBUID,
  type LockdownPairRecord,
  type RemotePairingFile,
} from '../src/pairing/pairing-file.js';

describe('encodeTLV/decodeTLV', () => {
  test('round-trips small entries', () => {
    const entries = [
      { type: 0x01, value: new Uint8Array([1, 2, 3]) },
      { type: 0xff, value: new Uint8Array(0) },
    ];
    const back = decodeTLV(encodeTLV(entries));
    expect(back.length).toBe(2);
    expect(back[0].type).toBe(0x01);
    expect(back[0].value).toEqual(new Uint8Array([1, 2, 3]));
    expect(back[1].type).toBe(0xff);
    expect(back[1].value).toEqual(new Uint8Array(0));
  });

  test('fragments values longer than 255 bytes and merges them back', () => {
    const big = new Uint8Array(600);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    const wire = encodeTLV([{ type: 0x03, value: big }]);
    // 600 = 255 + 255 + 90 -> three fragments, 6 header bytes.
    expect(wire.length).toBe(606);
    expect(wire[0]).toBe(0x03);
    expect(wire[1]).toBe(255);
    expect(wire[257]).toBe(0x03);
    expect(wire[258]).toBe(255);
    expect(wire[514]).toBe(0x03);
    expect(wire[515]).toBe(90);
    const back = decodeTLV(wire);
    expect(back.length).toBe(1);
    expect(back[0].type).toBe(0x03);
    expect(back[0].value).toEqual(big);
  });

  test('keeps non-consecutive same-type entries separate', () => {
    const wire = encodeTLV([
      { type: 0x01, value: new Uint8Array([1]) },
      { type: 0x02, value: new Uint8Array([2]) },
      { type: 0x01, value: new Uint8Array([3]) },
    ]);
    const back = decodeTLV(wire);
    expect(back.length).toBe(3);
    expect(back[2].value).toEqual(new Uint8Array([3]));
  });

  test('rejects out-of-range types and truncated input', () => {
    expect(() => encodeTLV([{ type: 256, value: new Uint8Array(0) }])).toThrow();
    expect(() => decodeTLV(new Uint8Array([0x01, 0x05, 0x01]))).toThrow(/malformed/);
  });
});

// ---------------------------------------------------------------------------
// opack encode / decode (generic API)
// ---------------------------------------------------------------------------

describe('opack encode/decode', () => {
  test('round-trips a mixed value', () => {
    const value = {
      s: 'hello',
      i: 42,
      big: 70000,
      f: 1.5,
      b: true,
      d: new Uint8Array([9, 8, 7]),
      a: [1, 'x'],
      n: { k: 'v' },
    };
    const back = opackDecode(opackEncode(value)) as Record<string, unknown>;
    expect(back['s']).toBe('hello');
    expect(back['i']).toBe(42);
    expect(back['f']).toBe(1.5);
    expect(back['b']).toBe(true);
    expect(back['d']).toEqual(new Uint8Array([9, 8, 7]));
    expect(back['a']).toEqual([1, 'x']);
    expect(back['n']).toEqual({ k: 'v' });
  });

  test('round-trips uint64 bigints exactly', () => {
    const big = 0x123456789abcdef0n;
    const back = opackDecode(opackEncode({ u: big })) as Record<string, unknown>;
    expect(back['u']).toBe(big);
    // Small bigints decode as numbers.
    expect(opackDecode(opackEncode(7n))).toBe(7);
  });

  test('rejects null and unsupported types', () => {
    expect(() => opackEncode(null)).toThrow(TypeError);
    expect(() => opackEncode(undefined)).toThrow(TypeError);
    expect(() => opackEncode({ a: null })).toThrow(TypeError);
    expect(() => opackEncode(-1n)).toThrow(RangeError);
  });

  test('matches plistToOpack/opackToPlist on the t1 vector', () => {
    expect(opackEncode(t1Value())).toEqual(hexToBytes(T1_HEX));
    expect(plistDeepEqual(opackDecode(hexToBytes(T1_HEX)) as PlistValue, t1Value())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Lockdown / remote pairing record functions
// ---------------------------------------------------------------------------

function fakeLockdownRecord(): LockdownPairRecord {
  return {
    DeviceCertificate: utf8Encoder.encode('ZmFrZS1kZXZpY2UtY2VydA=='),
    HostCertificate: utf8Encoder.encode('aG9zdC1jZXJ0'),
    HostPrivateKey: utf8Encoder.encode('aG9zdC1rZXk='),
    RootCertificate: utf8Encoder.encode('cm9vdC1jZXJ0'),
    RootPrivateKey: utf8Encoder.encode('cm9vdC1rZXk='),
    SystemBUID: 'BUID-1',
    HostID: 'HOST-1',
    EscrowBag: new Uint8Array([1, 2, 3]),
    WiFiMACAddress: 'aa:bb:cc:dd:ee:ff',
    UDID: 'UDID-1',
  };
}

describe('lockdown pairing record functions', () => {
  test('serialize/parse round-trips', () => {
    const xml = serializeLockdownPairRecord(fakeLockdownRecord());
    expect(xml).toContain('<plist');
    const back = parseLockdownPairRecord(xml);
    expect(back.SystemBUID).toBe('BUID-1');
    expect(back.HostID).toBe('HOST-1');
    expect(back.UDID).toBe('UDID-1');
    expect(back.WiFiMACAddress).toBe('aa:bb:cc:dd:ee:ff');
    expect(back.EscrowBag).toEqual(new Uint8Array([1, 2, 3]));
    // PEM headers added on serialize.
    expect(utf8Decoder.decode(back.DeviceCertificate)).toContain('-----BEGIN CERTIFICATE-----');
  });

  test('optional fields may be omitted', () => {
    const { EscrowBag: _e, UDID: _u, WiFiMACAddress: _w, ...rest } = fakeLockdownRecord();
    const back = parseLockdownPairRecord(serializeLockdownPairRecord(rest));
    expect(back.EscrowBag).toBeUndefined();
    expect(back.UDID).toBeUndefined();
    expect(back.WiFiMACAddress).toBeUndefined();
  });

  test('generateHostID/generateSystemBUID produce uppercase UUID v4', () => {
    const re = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/;
    expect(generateHostID()).toMatch(re);
    expect(generateSystemBUID()).toMatch(re);
    expect(generateHostID()).not.toBe(generateHostID());
  });
});

describe('remote pairing file functions', () => {
  test('serialize/parse round-trips', () => {
    const f: RemotePairingFile = {
      public_key: new Uint8Array(32).fill(0x11),
      private_key: new Uint8Array(32).fill(0x22),
      identifier: 'some-identifier',
      alt_irk: new Uint8Array(16).fill(0x33),
    };
    const xml = serializeRemotePairingFile(f);
    expect(xml).toContain('<plist');
    const back = parseRemotePairingFile(xml);
    expect(back.public_key).toEqual(f.public_key);
    expect(back.private_key).toEqual(f.private_key);
    expect(back.identifier).toBe('some-identifier');
    expect(back.alt_irk).toEqual(new Uint8Array(16).fill(0x33));
  });

  test('generateRemotePairingFile creates valid records', () => {
    const f = generateRemotePairingFile('test-host');
    expect(f.public_key.length).toBe(32);
    expect(f.private_key.length).toBe(32);
    expect(f.identifier).toMatch(UUID_V3_RE);
    const back = parseRemotePairingFile(serializeRemotePairingFile(f));
    expect(back.private_key).toEqual(f.private_key);
  });

  test('parse validates key lengths', () => {
    const bad = serializeRemotePairingFile({
      public_key: new Uint8Array(32),
      private_key: new Uint8Array(32),
      identifier: 'x',
    }).replace(/<data>[^<]*<\/data>/, '<data>AA==</data>');
    expect(() => parseRemotePairingFile(bad)).toThrow();
  });
});
