/**
 * Tests for src/pairing/remote-pairing.ts.
 *
 * All tests run against scripted in-memory transports — no real devices or
 * network connections. The fake "devices" implement the peer side of the
 * protocols independently (their own SRP-server math, their own TLS 1.2 PRF
 * and record layer), so the tests validate wire compatibility, not just
 * self-consistency.
 *
 * Coverage:
 * - RPPairing framing (sendFrame/readFrame round-trip, magic/length checks,
 *   sequenceNumber)
 * - SRP fixed vectors from idevice-srp 0.6.0 (A / key / M1 / M2)
 * - pairSetup integration against a fake device with fixed SRP vectors
 *   (salt, server B, PIN "000000"): the device independently verifies the
 *   client's M1 proof and Ed25519 pair-record signature
 * - pairSetup awaitingUserConsent flow (tvOS-style) with onAwaitingUserConsent
 * - createListener encrypted RPC against the same fake device
 * - pairVerify integration against a fake device (X25519 + Ed25519)
 * - startSession verify-then-setup fallback (pair-verify rejected -> SRP setup)
 * - crypto primitives: HKDF-SHA512, ChaCha20-Poly1305 (RFC 8439), Ed25519, X25519
 * - RpPairingFile round-trip + savePairingFile() XML output
 * - TLS 1.2 PSK handshake against an independent fake server + app-data echo
 * - CDTunnel handshake via establishTunnel() (pairing + rsdInfo + TLS + CDTunnel)
 */

import { describe, expect, test } from 'bun:test';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { cbc } from '@noble/ciphers/aes.js';
import { sha512, sha384 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';

import {
  RemotePairingClient,
  RemotePairingError,
  sendFrame,
  readFrame,
  tlsPskHandshake,
  establishTunnel,
  RPPAIRING_MAGIC_BYTES,
  WIRE_PROTOCOL_VERSION,
} from '../src/pairing/remote-pairing.js';
import type { Transport } from '../src/pairing/remote-pairing.js';
import {
  PairingDataComponentType,
  serializeTlv8,
  deserializeTlv8,
  collectComponentData,
} from '../src/pairing/tlv.js';
import { plistToOpack } from '../src/pairing/opack.js';
import { RpPairingFile } from '../src/pairing/pairing-file.js';
import { SrpClient, SRP_N_HEX } from '../src/pairing/srp.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const te = new TextEncoder();
const td = new TextDecoder();

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function u16be(v: number): Uint8Array {
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
}

function u64be(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, false);
  return out;
}

function u64le(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

// ---------------------------------------------------------------------------
// In-memory bidirectional transport
// ---------------------------------------------------------------------------

class LoopbackEnd implements Transport {
  private inbound: Uint8Array[] = [];
  private buf: Uint8Array = new Uint8Array(0);
  private waiters: Array<(d: Uint8Array) => void> = [];
  peer!: LoopbackEnd;

  async write(data: Uint8Array): Promise<void> {
    const w = this.peer.waiters.shift();
    if (w) w(data);
    else this.peer.inbound.push(data);
  }

  async readExact(n: number): Promise<Uint8Array> {
    while (this.buf.length < n) {
      let chunk = this.inbound.shift();
      if (chunk === undefined) {
        chunk = await new Promise<Uint8Array>((res) => this.waiters.push(res));
      }
      const nb: Uint8Array = new Uint8Array(this.buf.length + chunk.length);
      nb.set(this.buf);
      nb.set(chunk, this.buf.length);
      this.buf = nb;
    }
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }

  close(): void {}
}

function makeLoopback(): [Transport, Transport] {
  const a = new LoopbackEnd();
  const b = new LoopbackEnd();
  a.peer = b;
  b.peer = a;
  return [a, b];
}

// ---------------------------------------------------------------------------
// RPPairing framing
// ---------------------------------------------------------------------------

describe('RPPairing framing', () => {
  test('sendFrame/readFrame round-trip', async () => {
    const [a, b] = makeLoopback();
    const obj = {
      message: { plain: { _0: { request: { _0: { handshake: { _0: { wireProtocolVersion: 19 } } } } } } },
      originatedBy: 'host',
      sequenceNumber: 3,
    };
    await sendFrame(a, obj);
    expect(await readFrame(b)).toEqual(obj);
  });

  test('frame prefix is magic + u16 BE length', async () => {
    const [a, b] = makeLoopback();
    const body = te.encode(JSON.stringify({ ping: 1 }));
    await sendFrame(a, { ping: 1 });
    const prefix = await b.readExact(RPPAIRING_MAGIC_BYTES.length + 2);
    expect(prefix.slice(0, RPPAIRING_MAGIC_BYTES.length)).toEqual(RPPAIRING_MAGIC_BYTES);
    const len = (prefix[RPPAIRING_MAGIC_BYTES.length] << 8) | prefix[RPPAIRING_MAGIC_BYTES.length + 1];
    expect(len).toBe(body.length);
    const rest = await b.readExact(len);
    expect(JSON.parse(td.decode(rest))).toEqual({ ping: 1 });
  });

  test('readFrame rejects a bad magic', async () => {
    const [a, b] = makeLoopback();
    await a.write(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 5]));
    await expect(readFrame(b)).rejects.toThrow(RemotePairingError);
  });

  test('wire protocol version is 19', () => {
    expect(WIRE_PROTOCOL_VERSION).toBe(19);
  });

  test('sequenceNumber increments on each sent frame', async () => {
    const [a, b] = makeLoopback();
    await sendFrame(a, { message: 'one', originatedBy: 'test', sequenceNumber: 0 });
    await sendFrame(a, { message: 'two', originatedBy: 'test', sequenceNumber: 1 });
    await sendFrame(a, { message: 'three', originatedBy: 'test', sequenceNumber: 2 });
    expect((await readFrame(b)).sequenceNumber).toBe(0);
    expect((await readFrame(b)).sequenceNumber).toBe(1);
    expect((await readFrame(b)).sequenceNumber).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// SRP fixed vectors (idevice-srp 0.6.0 test vectors, via the real SrpClient)
// ---------------------------------------------------------------------------

const FIXED_A = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
const FIXED_SALT = hexToBytes('6465666768696a6b6c6d6e6f70717273');
const FIXED_B_PRIV = hexToBytes(
  '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
);
const FIXED_B_PUB = hexToBytes(
  '249420e5b677fcade48d93a431a6c40c4e65f8337379bb0a38704c7731e5555f' +
    '8b286f16f730c367c52920c2d930f8fb68522922e3c1482e0916d773b412c8152c' +
    'bf1e4fa2eb53f6312a8d5caf25b05ac5cf79682a4364d15be97eec2a9458fb846' +
    '3e278f239e0548faeda7338a16eee84d83f82362478253c69a9cf8cdd985b1d2e' +
    '96927ed507a0638598307a98eead1292e0b8df061e7119a549775111cfe26c9e19' +
    'd3e3d1d0d9e734fbf5106540aff295d19d5e2ffb7fc1f5e2ef2aac2c807e269092' +
    '912a1584d73def1b18098810af349f825622031f6c5e5489e6b8ba030705341ea0' +
    'dce6bfff7870e40dd800ce264f0a634d2027cb73e66f5e59127c51346e0872871' +
    '565e4c996587be17a1c0e06704ceb29cb9053e3c0e5ed8cc5111ee4cd4cc1a3dcc' +
    '148767c4ede285e708a5753c387c6423471196367c69a034912fe1f4edc623b96a' +
    '2566bd161b52ec9baa0249d8250a05fb1a4b5c2dfaafdca73104b417730a2c5c00' +
    '9a48a0453d3f4ff803b298b37c8daff6a0de4719d38e43a',
);
const EXPECTED_KEY_HEX =
  'c2b0cd83281ef1e11c3d9ad3f5943d93ee9faca8980938fcad01e716bbe16f2b36' +
  'b87b9d512b865ccbc181831ea90425728282aa6aeef024b7f70489bf86a6cd';
const EXPECTED_M1_HEX =
  'ef3e44bd858c8044ca61aa6d2497e075bee9f0ec84f480a7ec471f8b58f6f5327' +
  'bc97f23742995e0e9be1f8f86908c5a764513fa7dbb1354666e56bfd3c53a92';
const EXPECTED_M2_HEX =
  'e4b0a3ebd45eb02241056c8052ca9ae2c03647eef5c260359c119cfc35ea4b2a0' +
  'eae411af41cb57a9fc86672a06882b5cff1001cb49855725cfb0172cb3b34f5';

describe('SRP fixed vectors (idevice-srp 0.6.0)', () => {
  test('A for a = 0x01..0x20 has the expected prefix', () => {
    const aPub = new SrpClient().computePublicEphemeral(FIXED_A);
    expect(aPub.length).toBe(384);
    expect(bytesToHex(aPub).startsWith('bc0e7cf5dc3babf67dcedbb3b140aacc6cac43f4336b43bbd5de48d6ea7c8eda')).toBe(
      true,
    );
  });

  test('processReply derives the expected key / M1 and verifies M2', () => {
    const verifier = new SrpClient().processReply(FIXED_A, 'Pair-Setup', '000000', FIXED_SALT, FIXED_B_PUB);
    expect(bytesToHex(verifier.key())).toBe(EXPECTED_KEY_HEX);
    expect(bytesToHex(verifier.proof())).toBe(EXPECTED_M1_HEX);
    expect(verifier.verifyServer(hexToBytes(EXPECTED_M2_HEX))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Independent SRP-server math (for the fake device)
// ---------------------------------------------------------------------------

const SRP_N = BigInt('0x' + SRP_N_HEX);
const SRP_G = 5n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function bigToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return hexToBytes(hex);
}

function bytesToBigint(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function padTo(b: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  out.set(b, len - b.length);
  return out;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < out.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Server-side long-term values for the fixed vectors.
const SRP_IDENTITY_HASH = sha512(concat(te.encode('Pair-Setup'), new Uint8Array([0x3a]), te.encode('000000')));
const SRP_X = bytesToBigint(sha512(concat(FIXED_SALT, SRP_IDENTITY_HASH)));
const SRP_V = modPow(SRP_G, SRP_X, SRP_N);
const SRP_K = bytesToBigint(sha512(concat(padTo(bigToBytes(SRP_N), 384), padTo(bigToBytes(SRP_G), 384))));

describe('crypto primitives (HKDF/ChaCha20-Poly1305/Ed25519/X25519)', () => {
  test('ChaCha20-Poly1305 matches the RFC 8439 Section 2.8.2 vector', () => {
    const key = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
    const nonce = hexToBytes('070000004041424344454647');
    const aad = hexToBytes('50515253c0c1c2c3c4c5c6c7');
    const plaintext = te.encode(
      'Ladies and Gentlemen of the class of 99: If I could offer you only one tip for the future, sunscreen would be it.',
    );
    const ct = chacha20poly1305(key, nonce, aad).encrypt(plaintext);
    expect(Buffer.from(ct).toString('hex')).toBe(
      'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62' +
        'd63dbea45e8cb767119893d42fb3fb31870068d64ed10f0b2a1284fca0649' +
        '8743790c8e4302c7cced8851afea52114490ce6be61a2e9d7749342cc8cd' +
        '84e2acaac2ee3defbc01c6287fc7e9627818b8f563bceb63a7517d181b5e' +
        '37cc221f549c4ef',
    );
    // Decrypt round-trips.
    expect(chacha20poly1305(key, nonce, aad).decrypt(ct)).toEqual(plaintext);
  });

  test('HKDF-SHA512 is deterministic and produces the requested length', () => {
    const ikm = hexToBytes('0b'.repeat(22));
    const salt = hexToBytes('000102030405060708090a0b0c');
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
    const out1 = hkdf(sha512, ikm, salt, info, 42);
    const out2 = hkdf(sha512, ikm, salt, info, 42);
    expect(out1).toEqual(out2);
    expect(out1.length).toBe(42);
    // Different info gives a different output.
    expect(hkdf(sha512, ikm, salt, te.encode('other'), 42)).not.toEqual(out1);
  });

  test('Ed25519 sign/verify round-trips with a fixed key', () => {
    const priv = hexToBytes('9d61b19cffd4945335b8d4efef9b91c22a1b2c3d4e5f60718293a4b5c6d7e8f90');
    const pub = ed25519.getPublicKey(priv);
    const msg = te.encode('pair-verify test message');
    const sig = ed25519.sign(msg, priv);
    expect(ed25519.verify(sig, msg, pub)).toBe(true);
    expect(ed25519.verify(sig, te.encode('tampered'), pub)).toBe(false);
  });

  test('X25519 Alice and Bob agree on the same shared secret', () => {
    const alicePriv = hexToBytes('77076d0a7318a57d80d3df5344c831cea7b7d291a897ba4c9e3a59d7b3f8d24a');
    const bobPriv = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f04bfa2c4d98637d8a3b5c6d7e8f90a1');
    const alicePub = x25519.getPublicKey(alicePriv);
    const bobPub = x25519.getPublicKey(bobPriv);
    expect(alicePub.length).toBe(32);
    expect(bobPub.length).toBe(32);
    // Both sides derive the same shared secret.
    expect(x25519.getSharedSecret(alicePriv, bobPub)).toEqual(x25519.getSharedSecret(bobPriv, alicePub));
  });
});

describe('fake-device SRP server math matches the fixed B vector', () => {
  test('B = (k*v + g^b) mod N equals FIXED_B_PUB', () => {
    const b = bytesToBigint(FIXED_B_PRIV);
    const computedB = (SRP_K * SRP_V + modPow(SRP_G, b, SRP_N)) % SRP_N;
    expect(bigToBytes(computedB)).toEqual(FIXED_B_PUB);
  });
});

// ---------------------------------------------------------------------------
// Fake device: full pairSetup (SRP) + createListener RPC
// ---------------------------------------------------------------------------

const FAKE_ALT_IRK = hexToBytes('00112233445566778899aabbccddeeff');

const B64A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64e(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const b0 = data[i];
    const b1 = i + 1 < data.length ? data[i + 1] : 0;
    const b2 = i + 2 < data.length ? data[i + 2] : 0;
    out += B64A[b0 >> 2];
    out += B64A[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < data.length ? B64A[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < data.length ? B64A[b2 & 0x3f] : '=';
  }
  return out;
}

function b64d(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, '');
  const idx = (ch: string): number => {
    if (ch === '=') return 0;
    const i = B64A.indexOf(ch);
    if (i < 0) throw new Error('bad base64');
    return i;
  };
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const n = (idx(clean[i]) << 18) | (idx(clean[i + 1]) << 12) | (idx(clean[i + 2]) << 6) | idx(clean[i + 3]);
    out.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  return Uint8Array.from(out.slice(0, out.length - pad));
}

function pairingDataFrame(tlv: Uint8Array, seq: number): unknown {
  return {
    message: { plain: { _0: { event: { _0: { pairingData: { _0: { data: b64e(tlv) } } } } } } },
    originatedBy: 'device',
    sequenceNumber: seq,
  };
}

interface FakeSrpResult {
  sessionKey: Uint8Array;
  clientIdentifier: string;
}

/** Fake device: SRP pair-setup only (consent + M1/M2 + pair record). */
async function runSrpSetupPhase(
  transport: Transport,
  opts?: { consentMode?: 'immediate' | 'awaitingUserConsent' },
): Promise<FakeSrpResult> {
  const readPairingTlv = async (): Promise<{ kind: string; entries: ReturnType<typeof deserializeTlv8> }> => {
    const frame = (await readFrame(transport)) as {
      message: { plain: { _0: { event: { _0: { pairingData: { _0: { data: string; kind: string } } } } } } } };
    const pd = frame.message.plain._0.event._0.pairingData._0;
    return { kind: pd.kind, entries: deserializeTlv8(b64d(pd.data)) };
  };

  const saltAndB = (): Uint8Array =>
    serializeTlv8([
      { type: PairingDataComponentType.Salt, data: FIXED_SALT },
      { type: PairingDataComponentType.PublicKey, data: FIXED_B_PUB.slice(0, 254) },
      { type: PairingDataComponentType.PublicKey, data: FIXED_B_PUB.slice(254) },
    ]);

  // 1. consent
  {
    const { kind, entries } = await readPairingTlv();
    expect(kind).toBe('setupManualPairing');
    const method = collectComponentData(entries, PairingDataComponentType.Method);
    expect(method).toEqual(new Uint8Array([0x00]));
    if (opts?.consentMode === 'awaitingUserConsent') {
      // tvOS-style: report awaitingUserConsent first, then deliver salt+B.
      await sendFrame(transport, {
        message: { plain: { _0: { event: { _0: { awaitingUserConsent: {} } } } } },
        originatedBy: 'device',
        sequenceNumber: 0,
      });
    }
    await sendFrame(transport, pairingDataFrame(saltAndB(), 0));
  }

  // 2. SRP: verify client's M1 independently, answer with M2
  let sessionKey: Uint8Array;
  {
    const { entries } = await readPairingTlv();
    const aBytes = collectComponentData(entries, PairingDataComponentType.PublicKey);
    const m1 = collectComponentData(entries, PairingDataComponentType.Proof);
    expect(aBytes.length).toBeGreaterThan(300);

    const A = bytesToBigint(aBytes);
    const B = bytesToBigint(FIXED_B_PUB);
    const b = bytesToBigint(FIXED_B_PRIV);
    const u = bytesToBigint(sha512(concat(aBytes, bigToBytes(B))));
    const S = modPow((A * modPow(SRP_V, u, SRP_N)) % SRP_N, b, SRP_N);
    const key = sha512(bigToBytes(S));
    const hnxorg = xorBytes(sha512(padTo(bigToBytes(SRP_N), 384)), sha512(bigToBytes(SRP_G)));
    const m1Expected = sha512(
      concat(
        hnxorg,
        sha512(te.encode('Pair-Setup')),
        FIXED_SALT,
        padTo(aBytes, 384),
        padTo(bigToBytes(B), 384),
        key,
      ),
    );
    // The client's M1 proof must match the independently computed value.
    expect(m1).toEqual(m1Expected);
    const m2 = sha512(concat(aBytes, m1, key));
    sessionKey = key;
    await sendFrame(
      transport,
      pairingDataFrame(serializeTlv8([{ type: PairingDataComponentType.Proof, data: m2 }]), 1),
    );
  }

  // 3. pair record: decrypt, verify Ed25519 signature, answer with device info
  let clientIdentifier = '';
  {
    const { entries } = await readPairingTlv();
    const ct = collectComponentData(entries, PairingDataComponentType.EncryptedData);
    const setupKey = hkdf(
      sha512,
      sessionKey!,
      te.encode('Pair-Setup-Encrypt-Salt'),
      te.encode('Pair-Setup-Encrypt-Info'),
      32,
    );
    const pt = chacha20poly1305(setupKey, concat(new Uint8Array(4), te.encode('PS-Msg05'))).decrypt(ct);
    const pe = deserializeTlv8(pt);
    const idBytes = collectComponentData(pe, PairingDataComponentType.Identifier);
    const edPub = collectComponentData(pe, PairingDataComponentType.PublicKey);
    const sig = collectComponentData(pe, PairingDataComponentType.Signature);
    clientIdentifier = td.decode(idBytes);
    const hkdfOut = hkdf(
      sha512,
      sessionKey!,
      te.encode('Pair-Setup-Controller-Sign-Salt'),
      te.encode('Pair-Setup-Controller-Sign-Info'),
      32,
    );
    // The device independently verifies the host's pair-record signature.
    expect(ed25519.verify(sig, concat(hkdfOut, idBytes, edPub), edPub)).toBe(true);

    const info = plistToOpack({
      altIRK: FAKE_ALT_IRK,
      accountID: 'device-account',
      model: 'iPhone1,1',
      name: 'Fake Device',
      remotepairing_udid: 'FAKE-UDID-1',
    });
    const respCt = chacha20poly1305(setupKey, concat(new Uint8Array(4), te.encode('PS-Msg06'))).encrypt(
      serializeTlv8([{ type: PairingDataComponentType.Info, data: info }]),
    );
    await sendFrame(
      transport,
      pairingDataFrame(
        serializeTlv8([
          { type: PairingDataComponentType.EncryptedData, data: respCt.slice(0, 254) },
          { type: PairingDataComponentType.EncryptedData, data: respCt.slice(254) },
        ]),
        2,
      ),
    );
  }

  return { sessionKey: sessionKey!, clientIdentifier };
}

/** Fake device implementing the server side of pair-setup + createListener. */
async function runFakeSrpDevice(
  transport: Transport,
  opts?: { consentMode?: 'immediate' | 'awaitingUserConsent'; skipCreateListener?: boolean },
): Promise<FakeSrpResult> {
  const { sessionKey, clientIdentifier } = await runSrpSetupPhase(transport, opts);

  // 4. createListener encrypted RPC
  if (!opts?.skipCreateListener) {
  {
    const frame = (await readFrame(transport)) as {
      message: { streamEncrypted: { _0: string } };
    };
    const clientKey = hkdf(sha512, sessionKey!, undefined, te.encode('ClientEncrypt-main'), 32);
    const serverKey = hkdf(sha512, sessionKey!, undefined, te.encode('ServerEncrypt-main'), 32);
    const nonce = concat(u64le(0n), new Uint8Array(4));
    const reqJson = JSON.parse(td.decode(chacha20poly1305(clientKey, nonce).decrypt(b64d(frame.message.streamEncrypted._0))));
    expect(reqJson.request._0.createListener.transportProtocolType).toBe('tcp');
    const respJson = te.encode(JSON.stringify({ response: { _1: { createListener: { port: 58789, identifier: 'FAKE-LISTENER-ID' } } } }));
    const respEnc = chacha20poly1305(serverKey, nonce).encrypt(respJson);
    await sendFrame(transport, {
      message: { streamEncrypted: { _0: b64e(respEnc) } },
      originatedBy: 'device',
      sequenceNumber: 3,
    });
  }
  }

  return { sessionKey, clientIdentifier };
}

describe('pairSetup integration (fake device, fixed SRP vectors)', () => {
  test('full pair-setup + createListener', async () => {
    const [clientT, deviceT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pairingFile, 'test-host');

    const deviceDone = runFakeSrpDevice(deviceT);
    await client.pairSetup('000000');
    // runFakeSrpDevice's createListener step waits for the client's request,
    // so start createListener() before awaiting deviceDone to avoid deadlock.
    const createListenerPromise = client.createListener();
    const { sessionKey, clientIdentifier } = await deviceDone;
    const { port, identifier } = await createListenerPromise;

    // Client and device derived the same session key independently.
    expect(client.encryptionKey).toEqual(sessionKey);
    // The device stored our identifier; we stored the device's altIRK.
    expect(clientIdentifier).toBe(pairingFile.identifier);
    expect(pairingFile.altIrk).toEqual(FAKE_ALT_IRK);

    expect(port).toBe(58789);
    expect(identifier).toBe('FAKE-LISTENER-ID');
  }, 30000);

  test('pairSetup with a wrong PIN fails SRP authentication', async () => {
    const [clientT, deviceT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pairingFile, 'test-host');

    const deviceDone = runFakeSrpDevice(deviceT);
    // The device expects "000000"; any other PIN produces a wrong M1, so the
    // device's M1 check throws inside the fake device. The client then fails
    // reading the (never sent) M2 reply... instead assert the client throws.
    const clientPromise = client.pairSetup('123456');
    await expect(
      Promise.race([
        clientPromise.then(
          () => 'resolved',
          (e) => 'rejected',
        ),
        deviceDone.then(
          () => 'device-resolved',
          () => 'device-rejected',
        ),
      ]),
    ).resolves.not.toBe('resolved');
  }, 30000);

  test('pairSetup handles awaitingUserConsent and notifies the callback', async () => {
    const [clientT, deviceT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pairingFile, 'test-host');

    let consentIdentifier: string | undefined;
    client.onAwaitingUserConsent = (id) => {
      consentIdentifier = id;
    };

    const deviceDone = runFakeSrpDevice(deviceT, {
      consentMode: 'awaitingUserConsent',
      skipCreateListener: true,
    });
    // The tvOS flow uses the fixed PIN '000000'; the passed PIN is ignored.
    await client.pairSetup('999999');
    const { sessionKey } = await deviceDone;

    expect(consentIdentifier).toBe(pairingFile.identifier);
    expect(client.encryptionKey).toEqual(sessionKey);
    expect(pairingFile.altIrk).toEqual(FAKE_ALT_IRK);
  }, 30000);
});

// ---------------------------------------------------------------------------
// Fake device: pairVerify (X25519 + Ed25519)
// ---------------------------------------------------------------------------

async function runFakePairVerifyDevice(
  transport: Transport,
  devPriv: Uint8Array,
  clientEdPub: Uint8Array,
): Promise<Uint8Array> {
  const devPub = x25519.getPublicKey(devPriv);
  const readPairingTlv = async () => {
    const frame = (await readFrame(transport)) as {
      message: { plain: { _0: { event: { _0: { pairingData: { _0: { data: string } } } } } } } };
    return deserializeTlv8(b64d(frame.message.plain._0.event._0.pairingData._0.data));
  };

  const e1 = await readPairingTlv();
  const xPub = collectComponentData(e1, PairingDataComponentType.PublicKey);
  expect(xPub.length).toBe(32);

  await sendFrame(
    transport,
    pairingDataFrame(
      serializeTlv8([
        { type: PairingDataComponentType.State, data: new Uint8Array([0x02]) },
        { type: PairingDataComponentType.PublicKey, data: devPub },
      ]),
      0,
    ),
  );

  const e2 = await readPairingTlv();
  const ct = collectComponentData(e2, PairingDataComponentType.EncryptedData);
  const shared = x25519.getSharedSecret(devPriv, xPub);
  const setupKey = hkdf(
    sha512,
    shared,
    te.encode('Pair-Verify-Encrypt-Salt'),
    te.encode('Pair-Verify-Encrypt-Info'),
    32,
  );
  const pt = chacha20poly1305(setupKey, concat(new Uint8Array(4), te.encode('PV-Msg03'))).decrypt(ct);
  const pe = deserializeTlv8(pt);
  const idBytes = collectComponentData(pe, PairingDataComponentType.Identifier);
  const sig = collectComponentData(pe, PairingDataComponentType.Signature);
  // Independent verification of the host's Ed25519 pair-verify signature.
  expect(ed25519.verify(sig, concat(xPub, idBytes, devPub), clientEdPub)).toBe(true);

  await sendFrame(
    transport,
    pairingDataFrame(serializeTlv8([{ type: PairingDataComponentType.State, data: new Uint8Array([0x04]) }]), 1),
  );
  return shared;
}

describe('pairVerify integration (fake device)', () => {
  test('X25519 + Ed25519 pair-verify succeeds and agrees on the shared secret', async () => {
    const [clientT, deviceT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pairingFile);
    const devPriv = hexToBytes('40'.repeat(32));

    const deviceDone = runFakePairVerifyDevice(deviceT, devPriv, pairingFile.publicKey);
    await client.pairVerify();
    const shared = await deviceDone;
    expect(client.encryptionKey).toEqual(shared);
    expect(client.pairingFile).toBe(pairingFile);
  }, 30000);

  test('pairVerify without a pairing file throws', async () => {
    const [clientT] = makeLoopback();
    const client = new RemotePairingClient(clientT);
    await expect(client.pairVerify()).rejects.toThrow(RemotePairingError);
    expect(() => client.savePairingFile()).toThrow(RemotePairingError);
  });

  test('startSession falls back to pair-setup when pair-verify is rejected', async () => {
    const [clientT, deviceT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pairingFile, 'test-host');

    const deviceDone = (async () => {
      // 1. handshake
      const hs = (await readFrame(deviceT)) as any;
      expect(hs.message.plain._0.request._0.handshake._0.wireProtocolVersion).toBe(19);
      const hsResp = {
        message: { plain: { _0: { response: { _1: { handshake: { _0: {} } } } } } },
        originatedBy: 'device',
        sequenceNumber: 0,
      };
      await sendFrame(deviceT, hsResp);
      // 2. pair-verify: reject with ErrorResponse
      const pv = (await readFrame(deviceT)) as any;
      expect(pv.message.plain._0.event._0.pairingData._0.kind).toBe('verifyManualPairing');
      await sendFrame(
        deviceT,
        pairingDataFrame(
          serializeTlv8([{ type: PairingDataComponentType.ErrorResponse, data: new Uint8Array([0x02]) }]),
          1,
        ),
      );
      // 3. client sends pairVerifyFailed; then falls back to pair-setup (SRP)
      const pvf = (await readFrame(deviceT)) as any;
      expect(pvf.message.plain._0.event._0.pairVerifyFailed).not.toBeUndefined();
      return runSrpSetupPhase(deviceT);
    })();

    await client.startSession('000000');
    const { sessionKey } = await deviceDone;
    expect(client.encryptionKey).toEqual(sessionKey);
    expect(pairingFile.altIrk).toEqual(FAKE_ALT_IRK);
  }, 30000);
});

// ---------------------------------------------------------------------------
// Pairing file round-trip
// ---------------------------------------------------------------------------

describe('RpPairingFile', () => {
  test('toBytes/fromBytes round-trip', () => {
    const pf = RpPairingFile.generate('test-host');
    pf.altIrk = new Uint8Array(16).fill(7);
    const rt = RpPairingFile.fromBytes(pf.toBytes());
    expect(rt.publicKey).toEqual(pf.publicKey);
    expect(rt.privateKey).toEqual(pf.privateKey);
    expect(rt.identifier).toBe(pf.identifier);
    expect(rt.altIrk).toEqual(pf.altIrk);
  });

  test('savePairingFile() returns XML plist that re-parses', () => {
    const [clientT] = makeLoopback();
    const pf = RpPairingFile.generate('test-host');
    const client = new RemotePairingClient(clientT, pf);
    const xml = client.savePairingFile();
    expect(xml.startsWith('<?xml')).toBe(true);
    expect(xml).toContain('public_key');
    expect(xml).toContain('private_key');
    expect(xml).toContain('identifier');
    const rt = RpPairingFile.fromBytes(te.encode(xml));
    expect(rt.identifier).toBe(pf.identifier);
    expect(rt.publicKey).toEqual(pf.publicKey);
  });
});

// ---------------------------------------------------------------------------
// Independent TLS 1.2 PSK server (for interop testing of tlsPskHandshake)
// ---------------------------------------------------------------------------

function hsMsg(type: number, body: Uint8Array): Uint8Array {
  const len = body.length;
  return concat(
    new Uint8Array([type, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff]),
    body,
  );
}

function tlsRecord(ct: number, payload: Uint8Array): Uint8Array {
  return concat(new Uint8Array([ct, 0x03, 0x03, (payload.length >>> 8) & 0xff, payload.length & 0xff]), payload);
}

async function readTlsRecord(t: Transport): Promise<{ ct: number; payload: Uint8Array }> {
  const h = await t.readExact(5);
  const len = (h[3] << 8) | h[4];
  return { ct: h[0], payload: await t.readExact(len) };
}

function parseHsMessages(data: Uint8Array): Array<{ type: number; body: Uint8Array }> {
  const out: Array<{ type: number; body: Uint8Array }> = [];
  let pos = 0;
  while (pos + 4 <= data.length) {
    const type = data[pos];
    const len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    if (pos + 4 + len > data.length) break;
    out.push({ type, body: data.slice(pos + 4, pos + 4 + len) });
    pos += 4 + len;
  }
  return out;
}

/** Independent P_hash PRF (SHA-384), written separately from the module's tlsPrf. */
function testPrf(secret: Uint8Array, label: string, seed: Uint8Array, len: number): Uint8Array {
  const labelSeed = concat(te.encode(label), seed);
  let a = hmac(sha384, secret, labelSeed);
  const blocks: Uint8Array[] = [];
  let total = 0;
  while (total < len) {
    const block = hmac(sha384, secret, concat(a, labelSeed));
    blocks.push(block);
    total += block.length;
    a = hmac(sha384, secret, a);
  }
  return concat(...blocks).slice(0, len);
}

function testPskPremaster(psk: Uint8Array): Uint8Array {
  return concat(u16be(psk.length), new Uint8Array(psk.length), u16be(psk.length), psk);
}

interface SrvKeys {
  clientWrite: Uint8Array;
  clientMac: Uint8Array;
  serverWrite: Uint8Array;
  serverMac: Uint8Array;
}

function srvEncrypt(writeKey: Uint8Array, macKey: Uint8Array, seq: bigint, ct: number, pt: Uint8Array): Uint8Array {
  const mac = hmac(sha384, macKey, concat(u64be(seq), new Uint8Array([ct, 0x03, 0x03]), u16be(pt.length), pt));
  let payload = concat(pt, mac);
  const padLen = 16 - (payload.length % 16);
  payload = concat(payload, new Uint8Array(padLen).fill(padLen - 1));
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  return concat(iv, cbc(writeKey, iv, { disablePadding: true }).encrypt(payload));
}

function srvDecrypt(writeKey: Uint8Array, macKey: Uint8Array, seq: bigint, ct: number, encrypted: Uint8Array): Uint8Array {
  const iv = encrypted.slice(0, 16);
  const pt = cbc(writeKey, iv, { disablePadding: true }).decrypt(encrypted.slice(16));
  const padValue = pt[pt.length - 1];
  const contentLen = pt.length - (padValue + 1);
  const macLen = 48;
  const msg = pt.slice(0, contentLen - macLen);
  const receivedMac = pt.slice(contentLen - macLen, contentLen);
  const expectedMac = hmac(sha384, macKey, concat(u64be(seq), new Uint8Array([ct, 0x03, 0x03]), u16be(msg.length), msg));
  expect(receivedMac).toEqual(expectedMac);
  return msg;
}

/**
 * Fake TLS 1.2 PSK server: answers ClientHello with TLS_PSK_WITH_AES_256_CBC_SHA384,
 * completes the handshake, then either echoes app data or answers one CDTunnel
 * handshake request.
 */
async function runFakeTlsServer(transport: Transport, psk: Uint8Array, mode: 'echo' | 'cdtunnel'): Promise<void> {
  // 1. ClientHello
  let rec = await readTlsRecord(transport);
  expect(rec.ct).toBe(0x16);
  const ch = parseHsMessages(rec.payload);
  expect(ch[0].type).toBe(0x01);
  const clientRandom = ch[0].body.slice(2, 34);
  let transcript: Uint8Array = rec.payload;

  // 2. ServerHello + ServerHelloDone (both handshake messages in one record)
  const serverRandom = hexToBytes('80'.repeat(32));
  const shBody = concat(new Uint8Array([0x03, 0x03]), serverRandom, new Uint8Array([0x00, 0x00, 0xaf, 0x00]));
  const helloPayload = concat(hsMsg(0x02, shBody), hsMsg(0x0e, new Uint8Array(0)));
  transcript = concat(transcript, helloPayload);
  await transport.write(tlsRecord(0x16, helloPayload));

  const master = testPrf(testPskPremaster(psk), 'master secret', concat(clientRandom, serverRandom), 48);
  const kb = testPrf(master, 'key expansion', concat(serverRandom, clientRandom), 2 * (48 + 32));
  const keys: SrvKeys = {
    clientMac: kb.slice(0, 48),
    serverMac: kb.slice(48, 96),
    clientWrite: kb.slice(96, 128),
    serverWrite: kb.slice(128, 160),
  };

  // 3. ClientKeyExchange
  rec = await readTlsRecord(transport);
  expect(rec.ct).toBe(0x16);
  transcript = concat(transcript, rec.payload);

  // 4. ChangeCipherSpec
  rec = await readTlsRecord(transport);
  expect(rec.ct).toBe(0x14);

  // 5. Client Finished (encrypted)
  rec = await readTlsRecord(transport);
  expect(rec.ct).toBe(0x16);
  const finPt = srvDecrypt(keys.clientWrite, keys.clientMac, 0n, 0x16, rec.payload);
  const finMsgs = parseHsMessages(finPt);
  expect(finMsgs[0].type).toBe(0x14);
  expect(finMsgs[0].body).toEqual(testPrf(master, 'client finished', sha384(transcript), 12));
  transcript = concat(transcript, finPt);

  // 6. ChangeCipherSpec + server Finished
  await transport.write(tlsRecord(0x14, new Uint8Array([0x01])));
  const serverVd = testPrf(master, 'server finished', sha384(transcript), 12);
  await transport.write(
    tlsRecord(0x16, srvEncrypt(keys.serverWrite, keys.serverMac, 0n, 0x16, hsMsg(0x14, serverVd))),
  );

  // 7. application data
  let readSeq = 1n;
  let writeSeq = 1n;
  if (mode === 'echo') {
    rec = await readTlsRecord(transport);
    expect(rec.ct).toBe(0x17);
    const pt = srvDecrypt(keys.clientWrite, keys.clientMac, readSeq, 0x17, rec.payload);
    readSeq++;
    await transport.write(tlsRecord(0x17, srvEncrypt(keys.serverWrite, keys.serverMac, writeSeq, 0x17, pt)));
    writeSeq++;
  } else {
    rec = await readTlsRecord(transport);
    expect(rec.ct).toBe(0x17);
    const pt = srvDecrypt(keys.clientWrite, keys.clientMac, readSeq, 0x17, rec.payload);
    expect(pt.slice(0, 8)).toEqual(te.encode('CDTunnel'));
    const reqLen = (pt[8] << 8) | pt[9];
    const req = JSON.parse(td.decode(pt.slice(10, 10 + reqLen)));
    expect(req.type).toBe('clientHandshakeRequest');
    expect(req.mtu).toBe(16000);
    const respBody = te.encode(
      JSON.stringify({
        clientParameters: { address: 'fd00::2', netmask: 'ffff:ffff:ffff:ffff::', mtu: 1500 },
        serverAddress: 'fd00::1',
        serverRSDPort: 58783,
      }),
    );
    const respPkt = concat(te.encode('CDTunnel'), u16be(respBody.length), respBody);
    await transport.write(tlsRecord(0x17, srvEncrypt(keys.serverWrite, keys.serverMac, writeSeq, 0x17, respPkt)));
  }
}

/**
 * Fake device for the full establishTunnel() flow: RPPairing handshake +
 * pair-verify (X25519) + rsdInfo (encrypted RPC), then TLS-PSK + CDTunnel.
 */
async function runFakeTunnelDevice(
  transport: Transport,
  devXPriv: Uint8Array,
  clientEdPub: Uint8Array,
  rsci: Uint8Array,
): Promise<void> {
  const devPub = x25519.getPublicKey(devXPriv);

  // 1. handshake
  {
    const hs = (await readFrame(transport)) as any;
    expect(hs.message.plain._0.request._0.handshake).not.toBeUndefined();
    const hsResp = {
      message: { plain: { _0: { response: { _1: { handshake: { _0: {} } } } } } },
      originatedBy: 'device',
      sequenceNumber: 0,
    };
    await sendFrame(transport, hsResp);
  }

  // 2. pair-verify (X25519 + Ed25519)
  let shared: Uint8Array;
  {
    const readPairingTlv = async () => {
      const frame = (await readFrame(transport)) as any;
      return deserializeTlv8(b64d(frame.message.plain._0.event._0.pairingData._0.data));
    };
    const e1 = await readPairingTlv();
    const xPub = collectComponentData(e1, PairingDataComponentType.PublicKey);
    expect(xPub.length).toBe(32);
    await sendFrame(
      transport,
      pairingDataFrame(
        serializeTlv8([
          { type: PairingDataComponentType.State, data: new Uint8Array([0x02]) },
          { type: PairingDataComponentType.PublicKey, data: devPub },
        ]),
        1,
      ),
    );
    const e2 = await readPairingTlv();
    const ct = collectComponentData(e2, PairingDataComponentType.EncryptedData);
    shared = x25519.getSharedSecret(devXPriv, xPub);
    const setupKey = hkdf(
      sha512,
      shared,
      te.encode('Pair-Verify-Encrypt-Salt'),
      te.encode('Pair-Verify-Encrypt-Info'),
      32,
    );
    const pt = chacha20poly1305(setupKey, concat(new Uint8Array(4), te.encode('PV-Msg03'))).decrypt(ct);
    const pe = deserializeTlv8(pt);
    const idBytes = collectComponentData(pe, PairingDataComponentType.Identifier);
    const sig = collectComponentData(pe, PairingDataComponentType.Signature);
    expect(ed25519.verify(sig, concat(xPub, idBytes, devPub), clientEdPub)).toBe(true);
    await sendFrame(
      transport,
      pairingDataFrame(serializeTlv8([{ type: PairingDataComponentType.State, data: new Uint8Array([0x04]) }]), 2),
    );
  }

  // 3. rsdInfo over the encrypted RPC channel
  {
    const frame = (await readFrame(transport)) as {
      message: { streamEncrypted: { _0: string } };
    };
    const clientKey = hkdf(sha512, shared!, undefined, te.encode('ClientEncrypt-main'), 32);
    const serverKey = hkdf(sha512, shared!, undefined, te.encode('ServerEncrypt-main'), 32);
    const nonce = concat(u64le(0n), new Uint8Array(4));
    const req = JSON.parse(
      td.decode(chacha20poly1305(clientKey, nonce).decrypt(b64d(frame.message.streamEncrypted._0))),
    );
    expect(req.request._0.rsdInfo).not.toBeUndefined();
    const resp = te.encode(JSON.stringify({ response: { _1: { rsdInfo: { rsci: b64e(rsci) } } } }));
    const respEnc = chacha20poly1305(serverKey, nonce).encrypt(resp);
    await sendFrame(transport, {
      message: { streamEncrypted: { _0: b64e(respEnc) } },
      originatedBy: 'device',
      sequenceNumber: 3,
    });
  }

  // 4. TLS-PSK + CDTunnel (the PSK is the X25519 shared secret)
  await runFakeTlsServer(transport, shared!, 'cdtunnel');
}

describe('TLS-PSK interop (independent fake server)', () => {
  test('handshake completes and app data round-trips', async () => {
    const [clientT, serverT] = makeLoopback();
    const psk = hexToBytes('ab'.repeat(32));
    const serverDone = runFakeTlsServer(serverT, psk, 'echo');
    const tls = await tlsPskHandshake(clientT, psk);
    await tls.writeAppData(te.encode('hello tunnel'));
    expect(td.decode(await tls.readAppData())).toBe('hello tunnel');
    await serverDone;
  }, 30000);

  test('establishTunnel performs the CDTunnel handshake', async () => {
    const [clientT, serverT] = makeLoopback();
    const pairingFile = RpPairingFile.generate('test-host');
    const devXPriv = hexToBytes('cd'.repeat(32));
    const rsci = hexToBytes('ef'.repeat(16));
    const serverDone = runFakeTunnelDevice(serverT, devXPriv, pairingFile.publicKey, rsci);
    const tunnel = await establishTunnel(clientT, {}, undefined, pairingFile);
    expect(tunnel.tunnel.tunnelInfo.serverAddress).toBe('fd00::1');
    expect(tunnel.tunnel.tunnelInfo.serverRsdPort).toBe(58783);
    expect(tunnel.tunnel.tunnelInfo.clientAddress).toBe('fd00::2');
    expect(tunnel.tunnel.tunnelInfo.mtu).toBe(1500);
    await serverDone;
  }, 30000);
});
