/**
 * Minimal TLS 1.0–1.2 (RFC 2246 / RFC 5246) client for the lockdownd
 * `StartSession` upgrade.
 *
 * Why this exists: after `StartSession` returns `EnableSessionSSL`, every
 * further lockdownd request (e.g. `StartService` for AFC /
 * `installation_proxy`) must travel over TLS on the same connection. The
 * original SideImpactor did this with an OpenSSL-WASM build; here it is a
 * dependency-free TypeScript implementation that runs in the browser.
 *
 * Design notes (mirroring libimobiledevice's `idevice_connection_enable_ssl`
 * and jkcoxson/idevice's rustls-based `start_session`):
 * - Offers TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` (`0xC014`) /
 *   `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` (`0xC013`) first — this is what real
 *   devices negotiate (confirmed by a real connection log showing
 *   `ECDHE-RSA-AES256-SHA`), then falls back to the RSA key-exchange suites
 *   `TLS_RSA_WITH_AES_128_CBC_SHA` (`0x002F`) /
 *   `TLS_RSA_WITH_AES_256_CBC_SHA` (`0x0035`) for old (iOS < 10) devices that
 *   only speak TLS 1.0.
 * - ECDHE uses secp256r1 (`@noble/curves`); TLS 1.2 uses the SHA-256 PRF and
 *   explicit per-record CBC IVs (RFC 5246).
 * - The server (device) certificate is NOT verified, exactly like
 *   libimobiledevice (`SSL_set_verify(ssl, 0, …)`) and idevice
 *   (`NoServerNameVerification`); its RSA public key is only used for the
 *   RSA `ClientKeyExchange` encryption, and the ECDHE `ServerKeyExchange`
 *   signature is not checked.
 * - The pairing-file client certificate (HostCertificate) is sent only when
 *   the server asks for it via `CertificateRequest` (then a
 *   `CertificateVerify` signature follows): TLS 1.0 style (raw MD5+SHA-1,
 *   u16-prefixed, matching OpenSSL's de-facto wire format) or TLS 1.2 style
 *   (`rsa_pkcs1_sha256`, RFC 5246 `digitally-signed`), depending on the
 *   negotiated version.
 * - SNI `Device` is sent (like idevice); no ALPN; no session resumption.
 * - All RSA math is plain `bigint` modular exponentiation; hashes/AES/ECDH
 *   come from `@noble/*`; randomness from `crypto.getRandomValues`.
 *
 * What this does NOT do: TLS 1.3, GCM/ChaCha20 suites, (EC)DSA client certs,
 * session resumption, renegotiation, server certificate validation.
 */

import { sha1, md5 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { CHash } from '@noble/hashes/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { cbc } from '@noble/ciphers/aes.js';
import { p256 } from '@noble/curves/nist.js';
import type { Transport } from './usbmuxd.js';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class TlsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TlsError';
  }
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u16be(v: number): Uint8Array {
  return Uint8Array.of((v >>> 8) & 0xff, v & 0xff);
}

function u24be(v: number): Uint8Array {
  return Uint8Array.of((v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
}

function u64be(v: bigint): Uint8Array {
  let x = v;
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function readU16(b: Uint8Array, off: number): number {
  return (b[off] << 8) | b[off + 1];
}

function readU24(b: Uint8Array, off: number): number {
  return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2];
}

function constTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];  return diff === 0;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Random bytes with no zero octets (for PKCS#1 v1.5 type-2 padding). */
function randomNonZeroBytes(n: number): Uint8Array {
  const out = randomBytes(n);
  for (let i = 0; i < n; i++) {
    while (out[i] === 0) out[i] = randomBytes(1)[0];
  }
  return out;
}

function asciiBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new TlsError('odd-length hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Base64 / PEM
// ---------------------------------------------------------------------------

const B64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Decode(s: string): Uint8Array {
  const clean = s.replace(/[^A-Za-z0-9+/=]/g, '');
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    if (ch === '=') break;
    const v = B64_ALPHABET.indexOf(ch);
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export interface PemBlock {
  label: string;
  der: Uint8Array;
}

/**
 * Parses one PEM block; if the input is not PEM-armored it is treated as raw
 * DER with an empty label.
 */
export function pemToDer(input: Uint8Array): PemBlock {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch {
    return { label: '', der: input.slice() };
  }
  const m = text.match(
    /-----BEGIN ([A-Za-z0-9 ]+)-----\s*([\s\S]*?)\s*-----END \1-----/,
  );
  if (!m) return { label: '', der: input.slice() };
  return { label: m[1].trim(), der: base64Decode(m[2]) };
}

// ---------------------------------------------------------------------------
// Minimal DER reader
// ---------------------------------------------------------------------------

interface Tlv {
  tag: number;
  content: Uint8Array;
}

class DerCursor {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}

  get done(): boolean {
    return this.pos >= this.bytes.length;
  }

  readTlv(): Tlv {
    const b = this.bytes;
    if (this.pos >= b.length) throw new TlsError('DER: unexpected end of data');
    const tag = b[this.pos++];
    if (this.pos >= b.length) throw new TlsError('DER: truncated length');
    let len = b[this.pos++];
    if (len & 0x80) {
      const nBytes = len & 0x7f;
      if (nBytes === 0 || nBytes > 4)
        throw new TlsError('DER: unsupported length encoding');
      len = 0;
      for (let i = 0; i < nBytes; i++) {
        if (this.pos >= b.length) throw new TlsError('DER: truncated length');
        len = (len << 8) | b[this.pos++];
      }
    }
    if (this.pos + len > b.length)
      throw new TlsError('DER: content overruns buffer');
    const content = b.subarray(this.pos, this.pos + len);
    this.pos += len;
    return { tag, content };
  }
}

/** Reads the single top-level TLV and requires `tag`. */
function readTopLevel(der: Uint8Array, tag: number, what: string): Uint8Array {
  const cur = new DerCursor(der);
  const tlv = cur.readTlv();
  if (tlv.tag !== tag)
    throw new TlsError(
      `DER: expected ${what} (tag 0x${tag.toString(16)}), got 0x${tlv.tag.toString(16)}`,
    );
  return tlv.content;
}

function readSequenceChildren(content: Uint8Array): Tlv[] {
  const cur = new DerCursor(content);
  const out: Tlv[] = [];
  while (!cur.done) out.push(cur.readTlv());
  return out;
}

function tlvIntegerToBigint(tlv: Tlv): bigint {
  let v = 0n;
  for (const byte of tlv.content) v = (v << 8n) | BigInt(byte);
  return v;
}

function bytesToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

/** Byte length of the RSA modulus (== RSAES block size k). */
function rsaBlockLen(n: bigint): number {
  return Math.ceil(n.toString(2).length / 8);
}

function bigintToBytes(v: bigint, len: number): Uint8Array {
  if (v < 0n) throw new TlsError('negative bigint');
  const out = new Uint8Array(len);
  let x = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new TlsError('bigint does not fit in target length');
  return out;
}

// ---------------------------------------------------------------------------
// RSA key parsing
// ---------------------------------------------------------------------------

export interface RsaPublicKey {
  n: bigint;
  e: bigint;
}

export interface RsaPrivateKey {
  n: bigint;
  d: bigint;
}

const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

function oidToDotted(content: Uint8Array): string {
  if (content.length === 0) return '';
  const arcs = [Math.floor(content[0] / 40), content[0] % 40];
  let v = 0;
  for (let i = 1; i < content.length; i++) {
    v = (v << 7) | (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) {
      arcs.push(v);
      v = 0;
    }
  }
  return arcs.join('.');
}

function parseRsaPublicKeyDer(der: Uint8Array): RsaPublicKey {
  const seq = readSequenceChildren(
    readTopLevel(der, 0x30, 'RSAPublicKey SEQUENCE'),
  );
  if (seq.length < 2) throw new TlsError('RSAPublicKey: expected n and e');
  return { n: tlvIntegerToBigint(seq[0]), e: tlvIntegerToBigint(seq[1]) };
}

/**
 * Extracts the RSA public key from a DER X.509 certificate by locating the
 * `subjectPublicKeyInfo` whose algorithm is rsaEncryption. The certificate
 * itself is not validated (matches libimobiledevice behavior).
 */
export function parseRsaPublicKeyFromCertificate(
  certDer: Uint8Array,
): RsaPublicKey {
  const certChildren = readSequenceChildren(
    readTopLevel(certDer, 0x30, 'Certificate SEQUENCE'),
  );
  if (certChildren.length < 1) throw new TlsError('Certificate: empty');
  // certChildren[0] is the tbsCertificate SEQUENCE; its *content* holds the
  // TBSCertificate fields (starting with [0] EXPLICIT version on v3 certs).
  if (certChildren[0].tag !== 0x30)
    throw new TlsError('Certificate: tbsCertificate is not a SEQUENCE');
  const tbsChildren = readSequenceChildren(certChildren[0].content);
  for (const child of tbsChildren) {
    if (child.tag !== 0x30) continue;
    const spki = readSequenceChildren(child.content);
    if (spki.length < 2 || spki[0].tag !== 0x30 || spki[1].tag !== 0x03)
      continue;
    const alg = readSequenceChildren(spki[0].content);
    if (alg.length < 1 || alg[0].tag !== 0x06) continue;
    if (oidToDotted(alg[0].content) !== OID_RSA_ENCRYPTION) continue;
    const bitString = spki[1].content;
    if (bitString.length < 2 || bitString[0] !== 0)
      throw new TlsError('subjectPublicKey: expected 0 unused bits');
    return parseRsaPublicKeyDer(bitString.subarray(1));
  }
  throw new TlsError('Certificate: no rsaEncryption subjectPublicKeyInfo found');
}

function parsePkcs1PrivateKey(der: Uint8Array): RsaPrivateKey {
  const seq = readSequenceChildren(
    readTopLevel(der, 0x30, 'RSAPrivateKey SEQUENCE'),
  );
  if (seq.length < 4)
    throw new TlsError('RSAPrivateKey: expected at least version/n/e/d');
  return { n: tlvIntegerToBigint(seq[1]), d: tlvIntegerToBigint(seq[3]) };
}

/**
 * Parses an RSA private key from PEM (`PRIVATE KEY` / PKCS#8 or
 * `RSA PRIVATE KEY` / PKCS#1) or raw DER. Returns n and d.
 */
export function parseRsaPrivateKey(input: Uint8Array): RsaPrivateKey {
  const { label, der } = pemToDer(input);
  if (label === 'RSA PRIVATE KEY') return parsePkcs1PrivateKey(der);
  // Try PKCS#8; fall back to PKCS#1 for unlabeled DER.
  try {
    const seq = readSequenceChildren(readTopLevel(der, 0x30, 'PrivateKeyInfo'));
    if (seq.length >= 3 && seq[0].tag === 0x02 && seq[2].tag === 0x04) {
      return parsePkcs1PrivateKey(seq[2].content);
    }
  } catch {
    /* fall through */
  }
  return parsePkcs1PrivateKey(der);
}

// ---------------------------------------------------------------------------
// RSA primitives (bigint)
// ---------------------------------------------------------------------------

/** Square-and-multiply modular exponentiation. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod <= 0n) throw new TlsError('modPow: bad modulus');
  if (exp < 0n) throw new TlsError('modPow: negative exponent');
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** RSAES-PKCS1-v1_5 encryption (block type 2), for ClientKeyExchange. */
export function rsaPkcs1v15Encrypt(
  pub: RsaPublicKey,
  message: Uint8Array,
): Uint8Array {
  const k = rsaBlockLen(pub.n);
  if (message.length > k - 11)
    throw new TlsError('RSA encrypt: message too long');
  const ps = randomNonZeroBytes(k - message.length - 3);
  const em = concat(Uint8Array.of(0x00, 0x02), ps, Uint8Array.of(0x00), message);
  return bigintToBytes(modPow(bytesToBigint(em), pub.e, pub.n), k);
}

/**
 * RSASSA-PKCS1-v1_5 signature with block type 1 over a raw digest (no
 * DigestInfo), as required by the TLS 1.0 `CertificateVerify` message
 * (MD5+SHA1 of the handshake transcript).
 */
export function rsaPkcs1v15SignRaw(
  priv: RsaPrivateKey,
  digest: Uint8Array,
): Uint8Array {
  const k = rsaBlockLen(priv.n);
  if (digest.length > k - 11) throw new TlsError('RSA sign: digest too long');
  const ps = new Uint8Array(k - digest.length - 3).fill(0xff);
  const em = concat(Uint8Array.of(0x00, 0x01), ps, Uint8Array.of(0x00), digest);
  return bigintToBytes(modPow(bytesToBigint(em), priv.d, priv.n), k);
}

// ---------------------------------------------------------------------------
// TLS 1.0 PRF
// ---------------------------------------------------------------------------

function pHash(
  hash: CHash,
  secret: Uint8Array,
  seed: Uint8Array,
  outLen: number,
): Uint8Array {
  const out = new Uint8Array(outLen);
  let a = seed; // A(0)
  let pos = 0;
  while (pos < outLen) {
    a = hmac(hash, secret, a); // A(i) = HMAC(secret, A(i-1))
    const chunk = hmac(hash, secret, concat(a, seed));
    const n = Math.min(chunk.length, outLen - pos);
    out.set(chunk.subarray(0, n), pos);
    pos += n;
  }
  return out;
}

/** TLS 1.2 PRF = P_SHA-256 (RFC 5246 §5). */
export function tls12Prf(
  secret: Uint8Array,
  label: string,
  seed: Uint8Array,
  outLen: number,
): Uint8Array {
  return pHash(sha256, secret, concat(asciiBytes(label), seed), outLen);
}

/** SHA-256 of the handshake transcript (TLS 1.2 Finished / CertificateVerify). */
export function handshakeHash12(transcript: Uint8Array): Uint8Array {
  return sha256(transcript);
}

/** DigestInfo prefix for SHA-256 (RFC 3447), used by PKCS#1 v1.5 signatures. */
const SHA256_DIGEST_INFO_PREFIX = hexToBytes(
  '3031300d060960864801650304020105000420',
);

/**
 * RSA PKCS#1 v1.5 signature over a SHA-256 digest (with DigestInfo), as used
 * by TLS 1.2 `CertificateVerify` with `rsa_pkcs1_sha256`.
 */
export function rsaPkcs1v15SignSha256(
  priv: RsaPrivateKey,
  hash: Uint8Array,
): Uint8Array {
  if (hash.length !== 32) throw new TlsError('expected a SHA-256 digest');
  return rsaPkcs1v15SignRaw(priv, concat(SHA256_DIGEST_INFO_PREFIX, hash));
}

/** TLS 1.0 PRF = P_MD5(S1, …) XOR P_SHA-1(S2, …) (RFC 2246 §5). */
export function tls10Prf(
  secret: Uint8Array,
  label: string,
  seed: Uint8Array,
  outLen: number,
): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const labelAndSeed = concat(labelBytes, seed);
  const half = Math.ceil(secret.length / 2);
  const s1 = secret.subarray(0, half);
  const s2 = secret.subarray(secret.length - half);
  const p1 = pHash(md5, s1, labelAndSeed, outLen);
  const p2 = pHash(sha1, s2, labelAndSeed, outLen);
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) out[i] = p1[i] ^ p2[i];
  return out;
}

/** MD5(handshake) || SHA1(handshake), used by Finished/CertificateVerify. */
export function handshakeHash(transcript: Uint8Array): Uint8Array {
  return concat(md5(transcript), sha1(transcript));
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

const VERSION_TLS10 = 0x0301;
const VERSION_TLS12 = 0x0303;

/**
 * Offered cipher suites, in preference order: ECDHE-RSA with AES-CBC-SHA
 * first (what real devices negotiate — `ECDHE-RSA-AES256-SHA` was observed
 * on a live connection), then RSA key exchange for old (iOS < 10) devices
 * that only speak TLS 1.0.
 */
const CIPHER_SUITES = [0xc014, 0xc013, 0x002f, 0x0035];
const CIPHER_KEY_LEN: Record<number, number> = {
  0xc014: 32,
  0xc013: 16,
  0x002f: 16,
  0x0035: 32,
};
/** Cipher suites using ECDHE key exchange (need a ServerKeyExchange). */
const ECDHE_SUITES: ReadonlySet<number> = new Set([0xc014, 0xc013]);

/** secp256r1 (NIST P-256) as a TLS NamedCurve id. */
const NAMED_CURVE_SECP256R1 = 23;
/** `rsa_pkcs1_sha256` signature scheme (TLS 1.2 CertificateVerify). */
const SIGALG_RSA_PKCS1_SHA256 = 0x0401;

const REC_CHANGE_CIPHER_SPEC = 20;
const REC_ALERT = 21;
const REC_HANDSHAKE = 22;
const REC_APPLICATION_DATA = 23;

const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_CERTIFICATE = 11;
const HS_SERVER_KEY_EXCHANGE = 12;
const HS_CERTIFICATE_REQUEST = 13;
const HS_SERVER_HELLO_DONE = 14;
const HS_CERTIFICATE_VERIFY = 15;
const HS_CLIENT_KEY_EXCHANGE = 16;
const HS_FINISHED = 20;

const ALERT_DESCRIPTIONS: Record<number, string> = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  22: 'record_overflow',
  40: 'handshake_failure',
  41: 'no_certificate',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  90: 'user_canceled',
  100: 'no_renegotiation',
};

export interface TlsConnectOptions {
  /**
   * DER (or PEM) client certificate, sent only if the server requests client
   * authentication. For lockdownd this is the pairing file's HostCertificate.
   */
  clientCertificateDer?: Uint8Array;
  /** Private key matching `clientCertificateDer`. */
  clientPrivateKey?: RsaPrivateKey;
  /**
   * Maximum TLS version to offer in the ClientHello: `0x0301` (TLS 1.0) or
   * `0x0303` (TLS 1.2, the default). Force `0x0301` when talking to a peer
   * with broken version negotiation that rejects a TLS 1.2 ClientHello.
   */
  maxTlsVersion?: number;
  /** Handshake timeout; default 60s. `0` disables. */
  handshakeTimeoutMs?: number;
  onLog?: (message: string) => void;
}

interface ServerHello {
  version: number;
  random: Uint8Array;
  cipherSuite: number;
}

function hsMessage(type: number, body: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(type), u24be(body.length), body);
}

function tlsRecord(
  type: number,
  payload: Uint8Array,
  version: number = VERSION_TLS10,
): Uint8Array {
  return concat(
    Uint8Array.of(type),
    u16be(version),
    u16be(payload.length),
    payload,
  );
}

function alertError(payload: Uint8Array): TlsError {
  if (payload.length < 2) return new TlsError('TLS alert (truncated)');
  const level = payload[0] === 2 ? 'fatal' : 'warning';
  const desc = ALERT_DESCRIPTIONS[payload[1]] ?? `unknown(${payload[1]})`;
  return new TlsError(`TLS ${level} alert: ${desc}`);
}

// ---------------------------------------------------------------------------
// Handshake driver
// ---------------------------------------------------------------------------

class HandshakeDriver {
  private transcript: Uint8Array[] = [];
  private hsBuf: Uint8Array = new Uint8Array(0);
  private dead = false;
  private handshakeDone = false;

  // Crypto state (filled after ServerHello).
  private masterSecret: Uint8Array | null = null;
  private negotiatedVersion: number = VERSION_TLS10;
  private offeredVersion: number = VERSION_TLS12;
  private isTls12: boolean = false;
  private clientWriteMacKey: Uint8Array = new Uint8Array(0);
  private serverWriteMacKey: Uint8Array = new Uint8Array(0);
  private clientWriteKey: Uint8Array = new Uint8Array(0);
  private serverWriteKey: Uint8Array = new Uint8Array(0);
  private clientWriteIv: Uint8Array = new Uint8Array(0);
  private serverWriteIv: Uint8Array = new Uint8Array(0);

  private writeSeq = 0n;
  private readSeq = 0n;
  private writeEncrypted = false;
  private readEncrypted = false;

  constructor(
    private readonly transport: Transport,
    private readonly opts: TlsConnectOptions,
  ) {}

  log(msg: string): void {
    this.opts.onLog?.(msg);
  }

  private transcriptBytes(): Uint8Array {
    return concat(...this.transcript);
  }

  private async withHandshakeTimeout<T>(
    promise: Promise<T>,
    what: string,
  ): Promise<T> {
    const ms = this.opts.handshakeTimeoutMs ?? 60000;
    if (!ms) return promise;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timer = setTimeout(
            () => reject(new TlsError(`TLS handshake timed out (${what})`)),
            ms,
          );
        }),
      ]);
    } catch (e) {
      this.dead = true;
      try {
        this.transport.close();
      } catch {
        /* best effort */
      }
      throw e;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async readRecord(): Promise<{ type: number; payload: Uint8Array }> {
    if (this.dead) throw new TlsError('TLS connection is dead');
    const read5 = this.transport.read(5);
    const hdr = this.handshakeDone
      ? await read5
      : await this.withHandshakeTimeout(read5, 'record header');
    const type = hdr[0];
    const len = readU16(hdr, 3);
    if (len > 18432) throw new TlsError(`TLS record too large: ${len}`);
    const readPayload = this.transport.read(len);
    const payload = this.handshakeDone
      ? await readPayload
      : await this.withHandshakeTimeout(readPayload, 'record payload');
    return { type, payload };
  }

  private async writeRaw(bytes: Uint8Array): Promise<void> {
    if (this.dead) throw new TlsError('TLS connection is dead');
    await this.transport.write(bytes);
  }

  /** Sends one handshake message; plaintext before CCS. */
  private async sendHandshake(type: number, body: Uint8Array): Promise<void> {
    const msg = hsMessage(type, body);
    this.transcript.push(msg);
    await this.writeRaw(tlsRecord(REC_HANDSHAKE, msg, this.negotiatedVersion));
  }

  /** Reads handshake records until one full handshake message is available. */
  private async nextHandshakeMessage(): Promise<{
    type: number;
    body: Uint8Array;
  }> {
    for (;;) {
      if (this.hsBuf.length >= 4) {
        const len = readU24(this.hsBuf, 1);
        if (len > 1 << 20)
          throw new TlsError('handshake message too large');
        if (this.hsBuf.length >= 4 + len) {
          const type = this.hsBuf[0];
          const body = this.hsBuf.slice(4, 4 + len);
          this.hsBuf = this.hsBuf.slice(4 + len);
          return { type, body };
        }
      }
      const rec = await this.readRecord();
      if (rec.type === REC_ALERT) throw alertError(rec.payload);
      if (rec.type !== REC_HANDSHAKE)
        throw new TlsError(
          `unexpected TLS record type ${rec.type} during handshake`,
        );
      this.hsBuf = concat(this.hsBuf, rec.payload);
    }
  }

  private parseServerHello(body: Uint8Array): ServerHello {
    if (body.length < 38) throw new TlsError('ServerHello too short');
    const version = readU16(body, 0);
    const random = body.slice(2, 34);
    const sessionIdLen = body[34];
    const off = 35 + sessionIdLen;
    if (body.length < off + 3) throw new TlsError('ServerHello truncated');
    const cipherSuite = readU16(body, off);
    const compression = body[off + 2];
    if (compression !== 0)
      throw new TlsError(`unsupported compression method ${compression}`);
    return { version, random, cipherSuite };
  }

  private parseCertificateList(body: Uint8Array): Uint8Array[] {
    if (body.length < 3) throw new TlsError('Certificate message empty');
    const listLen = readU24(body, 0);
    let off = 3;
    const certs: Uint8Array[] = [];
    while (off < 3 + listLen) {
      if (off + 3 > body.length)
        throw new TlsError('Certificate list truncated');
      const certLen = readU24(body, off);
      off += 3;
      if (off + certLen > body.length)
        throw new TlsError('Certificate entry truncated');
      certs.push(body.slice(off, off + certLen));
      off += certLen;
    }
    return certs;
  }

  /**
   * Extracts the server's ephemeral ECDH public key from a
   * `ServerKeyExchange` (ECDHE `ServerECDHParams`, RFC 4492 §5.4). The
   * trailing signature is intentionally not verified — the device
   * certificate is never validated (mirrors libimobiledevice/idevice).
   */
  private parseServerEcdhePoint(body: Uint8Array): Uint8Array {
    if (body.length < 4) throw new TlsError('ServerKeyExchange too short');
    const curveType = body[0];
    const namedCurve = readU16(body, 1);
    if (curveType !== 3 || namedCurve !== NAMED_CURVE_SECP256R1) {
      throw new TlsError(
        `unsupported ECDHE curve (type=${curveType}, curve=0x${namedCurve.toString(16)})`,
      );
    }
    const pointLen = body[3];
    if (4 + pointLen > body.length)
      throw new TlsError('ServerKeyExchange point truncated');
    const point = body.slice(4, 4 + pointLen);
    if (point.length !== 65 || point[0] !== 0x04)
      throw new TlsError('expected an uncompressed secp256r1 point');
    return point;
  }

  // -- record-layer crypto --

  private encryptRecord(type: number, plaintext: Uint8Array): Uint8Array {
    const mac = hmac(
      sha1,
      this.clientWriteMacKey,
      concat(
        u64be(this.writeSeq),
        Uint8Array.of(type),
        u16be(this.negotiatedVersion),
        u16be(plaintext.length),
        plaintext,
      ),
    );
    const contentLen = plaintext.length + mac.length;
    const padLen = (16 - ((contentLen + 1) % 16)) % 16;
    const padding = new Uint8Array(padLen + 1).fill(padLen);
    const block = concat(plaintext, mac, padding);
    // NOTE: noble's cbc() applies PKCS#7 padding by default; the block above
    // already carries TLS padding, so it must be disabled here.
    if (this.isTls12) {
      // TLS 1.2 CBC uses a fresh explicit IV per record (RFC 5246 §6.2.3.2).
      const iv = randomBytes(16);
      const ct = cbc(this.clientWriteKey, iv, { disablePadding: true }).encrypt(
        block,
      );
      this.writeSeq += 1n;
      return tlsRecord(type, concat(iv, ct), this.negotiatedVersion);
    }
    const ct = cbc(this.clientWriteKey, this.clientWriteIv, {
      disablePadding: true,
    }).encrypt(block);
    this.clientWriteIv = ct.slice(ct.length - 16);
    this.writeSeq += 1n;
    return tlsRecord(type, ct, this.negotiatedVersion);
  }

  private decryptRecord(payload: Uint8Array, type: number): Uint8Array {
    let iv: Uint8Array;
    let ct: Uint8Array;
    if (this.isTls12) {
      if (payload.length < 16 || (payload.length - 16) % 16 !== 0)
        throw new TlsError('bad encrypted record length');
      iv = payload.slice(0, 16);
      ct = payload.slice(16);
    } else {
      if (payload.length === 0 || payload.length % 16 !== 0)
        throw new TlsError('bad encrypted record length');
      iv = this.serverWriteIv;
      ct = payload;
      this.serverWriteIv = payload.slice(payload.length - 16);
    }
    // TLS padding is validated manually below; disable noble's PKCS#7 handling.
    const pt = cbc(this.serverWriteKey, iv, {
      disablePadding: true,
    }).decrypt(ct);
    const padLen = pt[pt.length - 1];
    if (padLen > 16 || padLen + 1 > pt.length)
      throw new TlsError('bad record padding');
    for (let i = 0; i <= padLen; i++) {
      if (pt[pt.length - 1 - i] !== padLen)
        throw new TlsError('bad record padding');
    }
    const contentLen = pt.length - padLen - 1;
    if (contentLen < 20) throw new TlsError('record too short for MAC');
    const data = pt.slice(0, contentLen - 20);
    const mac = pt.slice(contentLen - 20, contentLen);
    const expected = hmac(
      sha1,
      this.serverWriteMacKey,
      concat(
        u64be(this.readSeq),
        Uint8Array.of(type),
        u16be(this.negotiatedVersion),
        u16be(data.length),
        data,
      ),
    );
    if (!constTimeEqual(mac, expected)) throw new TlsError('bad record MAC');
    this.readSeq += 1n;
    return data;
  }

  // -- public record-layer API used by TlsTransport --

  /** Encrypts and sends application data (fragmented to 2^14). */
  async writeAppData(data: Uint8Array): Promise<void> {
    if (this.dead) throw new TlsError('TLS connection is dead');
    for (let off = 0; off < data.length; off += 16384) {
      const chunk = data.subarray(off, Math.min(off + 16384, data.length));
      await this.writeRaw(this.encryptRecord(REC_APPLICATION_DATA, chunk));
    }
  }

  /** Reads and decrypts one application-data record payload. */
  async readAppData(): Promise<Uint8Array> {
    const rec = await this.readRecord();
    if (rec.type === REC_ALERT) {
      // Alerts after ChangeCipherSpec are encrypted like any other record.
      const payload = this.decryptRecord(rec.payload, rec.type);
      if (payload.length >= 2 && payload[1] === 0) {
        this.dead = true;
        throw new TlsError('TLS connection closed by peer (close_notify)');
      }
      throw alertError(payload);
    }
    if (rec.type !== REC_APPLICATION_DATA)
      throw new TlsError(`unexpected record type ${rec.type} after handshake`);
    return this.decryptRecord(rec.payload, rec.type);
  }

  /** Best-effort close_notify (fire-and-forget from `close()`). */
  sendCloseNotify(): void {
    if (this.dead || !this.writeEncrypted) return;
    const rec = this.encryptRecord(REC_ALERT, Uint8Array.of(1, 0));
    void this.transport.write(rec).catch(() => undefined);
  }

  /** Closes the underlying transport. */
  closeTransport(): void {
    this.dead = true;
    try {
      this.transport.close();
    } catch {
      /* best effort */
    }
  }

  // -- the handshake --

  async runHandshake(): Promise<TlsTransport> {
    // ---- ClientHello ----
    const offeredVersion = this.opts.maxTlsVersion ?? VERSION_TLS12;
    if (offeredVersion !== VERSION_TLS10 && offeredVersion !== VERSION_TLS12)
      throw new TlsError(
        `unsupported maxTlsVersion 0x${offeredVersion.toString(16)}`,
      );
    this.offeredVersion = offeredVersion;
    // The record-layer version of the ClientHello flight stays at TLS 1.0
    // for maximum compatibility (RFC 5246 §E.1); the offered version goes
    // inside the ClientHello body.
    this.negotiatedVersion = VERSION_TLS10;
    const clientRandom = randomBytes(32);
    const suites = concat(...CIPHER_SUITES.map(u16be));
    // Extensions: SNI "Device" (like idevice), supported groups,
    // point formats, signature algorithms, empty renegotiation_info.
    const sniHost = asciiBytes('Device');
    const extServerName = concat(
      u16be(0x0000),
      u16be(5 + sniHost.length),
      u16be(3 + sniHost.length),
      Uint8Array.of(0x00),
      u16be(sniHost.length),
      sniHost,
    );
    const extSupportedGroups = concat(
      u16be(0x000a),
      u16be(4),
      u16be(2),
      u16be(NAMED_CURVE_SECP256R1),
    );
    const extPointFormats = concat(
      u16be(0x000b),
      u16be(2),
      Uint8Array.of(0x01, 0x00), // uncompressed only
    );
    const extSigAlgs = concat(
      u16be(0x000d),
      u16be(6),
      u16be(4),
      u16be(SIGALG_RSA_PKCS1_SHA256),
      u16be(0x0201), // rsa_pkcs1_sha1
    );
    const extRenegotiationInfo = concat(
      u16be(0xff01),
      u16be(1),
      Uint8Array.of(0x00),
    );
    const extensions = concat(
      extServerName,
      extSupportedGroups,
      extPointFormats,
      extSigAlgs,
      extRenegotiationInfo,
    );
    const helloBody = offeredVersion === VERSION_TLS12
      ? concat(
          u16be(offeredVersion),
          clientRandom,
          Uint8Array.of(0x00), // session id length
          u16be(suites.length),
          suites,
          Uint8Array.of(0x01, 0x00), // compression methods: null
          u16be(extensions.length),
          extensions,
        )
      : concat(
          // TLS 1.0 offer: no extensions, mirroring the pre-1.2 client.
          u16be(offeredVersion),
          clientRandom,
          Uint8Array.of(0x00), // session id length
          u16be(suites.length),
          suites,
          Uint8Array.of(0x01, 0x00), // compression methods: null
        );
    this.log(
      `tls: sending ClientHello (TLS 1.${offeredVersion === VERSION_TLS12 ? '2' : '0'}, ECDHE-RSA/RSA, AES-CBC-SHA)`,
    );
    await this.sendHandshake(HS_CLIENT_HELLO, helloBody);

    // ---- Server flight ----
    let serverHello: ServerHello | null = null;
    let serverPublicKey: RsaPublicKey | null = null;
    let serverEcdhePoint: Uint8Array | null = null;
    let clientAuthRequested = false;

    for (;;) {
      const { type, body } = await this.nextHandshakeMessage();
      this.transcript.push(hsMessage(type, body));
      switch (type) {
        case HS_SERVER_HELLO: {
          serverHello = this.parseServerHello(body);
          if (
            serverHello.version !== VERSION_TLS10 &&
            serverHello.version !== VERSION_TLS12
          )
            throw new TlsError(
              `server negotiated unsupported TLS version 0x${serverHello.version.toString(16)}`,
            );
          if (!(serverHello.cipherSuite in CIPHER_KEY_LEN))
            throw new TlsError(
              `server chose unsupported cipher suite 0x${serverHello.cipherSuite.toString(16)}`,
            );
          this.negotiatedVersion = serverHello.version;
          this.isTls12 = serverHello.version === VERSION_TLS12;
          this.log(
            `tls: ServerHello (TLS 1.${this.isTls12 ? '2' : '0'}, cipher suite 0x${serverHello.cipherSuite.toString(16)})`,
          );
          break;
        }
        case HS_CERTIFICATE: {
          const certs = this.parseCertificateList(body);
          if (certs.length === 0)
            throw new TlsError('server sent an empty certificate list');
          serverPublicKey = parseRsaPublicKeyFromCertificate(certs[0]);
          this.log('tls: server certificate received (not verified, by design)');
          break;
        }
        case HS_SERVER_KEY_EXCHANGE: {
          if (!serverHello || !ECDHE_SUITES.has(serverHello.cipherSuite))
            throw new TlsError(
              'server sent ServerKeyExchange for a non-ECDHE suite',
            );
          serverEcdhePoint = this.parseServerEcdhePoint(body);
          this.log('tls: ServerKeyExchange (ECDHE secp256r1)');
          break;
        }
        case HS_CERTIFICATE_REQUEST:
          clientAuthRequested = true;
          this.log('tls: server requested a client certificate');
          break;
        case HS_SERVER_HELLO_DONE:
          if (body.length !== 0)
            throw new TlsError('ServerHelloDone must be empty');
          break;
        default:
          throw new TlsError(`unexpected handshake message ${type}`);
      }
      if (type === HS_SERVER_HELLO_DONE) break;
    }

    if (!serverHello) throw new TlsError('handshake failed: no ServerHello');
    if (!serverPublicKey)
      throw new TlsError('handshake failed: no server Certificate');
    const isEcdhe = ECDHE_SUITES.has(serverHello.cipherSuite);
    if (isEcdhe && !serverEcdhePoint)
      throw new TlsError('handshake failed: no ServerKeyExchange for ECDHE');

    // ---- Key derivation ----
    const prf = this.isTls12 ? tls12Prf : tls10Prf;
    const transcriptHash = (t: Uint8Array): Uint8Array =>
      this.isTls12 ? handshakeHash12(t) : handshakeHash(t);
    let premaster: Uint8Array;
    let ckexBody: Uint8Array;
    if (isEcdhe) {
      const ecdheSecret = p256.keygen().secretKey;
      const myPoint = p256.getPublicKey(ecdheSecret, false);
      const shared = p256.getSharedSecret(
        ecdheSecret,
        serverEcdhePoint!,
        false,
      );
      ecdheSecret.fill(0);
      // RFC 4492 §5.10: the premaster secret is the x-coordinate.
      premaster = shared.slice(1, 33);
      shared.fill(0);
      ckexBody = concat(Uint8Array.of(myPoint.length), myPoint);
    } else {
      // RFC 5246 §7.4.7.1: the premaster version is the version the client
      // offered in the ClientHello, NOT the negotiated version — the server
      // checks this and derives different keys on mismatch.
      premaster = concat(u16be(this.offeredVersion), randomBytes(46));
      const encrypted = rsaPkcs1v15Encrypt(serverPublicKey, premaster);
      ckexBody = concat(u16be(encrypted.length), encrypted);
    }
    this.masterSecret = prf(
      premaster,
      'master secret',
      concat(clientRandom, serverHello.random),
      48,
    );
    premaster.fill(0);
    const keyLen = CIPHER_KEY_LEN[serverHello.cipherSuite];
    const keyBlock = prf(
      this.masterSecret,
      'key expansion',
      concat(serverHello.random, clientRandom),
      2 * (20 + keyLen + 16),
    );
    let off = 0;
    const take = (n: number): Uint8Array => {
      const s = keyBlock.slice(off, off + n);
      off += n;
      return s;
    };
    this.clientWriteMacKey = take(20);
    this.serverWriteMacKey = take(20);
    this.clientWriteKey = take(keyLen);
    this.serverWriteKey = take(keyLen);
    if (this.isTls12) {
      // TLS 1.2 CBC uses explicit per-record IVs; the key-block IVs are unused.
      take(16);
      take(16);
    } else {
      this.clientWriteIv = take(16);
      this.serverWriteIv = take(16);
    }

    // ---- Client flight ----
    if (clientAuthRequested) {
      const { clientCertificateDer, clientPrivateKey } = this.opts;
      if (!clientCertificateDer || !clientPrivateKey)
        throw new TlsError(
          'server requested a client certificate but none was configured',
        );
      const { der: certDer } = pemToDer(clientCertificateDer);
      const certBody = concat(
        u24be(3 + certDer.length),
        u24be(certDer.length),
        certDer,
      );
      await this.sendHandshake(HS_CERTIFICATE, certBody);
      this.log('tls: client certificate sent');
    }

    await this.sendHandshake(HS_CLIENT_KEY_EXCHANGE, ckexBody);

    if (clientAuthRequested) {
      const priv = this.opts.clientPrivateKey;
      if (!priv) throw new TlsError('client private key missing');
      let verifyBody: Uint8Array;
      if (this.isTls12) {
        const sig = rsaPkcs1v15SignSha256(
          priv,
          handshakeHash12(this.transcriptBytes()),
        );
        verifyBody = concat(
          u16be(SIGALG_RSA_PKCS1_SHA256),
          u16be(sig.length),
          sig,
        );
      } else {
        const sig = rsaPkcs1v15SignRaw(
          priv,
          handshakeHash(this.transcriptBytes()),
        );
        // NOTE: RFC 2246 leaves the signature length implicit for TLS 1.0,
        // but OpenSSL (and every stack that interoperates with it, including
        // the device side) has always sent CertificateVerify with an explicit
        // u16 length prefix — see tls_construct_cert_verify /
        // tls_process_cert_verify in OpenSSL's statem_lib.c. Match that.
        verifyBody = concat(u16be(sig.length), sig);
      }
      await this.sendHandshake(HS_CERTIFICATE_VERIFY, verifyBody);
      this.log('tls: CertificateVerify sent');
    }

    // ChangeCipherSpec is not a handshake message and is not transcripted.
    await this.writeRaw(
      tlsRecord(
        REC_CHANGE_CIPHER_SPEC,
        Uint8Array.of(0x01),
        this.negotiatedVersion,
      ),
    );
    this.writeEncrypted = true;
    this.writeSeq = 0n;

    const clientVerify = prf(
      this.masterSecret,
      'client finished',
      transcriptHash(this.transcriptBytes()),
      12,
    );
    const finishedMsg = hsMessage(HS_FINISHED, clientVerify);
    this.transcript.push(finishedMsg);
    await this.writeRaw(this.encryptRecord(REC_HANDSHAKE, finishedMsg));
    this.log('tls: client Finished sent');

    // ---- Server Finished ----
    const ccs = await this.readRecord();
    if (ccs.type !== REC_CHANGE_CIPHER_SPEC || ccs.payload.length !== 1 || ccs.payload[0] !== 1)
      throw new TlsError('expected ChangeCipherSpec from server');
    this.readEncrypted = true;
    this.readSeq = 0n;

    const finRec = await this.readRecord();
    if (finRec.type === REC_ALERT) throw alertError(finRec.payload);
    if (finRec.type !== REC_HANDSHAKE)
      throw new TlsError(`expected Finished, got record type ${finRec.type}`);
    const finPlain = this.decryptRecord(finRec.payload, finRec.type);
    if (finPlain.length < 4) throw new TlsError('Finished message truncated');
    const finType = finPlain[0];
    const finLen = readU24(finPlain, 1);
    if (finType !== HS_FINISHED || finLen !== 12 || finPlain.length !== 16)
      throw new TlsError('malformed server Finished');
    const expected = prf(
      this.masterSecret,
      'server finished',
      transcriptHash(this.transcriptBytes()),
      12,
    );
    if (!constTimeEqual(finPlain.slice(4), expected))
      throw new TlsError('server Finished verify_data mismatch');

    this.handshakeDone = true;
    this.log('tls: handshake complete, session encrypted');
    return new TlsTransport(this);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Performs the TLS handshake over `transport` and returns an encrypted
 * {@link TlsTransport}. Negotiates TLS 1.2 with ECDHE-RSA when the server
 * supports it, falling back to TLS 1.0 with RSA key exchange. Closing the
 * returned transport closes the underlying transport.
 */
export async function tlsConnect(
  transport: Transport,
  opts: TlsConnectOptions = {},
): Promise<TlsTransport> {
  const driver = new HandshakeDriver(transport, opts);
  return driver.runHandshake();
}

/**
 * Encrypted byte transport produced by {@link tlsConnect}. `read(n)`
 * resolves with exactly `n` bytes (buffering decrypted records).
 */
export class TlsTransport implements Transport {
  private recvBuf: Uint8Array = new Uint8Array(0);
  private closed = false;

  /** @internal */
  constructor(private readonly driver: HandshakeDriver) {}

  async read(n: number): Promise<Uint8Array> {
    if (n < 0) throw new TlsError('read: negative length');
    if (n === 0) return new Uint8Array(0);
    while (this.recvBuf.length < n) {
      if (this.closed) throw new TlsError('TLS connection is closed');
      const chunk = await this.driver.readAppData();
      this.recvBuf = concat(this.recvBuf, chunk);
    }
    const out = this.recvBuf.slice(0, n);
    this.recvBuf = this.recvBuf.slice(n);
    return out;
  }

  async write(data: Uint8Array): Promise<void> {
    if (this.closed) throw new TlsError('TLS connection is closed');
    await this.driver.writeAppData(data);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.driver.sendCloseNotify();
    } catch {
      /* best effort */
    }
    this.driver.closeTransport();
  }
}
