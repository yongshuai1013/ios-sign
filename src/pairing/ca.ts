/**
 * CA 憑證產生模組。
 *
 * TypeScript 移植自 Rust `idevice`（jkcoxson/idevice）的 `src/ca.rs`
 *（`generate_certificates` / `make_cert`）。
 *
 * 對照 ca.rs 的關鍵欄位（以 x509-cert 0.2.5 `Profile::Root` 的實際行為為準，
 * 已逐項核對該版本 `builder.rs` / `ext/pkix.rs` / `ext/pkix/keyusage.rs` 原始碼）：
 *
 * - RSA-2048；簽章演算法 sha256WithRSAEncryption（OID 1.2.840.113549.1.1.11，參數 NULL）
 * - version v3（[0] explicit 包 INTEGER 2），serialNumber = INTEGER 1
 * - issuer：`Profile::Root` 的 `get_issuer()` 直接回傳 subject 的複本，
 *   因此 CA 憑證 issuer = 空 Name，裝置/主機憑證 issuer = CN=Device / CN=<hostId>
 * - validity：`CertificateBuilder::new` 會呼叫 `rfc5280_adjust_utc_time()`，
 *   2049-12-31T23:59:59Z（含）以前的日期改用 UTCTime 編碼，
 *   之後的日期用 GeneralizedTime。
 *   有效期長度沿用 ca.rs 的常數 `365 * 9 * 12 * 31 * 24 * 60 * 60` 秒
 *   （原始註解寫「約 9 年」，但算式實際約為 3348 年，此處照抄來源以求一致）
 * - extensions（依序；`Profile::Root` 不會產生 AuthorityKeyIdentifier）：
 *   1. SubjectKeyIdentifier（non-critical）= SHA-1(公鑰 BIT STRING 本體，
 *      即 RSAPublicKey DER，不含 tag/length/unused-bits 位元組）
 *   2. BasicConstraints（critical）：cA = TRUE，無 pathLenConstraint
 *   3. KeyUsage（critical）：keyCertSign + cRLSign（注意：不含 digitalSignature）
 * - 輸出 PEM 皆為 LF 換行、base64 每 64 字元一行（對應 ca.rs 的 LineEnding::LF）
 *
 * 配對流程中的實際用法（對應 `lockdown.rs` 的 `build_pair_request`）：
 * - `generateCertificates(devicePublicKeyPem)` 產生 hostCert（自簽 CA）、
 *   devCert（CN=Device，由 CA 簽發）與 CA 私鑰（PKCS#8 PEM）。
 * - Pair 請求送出 `DeviceCertificate` / `HostCertificate` / `RootCertificate`
 *  （Host 與 Root 為同一張自簽憑證）與 `RootPrivateKey`；
 *   配對成功後再把 `HostPrivateKey`（同一把私鑰）寫入配對檔。
 *
 * 全部 RSA 運算使用 WebCrypto（`crypto.subtle`），DER 手寫編碼，
 * 因此可在瀏覽器 / Node / Bun / Deno 執行，無需原生依賴。
 */

// ---------------------------------------------------------------------------
// 常數（演算法 OID 與有效期照抄 ca.rs / x509-cert 0.2.5）
// ---------------------------------------------------------------------------

/** sha256WithRSAEncryption */
const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
/** rsaEncryption */
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
/** commonName */
const OID_COMMON_NAME = '2.5.4.3';
/** basicConstraints */
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
/** keyUsage */
const OID_KEY_USAGE = '2.5.29.15';
/** subjectKeyIdentifier */
const OID_SUBJECT_KEY_ID = '2.5.29.14';

/**
 * 憑證有效期（秒）。照抄 ca.rs：
 * `365 * 9 * 12 * 31 * 24 * 60 * 60`（原始註解：約 9 年）。
 */
export const CERT_LIFETIME_SECS = 365 * 9 * 12 * 31 * 24 * 60 * 60;

/** RFC 5280 §4.1.2.5：此時間點（含）以前的日期用 UTCTime 編碼 */
const UTCTIME_MAX_SECS = 2534023007; // 2049-12-31T23:59:59Z

// ---------------------------------------------------------------------------
// DER 編碼器（TLV）
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

function encodeLength(len: number): Uint8Array {
  if (len < 128) return Uint8Array.of(len);
  const bytes: number[] = [];
  let v = len;
  while (v > 0) {
    bytes.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), encodeLength(content.length), content);
}

/** INTEGER（正整數：去除前導零，必要時補 0x00 避免被判為負數） */
function encodeIntegerBytes(raw: Uint8Array): Uint8Array {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0) i++;
  let v = raw.subarray(i);
  if (v.length > 0 && v[0] & 0x80) v = concat(Uint8Array.of(0), v);
  return tlv(0x02, v);
}

function encodeIntegerNum(n: number): Uint8Array {
  if (n === 0) return tlv(0x02, Uint8Array.of(0));
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return encodeIntegerBytes(Uint8Array.from(bytes));
}

function encodeOid(dotted: string): Uint8Array {
  const arcs = dotted.split('.').map(Number);
  const out: number[] = [40 * arcs[0] + arcs[1]];
  for (let i = 2; i < arcs.length; i++) {
    let v = arcs[i];
    const groups: number[] = [v % 128];
    v = Math.floor(v / 128);
    while (v > 0) {
      groups.unshift((v % 128) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(out));
}

const encodeNull = (): Uint8Array => tlv(0x05, new Uint8Array(0));
const encodeBoolean = (b: boolean): Uint8Array => tlv(0x01, Uint8Array.of(b ? 0xff : 0x00));
const encodeSequence = (...parts: Uint8Array[]): Uint8Array => tlv(0x30, concat(...parts));
const encodeSet = (...parts: Uint8Array[]): Uint8Array => tlv(0x31, concat(...parts));
const encodeUtf8String = (s: string): Uint8Array => tlv(0x0c, new TextEncoder().encode(s));
const encodeOctetString = (d: Uint8Array): Uint8Array => tlv(0x04, d);
const encodeBitString = (data: Uint8Array, unusedBits = 0): Uint8Array =>
  tlv(0x03, concat(Uint8Array.of(unusedBits), data));
/** context-specific constructed [n]（explicit 包裝） */
const encodeExplicit = (n: number, inner: Uint8Array): Uint8Array => tlv(0xa0 | n, inner);

/** UTCTime，格式 YYMMDDHHMMSSZ */
function encodeUtcTime(unixSecs: number): Uint8Array {
  const d = new Date(unixSecs * 1000);
  const p = (v: number): string => String(v).padStart(2, '0');
  const s =
    `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, new TextEncoder().encode(s));
}

/** GeneralizedTime，格式 YYYYMMDDHHMMSSZ */
function encodeGeneralizedTime(unixSecs: number): Uint8Array {
  const d = new Date(unixSecs * 1000);
  const p = (v: number, w: number): string => String(v).padStart(w, '0');
  const s =
    `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1, 2)}${p(d.getUTCDate(), 2)}` +
    `${p(d.getUTCHours(), 2)}${p(d.getUTCMinutes(), 2)}${p(d.getUTCSeconds(), 2)}Z`;
  return tlv(0x18, new TextEncoder().encode(s));
}

/**
 * 對應 x509-cert 的 `Time::rfc5280_adjust_utc_time()`：
 * 2049 年底前用 UTCTime，之後用 GeneralizedTime。
 */
function encodeTime(unixSecs: number): Uint8Array {
  return unixSecs <= UTCTIME_MAX_SECS ? encodeUtcTime(unixSecs) : encodeGeneralizedTime(unixSecs);
}

export interface TlvNode {
  tag: number;
  content: Uint8Array;
  /** 含 tag + length 的完整 TLV 位元組（簽章驗證時需要原始 TBS 位元組） */
  raw: Uint8Array;
  next: number;
}

/** 讀取一個 TLV（供解析 PKCS#1 / SPKI / 憑證用） */
export function readTlv(d: Uint8Array, off: number): TlvNode {
  const start = off;
  if (off >= d.length) throw new Error('DER: 非預期的結尾');
  const tag = d[off++];
  if (off >= d.length) throw new Error('DER: 長度被截斷');
  let len = d[off++];
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4) throw new Error('DER: 非法長度編碼');
    len = 0;
    for (let i = 0; i < count; i++) {
      if (off >= d.length) throw new Error('DER: 長度被截斷');
      len = len * 256 + d[off++];
    }
  }
  const content = d.subarray(off, off + len);
  if (content.length !== len) throw new Error('DER: 內容被截斷');
  return { tag, content, raw: d.subarray(start, off + len), next: off + len };
}

// ---------------------------------------------------------------------------
// Base64 / PEM 工具
// ---------------------------------------------------------------------------

function base64Encode(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)) as number[]);
  }
  return btoa(bin);
}

function base64Decode(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlDecode(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  return base64Decode(b64);
}

/** PEM 文字 → DER 位元組 */
export function pemToDer(pem: string): Uint8Array {
  const m = pem.match(/-----BEGIN [^-]+-----\s*([\s\S]*?)\s*-----END [^-]+-----/);
  if (!m) throw new Error('無效的 PEM：缺少標頭/標尾');
  return base64Decode(m[1]);
}

/** DER 位元組 → PEM 文字位元組（LF 換行，base64 每 64 字元一行） */
export function derToPem(der: Uint8Array, label: string): Uint8Array {
  const b64 = base64Encode(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return new TextEncoder().encode(
    `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`,
  );
}

/** 解析 PKCS#1 PEM 公鑰（`-----BEGIN RSA PUBLIC KEY-----`），取出 n、e */
export function parsePkcs1PublicKey(pem: string): { n: Uint8Array; e: Uint8Array } {
  const der = pemToDer(pem);
  return parsePkcs1Der(der);
}

/** 解析 PKCS#1 DER 公鑰（SEQUENCE { INTEGER n, INTEGER e }），取出 n、e */
export function parsePkcs1Der(der: Uint8Array): { n: Uint8Array; e: Uint8Array } {
  const seq = readTlv(der, 0);
  if (seq.tag !== 0x30) throw new Error('PKCS#1：預期為 SEQUENCE');
  const nTlv = readTlv(seq.content, 0);
  const eTlv = readTlv(seq.content, nTlv.next);
  if (nTlv.tag !== 0x02 || eTlv.tag !== 0x02) throw new Error('PKCS#1：預期為兩個 INTEGER');
  if (eTlv.next !== seq.content.length) throw new Error('PKCS#1：有多餘位元組');
  const strip = (v: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    return v.subarray(i);
  };
  return { n: strip(nTlv.content), e: strip(eTlv.content) };
}

/** 由 n、e 重建 canonical 的 PKCS#1 RSAPublicKey DER */
function buildPkcs1Der(n: Uint8Array, e: Uint8Array): Uint8Array {
  return encodeSequence(encodeIntegerBytes(n), encodeIntegerBytes(e));
}

/**
 * 將 PKCS#1 公鑰（PEM 字串、PEM 位元組或 DER 位元組）正規化為 PKCS#1 DER。
 * ca.rs 的 `generate_certificates` 只接受 PKCS#1 PEM，此處多容忍 DER 輸入。
 */
export function toPkcs1Der(input: string | Uint8Array): Uint8Array {
  if (typeof input === 'string') {
    const { n, e } = parsePkcs1PublicKey(input);
    return buildPkcs1Der(n, e);
  }
  const head = new TextDecoder().decode(input.subarray(0, 27));
  if (head.includes('-----BEGIN')) {
    const { n, e } = parsePkcs1PublicKey(new TextDecoder().decode(input));
    return buildPkcs1Der(n, e);
  }
  const { n, e } = parsePkcs1Der(input);
  return buildPkcs1Der(n, e);
}

/** 從 SPKI DER 取出內層 PKCS#1 RSAPublicKey DER */
export function spkiToPkcs1(spkiDer: Uint8Array): Uint8Array {
  const seq = readTlv(spkiDer, 0);
  if (seq.tag !== 0x30) throw new Error('SPKI：預期為 SEQUENCE');
  const algId = readTlv(seq.content, 0);
  const bitStr = readTlv(seq.content, algId.next);
  if (bitStr.tag !== 0x03) throw new Error('SPKI：預期第二個欄位為 BIT STRING');
  if (bitStr.content.length < 1 || bitStr.content[0] !== 0) {
    throw new Error('SPKI：公鑰 BIT STRING 的 unused bits 必須為 0');
  }
  return bitStr.content.subarray(1);
}

// ---------------------------------------------------------------------------
// X.509 結構
// ---------------------------------------------------------------------------

const signatureAlgorithm = (): Uint8Array =>
  encodeSequence(encodeOid(OID_SHA256_WITH_RSA), encodeNull());

/** 以 PKCS#1 公鑰 DER 組出 SubjectPublicKeyInfo */
function spkiFromPkcs1(pkcs1Der: Uint8Array): Uint8Array {
  return encodeSequence(
    encodeSequence(encodeOid(OID_RSA_ENCRYPTION), encodeNull()),
    encodeBitString(pkcs1Der),
  );
}

/** 空 Name（空 SEQUENCE）。ca.rs 的 CA 憑證 subject / issuer 即為此 */
const emptyName = (): Uint8Array => encodeSequence();

/** subject 為 CN=<cn> 的 RDNSequence（值用 UTF8String，與 x509-cert 的 FromStr 一致） */
function cnName(cn: string): Uint8Array {
  return encodeSequence(
    encodeSet(encodeSequence(encodeOid(OID_COMMON_NAME), encodeUtf8String(cn))),
  );
}

/**
 * `Profile::Root` 風格的 extensions（x509-cert 0.2.5 `builder.rs` 的
 * `Profile::build_extensions`，依序）：
 * 1. SubjectKeyIdentifier（non-critical）= SHA-1(公鑰 BIT STRING 本體)
 * 2. BasicConstraints（critical）：cA = TRUE
 * 3. KeyUsage（critical）：keyCertSign + cRLSign
 * 注意：Root 不會產生 AuthorityKeyIdentifier。
 */
async function buildExtensions(subjectPublicKeyDer: Uint8Array): Promise<Uint8Array> {
  // 1. SubjectKeyIdentifier：SHA-1 over 公鑰 BIT STRING 的內容位元組
  //    （RFC 5280 §4.2.1.2 方法 (1)；x509-cert 的 SubjectKeyIdentifier::try_from(spki)）
  const skid = new Uint8Array(
    await crypto.subtle.digest('SHA-1', new Uint8Array(subjectPublicKeyDer)),
  );
  const subjectKeyIdentifier = encodeSequence(
    encodeOid(OID_SUBJECT_KEY_ID),
    // non-critical：不放 critical BOOLEAN
    encodeOctetString(encodeOctetString(skid)),
  );

  // 2. BasicConstraints（critical）：SEQUENCE { BOOLEAN TRUE }，無 pathLenConstraint
  const basicConstraints = encodeSequence(
    encodeOid(OID_BASIC_CONSTRAINTS),
    encodeBoolean(true), // critical
    encodeOctetString(encodeSequence(encodeBoolean(true))), // cA = TRUE
  );

  // 3. KeyUsage（critical）：keyCertSign(5) + cRLSign(6)
  //    BIT STRING：bit5=0x04, bit6=0x02 → 首位元組 0x06，未使用位元數 1
  const keyUsage = encodeSequence(
    encodeOid(OID_KEY_USAGE),
    encodeBoolean(true), // critical
    encodeOctetString(encodeBitString(Uint8Array.of(0x06), 1)),
  );

  return encodeExplicit(3, encodeSequence(subjectKeyIdentifier, basicConstraints, keyUsage));
}

/**
 * 對應 ca.rs 的 `make_cert`：建 TBSCertificate 並以簽發者私鑰簽章。
 *
 * `Profile::Root` 語意：issuer 與 subject 相同（皆為 `nameDer`）。
 *
 * @param signingKey 簽發者的 RSA 私鑰（CA 憑證為自簽；裝置/主機憑證為 CA 私鑰）
 * @param subjectPublicKeyDer 憑證主體的 PKCS#1 RSAPublicKey DER
 * @param commonName null → 空 subject；否則 subject/issuer 皆為 CN=<commonName>
 */
async function makeCertificate(
  signingKey: CryptoKey,
  subjectPublicKeyDer: Uint8Array,
  commonName: string | null,
): Promise<Uint8Array> {
  const spki = spkiFromPkcs1(subjectPublicKeyDer);
  const name = commonName === null ? emptyName() : cnName(commonName);
  const notBeforeSecs = Math.floor(Date.now() / 1000);
  const notAfterSecs = notBeforeSecs + CERT_LIFETIME_SECS;

  const tbs = encodeSequence(
    encodeExplicit(0, encodeIntegerNum(2)), // version v3
    encodeIntegerNum(1), // serialNumber = 1（對應 SerialNumber::new(&[1])）
    signatureAlgorithm(), // signature
    name, // issuer（Profile::Root：issuer = subject）
    encodeSequence(encodeTime(notBeforeSecs), encodeTime(notAfterSecs)), // validity
    name, // subject
    spki, // subjectPublicKeyInfo
    await buildExtensions(subjectPublicKeyDer), // [3] extensions
  );

  const sig = new Uint8Array(
    // 拷貝為 ArrayBuffer 背景，滿足 BufferSource 型別
    await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signingKey, new Uint8Array(tbs)),
  );
  return encodeSequence(tbs, signatureAlgorithm(), encodeBitString(sig));
}

// ---------------------------------------------------------------------------
// 金鑰工具
// ---------------------------------------------------------------------------

async function generateRsaKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
}

/** 從 RSA 私鑰（JWK）取出 n、e 並重建 canonical PKCS#1 公鑰 DER */
async function pkcs1FromPrivateKey(privateKey: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk.n || !jwk.e) throw new Error('無法從私鑰取出 RSA 公開參數');
  return buildPkcs1Der(base64UrlDecode(jwk.n), base64UrlDecode(jwk.e));
}

async function importPkcs8PrivateKey(pkcs8Der: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    new Uint8Array(pkcs8Der),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign'],
  );
}

// ---------------------------------------------------------------------------
// 公開 API
// ---------------------------------------------------------------------------

/** 自簽 Root CA（在配對流程中同時擔任 Host 憑證，即 idevice 的 hostCert） */
export interface RootCA {
  /** 自簽 CA 憑證 DER */
  certDer: Uint8Array;
  /** 自簽 CA 憑證 PEM（LF 換行） */
  certPem: Uint8Array;
  /** CA 私鑰（WebCrypto CryptoKey） */
  privateKey: CryptoKey;
  /** CA 公鑰（WebCrypto CryptoKey） */
  publicKey: CryptoKey;
  /** CA 私鑰 PKCS#8 DER */
  privateKeyPkcs8Der: Uint8Array;
  /** CA 私鑰 PKCS#8 PEM（LF 換行；配對檔的 RootPrivateKey / HostPrivateKey 欄位用此） */
  privateKeyPkcs8Pem: Uint8Array;
  /** CA 公鑰 SPKI DER */
  publicKeySpkiDer: Uint8Array;
}

/**
 * 產生 Root CA：新的 RSA-2048 金鑰對 + 自簽憑證（subject/issuer 為空 Name）。
 * 對應配對流程中的 Host 憑證（idevice 的 `generate_certificates` 亦如此產生）。
 */
export async function createRootCA(): Promise<RootCA> {
  const pair = await generateRsaKeyPair();
  const spkiDer = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const pkcs1Der = spkiToPkcs1(spkiDer);
  const certDer = await makeCertificate(pair.privateKey, pkcs1Der, null);
  const pkcs8Der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return {
    certDer,
    certPem: derToPem(certDer, 'CERTIFICATE'),
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    privateKeyPkcs8Der: pkcs8Der,
    privateKeyPkcs8Pem: derToPem(pkcs8Der, 'PRIVATE KEY'),
    publicKeySpkiDer: spkiDer,
  };
}

/** 由 Root 簽發的主機憑證 */
export interface HostCertificate {
  /** 主機憑證 DER（subject/issuer 為 CN=<hostId>，由 root 私鑰簽發） */
  certDer: Uint8Array;
  /** 主機憑證 PEM（LF 換行） */
  certPem: Uint8Array;
  /** 主機私鑰（WebCrypto CryptoKey，新產生的 RSA-2048） */
  privateKey: CryptoKey;
  /** 主機私鑰 PKCS#8 DER */
  privateKeyDer: Uint8Array;
  /** 主機私鑰 PKCS#8 PEM（LF 換行） */
  privateKeyPem: Uint8Array;
}

/**
 * 簽發主機憑證：產生新的 RSA-2048 金鑰對，憑證 subject/issuer 為 CN=<hostId>，
 * 由 `root` 的私鑰簽發（`Profile::Root` 語意：issuer 與 subject 相同）。
 */
export async function issueHostCertificate(
  root: Pick<RootCA, 'privateKey'>,
  hostId: string,
): Promise<HostCertificate> {
  const pair = await generateRsaKeyPair();
  const spkiDer = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const pkcs1Der = spkiToPkcs1(spkiDer);
  const certDer = await makeCertificate(root.privateKey, pkcs1Der, hostId);
  const pkcs8Der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return {
    certDer,
    certPem: derToPem(certDer, 'CERTIFICATE'),
    privateKey: pair.privateKey,
    privateKeyDer: pkcs8Der,
    privateKeyPem: derToPem(pkcs8Der, 'PRIVATE KEY'),
  };
}

/**
 * 簽發裝置憑證：subject/issuer 為 CN=Device，公鑰為裝置公鑰，由 `root` 私鑰簽發。
 *
 * @param devicePublicKey 裝置的 RSA 公鑰，PKCS#1 DER 位元組、PKCS#1 PEM 字串或 PEM 位元組
 * @returns 裝置憑證 DER
 */
export async function issueDeviceCertificate(
  root: Pick<RootCA, 'privateKey'>,
  devicePublicKey: Uint8Array | string,
): Promise<Uint8Array> {
  const pkcs1Der = toPkcs1Der(devicePublicKey);
  return makeCertificate(root.privateKey, pkcs1Der, 'Device');
}

// ---------------------------------------------------------------------------
// generate_certificates（對應 ca.rs，供 lockdown 配對流程直接使用）
// ---------------------------------------------------------------------------

/** `generateCertificates` 的回傳值：三者皆為 PEM 文字位元組（LF 換行） */
export interface CaResult {
  /** Host 憑證 PEM（自簽 CA；配對檔的 HostCertificate / RootCertificate 欄位用此） */
  hostCert: Uint8Array;
  /** 裝置憑證 PEM（CN=Device；配對檔的 DeviceCertificate 欄位用此） */
  devCert: Uint8Array;
  /** CA 私鑰 PKCS#8 PEM（配對檔的 RootPrivateKey / HostPrivateKey 欄位用此） */
  privateKey: Uint8Array;
}

/**
 * 產生 CA 憑證（hostCert）、裝置憑證（devCert）與 CA 私鑰。
 * 對應 ca.rs 的 `generate_certificates`。
 *
 * @param devicePublicKeyPem 裝置的 PKCS#1 公鑰（PEM 字串/位元組；亦容忍 DER 位元組）。
 *   來源為 lockdown `GetValue(DevicePublicKey)` 回傳的 `-----BEGIN RSA PUBLIC KEY-----` PEM。
 * @param privateKeyDerPkcs8 可選：現成的 PKCS#8 DER 私鑰；未提供則以 WebCrypto 產生 RSA-2048
 */
export async function generateCertificates(
  devicePublicKeyPem: string | Uint8Array,
  privateKeyDerPkcs8?: Uint8Array,
): Promise<CaResult> {
  // 載入裝置公鑰（PKCS#1）並正規化為 DER
  const devPkcs1Der = toPkcs1Der(devicePublicKeyPem);

  // 產生或匯入 CA 私鑰
  const privateKey = privateKeyDerPkcs8
    ? await importPkcs8PrivateKey(privateKeyDerPkcs8)
    : (await generateRsaKeyPair()).privateKey;

  // 從私鑰取出 CA 公鑰的 PKCS#1 DER
  const caPkcs1Der = await pkcs1FromPrivateKey(privateKey);

  // CA 憑證（自簽，subject/issuer 為空 Name）
  const hostCertDer = await makeCertificate(privateKey, caPkcs1Der, null);
  // 裝置憑證（subject/issuer CN=Device）
  const devCertDer = await makeCertificate(privateKey, devPkcs1Der, 'Device');

  const pkcs8Der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));

  return {
    hostCert: derToPem(hostCertDer, 'CERTIFICATE'),
    devCert: derToPem(devCertDer, 'CERTIFICATE'),
    privateKey: derToPem(pkcs8Der, 'PRIVATE KEY'),
  };
}
