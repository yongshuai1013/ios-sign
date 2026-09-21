/**
 * ca.ts 的測試（bun:test）。
 *
 * 用 WebCrypto 產生 RSA-2048 金鑰對，手組 PKCS#1 DER 當作「裝置公鑰」輸入，
 * 再驗證憑證結構與簽章。以下斷言對照 Rust `idevice` 的 `src/ca.rs` 與
 * x509-cert 0.2.5 `Profile::Root` 的實際行為：
 * - issuer 與 subject 相同（CA：空 Name；裝置：CN=Device）
 * - notBefore 用 UTCTime、notAfter 用 GeneralizedTime（RFC 5280 §4.1.2.5）
 * - extensions 依序為 SKI（non-critical）→ BasicConstraints（critical, cA=TRUE）
 *   → KeyUsage（critical, keyCertSign + cRLSign）
 */

// `bun test` 會自動提供 describe / test / expect 全域函式（已用 bun 1.3.10 實測確認），
// 以下僅為 tsc 補上型別宣告，不影響執行期。
declare function describe(name: string, fn: () => void): void;
declare function test(name: string, fn: () => void | Promise<void>): void;
declare function expect(actual: unknown): {
  toBe(expected: unknown): void;
  toEqual(expected: unknown): void;
  toBeLessThanOrEqual(expected: number): void;
  toBeGreaterThanOrEqual(expected: number): void;
  toContain(item: unknown): void;
};

import {
  createRootCA,
  derToPem,
  generateCertificates,
  issueDeviceCertificate,
  issueHostCertificate,
  parsePkcs1PublicKey,
  pemToDer,
} from '../src/pairing/ca.js';

// ---------------------------------------------------------------------------
// 測試用的迷你 DER 工具（與 ca.ts 內部實作獨立，避免自己測自己）
// ---------------------------------------------------------------------------

function tConcat(...parts: Uint8Array[]): Uint8Array {
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

function tTlv(tag: number, content: Uint8Array): Uint8Array {
  const len = content.length;
  const lenBytes =
    len < 128
      ? Uint8Array.of(len)
      : (() => {
          const b: number[] = [];
          let v = len;
          while (v > 0) {
            b.unshift(v % 256);
            v = Math.floor(v / 256);
          }
          return Uint8Array.of(0x80 | b.length, ...b);
        })();
  return tConcat(Uint8Array.of(tag), lenBytes, content);
}

function tInt(v: Uint8Array): Uint8Array {
  let i = 0;
  while (i < v.length - 1 && v[i] === 0) i++;
  let w = v.subarray(i);
  if (w[0] & 0x80) w = tConcat(Uint8Array.of(0), w);
  return tTlv(0x02, w);
}

function tSeq(...parts: Uint8Array[]): Uint8Array {
  return tTlv(0x30, tConcat(...parts));
}

// 保留起始偏移以便取出 raw（含 tag+length 的完整 TLV）
function readTlv(
  d: Uint8Array,
  off: number,
): { tag: number; content: Uint8Array; raw: Uint8Array; next: number } {
  const start = off;
  const tag = d[off++];
  let len = d[off++];
  if (len & 0x80) {
    const count = len & 0x7f;
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + d[off++];
  }
  const content = d.subarray(off, off + len);
  if (content.length !== len) throw new Error('DER 截斷');
  return { tag, content, raw: d.subarray(start, off + len), next: off + len };
}

function b64UrlDecode(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseGeneralizedTime(d: Uint8Array): number {
  const s = new TextDecoder().decode(d);
  const Y = +s.slice(0, 4);
  const Mo = +s.slice(4, 6);
  const D = +s.slice(6, 8);
  const h = +s.slice(8, 10);
  const mi = +s.slice(10, 12);
  const se = +s.slice(12, 14);
  return Date.UTC(Y, Mo - 1, D, h, mi, se) / 1000;
}

/** 解析 UTCTime（YYMMDDHHMMSSZ；RFC 5280：00–49 為 2000s，50–99 為 1900s） */
function parseUtcTime(d: Uint8Array): number {
  const s = new TextDecoder().decode(d);
  const yy = +s.slice(0, 2);
  const Y = yy >= 50 ? 1900 + yy : 2000 + yy;
  const Mo = +s.slice(2, 4);
  const D = +s.slice(4, 6);
  const h = +s.slice(6, 8);
  const mi = +s.slice(8, 10);
  const se = +s.slice(10, 12);
  return Date.UTC(Y, Mo - 1, D, h, mi, se) / 1000;
}

/** 產生假裝置 RSA-2048 公鑰的 PKCS#1 PEM（手組 SEQUENCE{INTEGER n, INTEGER e}） */
async function makeFakeDevicePkcs1Pem(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const jwk = await crypto.subtle.exportKey('jwk', (pair as CryptoKeyPair).publicKey);
  const n = b64UrlDecode(jwk.n!);
  const e = b64UrlDecode(jwk.e!);
  const der = tSeq(tInt(n), tInt(e));
  return new TextDecoder().decode(derToPem(der, 'RSA PUBLIC KEY'));
}

/** 檢查 PEM 標頭/標尾與 64 字元換行 */
function checkPem(pemBytes: Uint8Array, label: string): string {
  const text = new TextDecoder().decode(pemBytes);
  expect(text.startsWith(`-----BEGIN ${label}-----\n`)).toBe(true);
  expect(text.endsWith(`-----END ${label}-----\n`)).toBe(true);
  expect(text.includes('\r')).toBe(false);
  const lines = text.split('\n');
  for (const line of lines.slice(1, -2)) {
    expect(line.length).toBeLessThanOrEqual(64);
    expect(line.length).toBeGreaterThanOrEqual(1);
  }
  return text;
}

/** 從 Name DER 取出 CN（預期為 SET → SEQUENCE → OID=2.5.4.3 + 字串） */
function nameCn(nameContent: Uint8Array): string {
  const setTlv = readTlv(nameContent, 0);
  expect(setTlv.tag).toBe(0x31);
  const atv = readTlv(setTlv.content, 0);
  expect(atv.tag).toBe(0x30);
  const oidTlv = readTlv(atv.content, 0);
  const strTlv = readTlv(atv.content, oidTlv.next);
  expect(oidTlv.tag).toBe(0x06);
  expect(Array.from(oidTlv.content)).toEqual([0x55, 0x04, 0x03]); // 2.5.4.3
  expect(strTlv.tag).toBe(0x0c); // UTF8String
  return new TextDecoder().decode(strTlv.content);
}

const hex = (d: Uint8Array): string =>
  Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');

/** 跳過 TBS 前 n 個欄位，回傳下一個欄位的偏移 */
function skipTbsFields(tbsContent: Uint8Array, n: number): number {
  let off = 0;
  for (let i = 0; i < n; i++) off = readTlv(tbsContent, off).next;
  return off;
}

/** 以指定的 RSA 公鑰驗證憑證簽章 */
async function expectValidSignature(
  certDer: Uint8Array,
  publicKey: CryptoKey,
): Promise<void> {
  const cert = readTlv(certDer, 0);
  expect(cert.tag).toBe(0x30);
  const tbs = readTlv(cert.content, 0);
  const sigAlg = readTlv(cert.content, tbs.next);
  const sig = readTlv(cert.content, sigAlg.next);
  expect(sig.tag).toBe(0x03);
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    new Uint8Array(sig.content.subarray(1)), // 跳過 BIT STRING 的 unused-bits 位元組
    new Uint8Array(tbs.raw),
  );
  expect(ok).toBe(true);
}

// 與 ca.rs 相同（測試容差用）
const EXPECTED_LIFETIME = 365 * 9 * 12 * 31 * 24 * 60 * 60;

describe('ca', () => {
  test('PEM 工具往返與 PKCS#1 解析', async () => {
    const devicePem = await makeFakeDevicePkcs1Pem();
    const { n, e } = parsePkcs1PublicKey(devicePem);
    // 2048 位元 RSA 的 n 應為 256 位元組，e 應為 3 位元組 (65537)
    expect(n.length).toBe(256);
    expect(Array.from(e)).toEqual([1, 0, 1]);

    const der = pemToDer(devicePem);
    const back = derToPem(der, 'RSA PUBLIC KEY');
    expect(new TextDecoder().decode(back)).toBe(devicePem);
  });

  test('generateCertificates：PEM 標頭、憑證欄位、簽章驗證', async () => {
    const devicePem = await makeFakeDevicePkcs1Pem();
    const { hostCert, devCert, privateKey } = await generateCertificates(devicePem);

    const hostText = checkPem(hostCert, 'CERTIFICATE');
    const devText = checkPem(devCert, 'CERTIFICATE');
    checkPem(privateKey, 'PRIVATE KEY');

    // ---- 解析 devCert ----
    const devDer = pemToDer(devText);
    const cert = readTlv(devDer, 0);
    expect(cert.tag).toBe(0x30);

    const tbs = readTlv(cert.content, 0);

    let off = 0;
    const versionWrap = readTlv(tbs.content, off);
    off = versionWrap.next;
    const serialTlv = readTlv(tbs.content, off);
    off = serialTlv.next;
    const tbsSigAlg = readTlv(tbs.content, off);
    void tbsSigAlg;
    off = tbsSigAlg.next;
    const issuerTlv = readTlv(tbs.content, off);
    off = issuerTlv.next;
    const validityTlv = readTlv(tbs.content, off);
    off = validityTlv.next;
    const subjectTlv = readTlv(tbs.content, off);
    off = subjectTlv.next;
    const spkiTlv = readTlv(tbs.content, off);
    void spkiTlv;
    off = spkiTlv.next;
    const extWrap = readTlv(tbs.content, off);

    // version = v3（[0] explicit 包 INTEGER 2）
    expect(versionWrap.tag).toBe(0xa0);
    const ver = readTlv(versionWrap.content, 0);
    expect(ver.tag).toBe(0x02);
    expect(Array.from(ver.content)).toEqual([2]);

    // serial = 1
    expect(serialTlv.tag).toBe(0x02);
    expect(Array.from(serialTlv.content)).toEqual([1]);

    // Profile::Root 語意：issuer 與 subject 相同 → CN=Device
    expect(nameCn(issuerTlv.content)).toBe('Device');
    expect(nameCn(subjectTlv.content)).toBe('Device');

    // 有效期：notBefore 為 UTCTime（RFC 5280：2049 年底前），notAfter 為 GeneralizedTime
    const nb = readTlv(validityTlv.content, 0);
    const na = readTlv(validityTlv.content, nb.next);
    expect(nb.tag).toBe(0x17); // UTCTime
    expect(na.tag).toBe(0x18); // GeneralizedTime
    const diff = parseGeneralizedTime(na.content) - parseUtcTime(nb.content);
    expect(Math.abs(diff - EXPECTED_LIFETIME)).toBeLessThanOrEqual(86400);

    // extensions：依序 SKI → BasicConstraints → KeyUsage
    expect(extWrap.tag).toBe(0xa3);
    const extSeq = readTlv(extWrap.content, 0);
    expect(extSeq.tag).toBe(0x30);
    const exts: { oid: string; critical: boolean; value: Uint8Array }[] = [];
    let eoff = 0;
    while (eoff < extSeq.content.length) {
      const ext = readTlv(extSeq.content, eoff);
      eoff = ext.next;
      let coff = 0;
      const eoid = readTlv(ext.content, coff);
      coff = eoid.next;
      let critical = false;
      let valueTlv = readTlv(ext.content, coff);
      if (valueTlv.tag === 0x01) {
        critical = valueTlv.content[0] === 0xff;
        coff = valueTlv.next;
        valueTlv = readTlv(ext.content, coff);
      }
      expect(valueTlv.tag).toBe(0x04); // extnValue 皆為 OCTET STRING
      exts.push({ oid: hex(eoid.content), critical, value: valueTlv.content });
    }
    expect(exts.map((e) => e.oid)).toEqual(['551d0e', '551d13', '551d0f']);

    // 1. SubjectKeyIdentifier：non-critical，值 = SHA-1(裝置 PKCS#1 公鑰 DER)
    expect(exts[0].critical).toBe(false);
    const skiInner = readTlv(exts[0].value, 0);
    expect(skiInner.tag).toBe(0x04);
    const expectedSki = new Uint8Array(
      await crypto.subtle.digest('SHA-1', new Uint8Array(pemToDer(devicePem))),
    );
    expect(Array.from(skiInner.content)).toEqual(Array.from(expectedSki));

    // 2. BasicConstraints：critical，值 = SEQUENCE { BOOLEAN TRUE }（無 pathLen）
    expect(exts[1].critical).toBe(true);
    const bcInner = readTlv(exts[1].value, 0);
    expect(bcInner.tag).toBe(0x30);
    const bcBool = readTlv(bcInner.content, 0);
    expect(bcBool.tag).toBe(0x01);
    expect(Array.from(bcBool.content)).toEqual([0xff]);
    expect(bcBool.next).toBe(bcInner.content.length);

    // 3. KeyUsage：critical，值 = BIT STRING{keyCertSign, cRLSign} = 03 02 01 06
    expect(exts[2].critical).toBe(true);
    expect(Array.from(exts[2].value)).toEqual([0x03, 0x02, 0x01, 0x06]);

    // ---- 以 CA 公鑰驗證簽章 ----
    // 從 hostCert 取出 CA 的 SPKI（TBS 第 7 個欄位，index 6）
    const hostDer = pemToDer(hostText);
    const hostCertTlv = readTlv(hostDer, 0);
    const hostTbs = readTlv(hostCertTlv.content, 0);
    const hostSpki = readTlv(hostTbs.content, skipTbsFields(hostTbs.content, 6));

    const caPublicKey = await crypto.subtle.importKey(
      'spki',
      new Uint8Array(hostSpki.raw),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );

    // devCert 由 CA 簽發 → 驗證通過
    await expectValidSignature(devDer, caPublicKey);
    // hostCert 自簽 → 驗證通過
    await expectValidSignature(hostDer, caPublicKey);

    // hostCert 的 subject/issuer 皆為空 Name
    const hostSubject = readTlv(hostTbs.content, skipTbsFields(hostTbs.content, 5));
    const hostIssuer = readTlv(hostTbs.content, skipTbsFields(hostTbs.content, 3));
    expect(hostSubject.tag).toBe(0x30);
    expect(hostSubject.content.length).toBe(0);
    expect(hostIssuer.tag).toBe(0x30);
    expect(hostIssuer.content.length).toBe(0);
  });

  test('generateCertificates：可接受外部 PKCS#8 私鑰', async () => {
    const devicePem = await makeFakeDevicePkcs1Pem();
    const first = await generateCertificates(devicePem);
    const pkcs8Der = pemToDer(new TextDecoder().decode(first.privateKey));

    const second = await generateCertificates(devicePem, pkcs8Der);
    checkPem(second.hostCert, 'CERTIFICATE');
    checkPem(second.devCert, 'CERTIFICATE');
    checkPem(second.privateKey, 'PRIVATE KEY');

    // 同一把私鑰產生的 hostCert，SPKI 應相同（同一 CA）
    const spkiOf = (pemBytes: Uint8Array): string => {
      const der = pemToDer(new TextDecoder().decode(pemBytes));
      const c = readTlv(der, 0);
      const t = readTlv(c.content, 0);
      const spki = readTlv(t.content, skipTbsFields(t.content, 6));
      return hex(spki.raw);
    };
    expect(spkiOf(second.hostCert)).toBe(spkiOf(first.hostCert));

    // 第二組 devCert 也能用同一 CA 公鑰驗證
    const hostDer = pemToDer(new TextDecoder().decode(second.hostCert));
    const hc = readTlv(hostDer, 0);
    const ht = readTlv(hc.content, 0);
    const caPub = await crypto.subtle.importKey(
      'spki',
      new Uint8Array(readTlv(ht.content, skipTbsFields(ht.content, 6)).raw),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    await expectValidSignature(pemToDer(new TextDecoder().decode(second.devCert)), caPub);
  });
});

describe('ca - RootCA / 簽發 API', () => {
  test('createRootCA：自簽 CA，subject/issuer 為空', async () => {
    const root = await createRootCA();
    checkPem(root.certPem, 'CERTIFICATE');
    checkPem(root.privateKeyPkcs8Pem, 'PRIVATE KEY');

    const cert = readTlv(root.certDer, 0);
    expect(cert.tag).toBe(0x30);
    const tbs = readTlv(cert.content, 0);

    const issuer = readTlv(tbs.content, skipTbsFields(tbs.content, 3));
    const subject = readTlv(tbs.content, skipTbsFields(tbs.content, 5));
    expect(issuer.tag).toBe(0x30);
    expect(issuer.content.length).toBe(0);
    expect(subject.tag).toBe(0x30);
    expect(subject.content.length).toBe(0);

    // 自簽驗證通過
    await expectValidSignature(root.certDer, root.publicKey);

    // 私鑰 PKCS#8 DER：SEQUENCE，首欄 INTEGER 0（version）
    const pkcs8 = readTlv(root.privateKeyPkcs8Der, 0);
    expect(pkcs8.tag).toBe(0x30);
    const ver = readTlv(pkcs8.content, 0);
    expect(ver.tag).toBe(0x02);
    expect(Array.from(ver.content)).toEqual([0]);
  });

  test('issueHostCertificate：CN=hostId，由 root 簽發', async () => {
    const root = await createRootCA();
    const hostId = '8F1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9';
    const host = await issueHostCertificate(root, hostId);
    checkPem(host.certPem, 'CERTIFICATE');
    checkPem(host.privateKeyPem, 'PRIVATE KEY');

    const cert = readTlv(host.certDer, 0);
    const tbs = readTlv(cert.content, 0);
    const subject = readTlv(tbs.content, skipTbsFields(tbs.content, 5));
    expect(nameCn(subject.content)).toBe(hostId);

    // 由 root 私鑰簽發 → 以 root 公鑰驗證通過
    await expectValidSignature(host.certDer, root.publicKey);

    // 主機私鑰（privateKeyDer）可匯入，且與憑證內公鑰成對
    const hostPriv = await crypto.subtle.importKey(
      'pkcs8',
      new Uint8Array(host.privateKeyDer),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const spki = readTlv(tbs.content, skipTbsFields(tbs.content, 6));
    const hostPub = await crypto.subtle.importKey(
      'spki',
      new Uint8Array(spki.raw),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const msg = new TextEncoder().encode('pairing-probe');
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', hostPriv, msg);
    expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', hostPub, signature, msg)).toBe(
      true,
    );
  });

  test('issueDeviceCertificate：接受 DER 與 PEM，subject/issuer 為 CN=Device', async () => {
    const root = await createRootCA();
    const devicePem = await makeFakeDevicePkcs1Pem();
    const deviceDer = pemToDer(devicePem);

    const inputs: (Uint8Array | string)[] = [deviceDer, devicePem];
    for (const input of inputs) {
      const certDer = await issueDeviceCertificate(root, input);
      const cert = readTlv(certDer, 0);
      expect(cert.tag).toBe(0x30);
      const tbs = readTlv(cert.content, 0);
      const issuer = readTlv(tbs.content, skipTbsFields(tbs.content, 3));
      const subject = readTlv(tbs.content, skipTbsFields(tbs.content, 5));
      expect(nameCn(issuer.content)).toBe('Device');
      expect(nameCn(subject.content)).toBe('Device');
      await expectValidSignature(certDer, root.publicKey);
    }
  });

  test('issueDeviceCertificate：拒絕非法的公鑰輸入', async () => {
    const root = await createRootCA();
    let threw = false;
    try {
      await issueDeviceCertificate(root, new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]));
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});
