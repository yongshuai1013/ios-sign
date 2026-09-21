/**
 * tls-client.ts 的測試（bun:test）。
 *
 * 涵蓋：
 * - TLS 1.0 PRF：以獨立實作（python hashlib 事先算出的固定向量）驗證，
 *   外加與 node:crypto 實作的隨機交叉驗證。
 * - TLS 1.2 PRF（P_SHA-256）：固定向量＋隨機交叉驗證。
 * - PEM/DER 解析、RSA 金鑰解析（PKCS#1 / PKCS#8）、從 X.509 憑證抽公鑰。
 * - RSA PKCS#1 v1.5 加密／簽章與 openssl 交叉驗證（含 SHA-256 DigestInfo）。
 * - 與真實 `openssl s_server` 的互通：TLS 1.0（RSA kx）與 TLS 1.2
 *  （ECDHE-RSA-AES256/AES128-SHA）：不含／含 client certificate 兩種握手、
 *   雙向 application data、大檔分片傳輸、close_notify。
 *
 * 需要系統上有 `openssl`（含 `s_server -tls1`／`-tls1_2`）；沒有時互通測試會 skip。
 */

import { describe, expect, test } from 'bun:test';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, createServer, type Server, type Socket } from 'node:net';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  tlsConnect,
  TlsError,
  pemToDer,
  parseRsaPrivateKey,
  parseRsaPublicKeyFromCertificate,
  rsaPkcs1v15Encrypt,
  rsaPkcs1v15SignRaw,
  rsaPkcs1v15SignSha256,
  modPow,
  tls10Prf,
  tls12Prf,
} from '../src/pairing/tls-client.js';
import type { Transport } from '../src/pairing/usbmuxd.js';

// ---------------------------------------------------------------------------
// openssl 可用性
// ---------------------------------------------------------------------------

const HAVE_OPENSSL: boolean = (() => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

// ---------------------------------------------------------------------------
// PRF
// ---------------------------------------------------------------------------

function hex(h: string): Uint8Array {
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

describe('tls10Prf', () => {
  test('matches an independently computed fixed vector (48-byte secret)', () => {
    const secret = hex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f',
    );
    const seed = hex(
      '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' +
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
    );
    const got = Buffer.from(tls10Prf(secret, 'master secret', seed, 48)).toString('hex');
    expect(got).toBe(
      '2e81c84ea2f797bc352536b726889d0f5aaa51078c5b2a99129141178da9ed1' +
        '08ac69f9aa3cbc0ff5b27f58e7ea47ea7',
    );
  });

  test('matches an independently computed fixed vector (odd-length secret)', () => {
    const secret = new Uint8Array(13).fill(0xab);
    const got = Buffer.from(
      tls10Prf(secret, 'key expansion', Uint8Array.of(1, 2, 3), 100),
    ).toString('hex');
    expect(got).toBe(
      'ff6960745d9ec4abd7512ee4612314f3cb45bf15d77822751c37531acd48c878' +
        '499de92d272a37444eb0fe4d1174388ca98934199a6eefd0ec36ae5017163ab' +
        'e01b931c8c6d9e269fbb281549dad71eef783669375d646faba74cfceac31853' +
        '3324086e7',
    );
  });

  test('cross-checks against a node:crypto reference on random inputs', () => {
    const pHashRef = (
      hashName: 'md5' | 'sha1',
      secret: Uint8Array,
      seed: Uint8Array,
      outLen: number,
    ): Buffer => {
      const out = Buffer.alloc(outLen);
      let a: Buffer = Buffer.from(seed);
      let pos = 0;
      while (pos < outLen) {
        a = createHmac(hashName, secret).update(a).digest();
        const chunk = createHmac(hashName, secret)
          .update(Buffer.concat([a, seed]))
          .digest();
        const n = Math.min(chunk.length, outLen - pos);
        chunk.copy(out, pos, 0, n);
        pos += n;
      }
      return out;
    };
    for (let t = 0; t < 25; t++) {
      const secret = randomBytes(1 + Math.floor(Math.random() * 64));
      const seed = randomBytes(77);
      const label = t % 2 === 0 ? 'master secret' : 'key expansion';
      const outLen = 12 + Math.floor(Math.random() * 120);
      const labelSeed = Buffer.concat([Buffer.from(label), seed]);
      const half = Math.ceil(secret.length / 2);
      const p1 = pHashRef('md5', secret.subarray(0, half), labelSeed, outLen);
      const p2 = pHashRef(
        'sha1',
        secret.subarray(secret.length - half),
        labelSeed,
        outLen,
      );
      const want = Buffer.alloc(outLen);
      for (let i = 0; i < outLen; i++) want[i] = p1[i] ^ p2[i];
      expect(Buffer.from(tls10Prf(secret, label, seed, outLen)).equals(want)).toBe(
        true,
      );
    }
  });
});

describe('tls12Prf', () => {
  test('matches an independently computed fixed vector', () => {
    const secret = hex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f',
    );
    const seed = hex(
      '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' +
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
    );
    const got = Buffer.from(tls12Prf(secret, 'master secret', seed, 48)).toString('hex');
    expect(got).toBe(
      '33f19713029a32518129acfbd2623ad9b9e3bfe795f60dbc0228a7bc4142a453' +
        '70fa02ebdfecbc1f5ac0d266becfb59a',
    );
  });

  test('cross-checks against a node:crypto reference on random inputs', () => {
    const pHashRef = (
      secret: Uint8Array,
      seed: Uint8Array,
      outLen: number,
    ): Buffer => {
      const out = Buffer.alloc(outLen);
      let a: Buffer = Buffer.from(seed);
      let pos = 0;
      while (pos < outLen) {
        a = createHmac('sha256', secret).update(a).digest();
        const chunk = createHmac('sha256', secret)
          .update(Buffer.concat([a, seed]))
          .digest();
        const n = Math.min(chunk.length, outLen - pos);
        chunk.copy(out, pos, 0, n);
        pos += n;
      }
      return out;
    };
    for (let t = 0; t < 25; t++) {
      const secret = randomBytes(1 + Math.floor(Math.random() * 64));
      const seed = randomBytes(77);
      const label = t % 2 === 0 ? 'master secret' : 'key expansion';
      const want = pHashRef(secret, Buffer.concat([Buffer.from(label), seed]), 12 + Math.floor(Math.random() * 120));
      const got = tls12Prf(secret, label, seed, want.length);
      expect(Buffer.from(got).equals(want)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// PEM / DER / RSA
// ---------------------------------------------------------------------------

describe('key parsing', () => {
  // 小到可以手算的 RSA 測試金鑰：p=61, q=53, n=3233, e=17, d=2753。
  // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
  // dp=53, dq=49, qinv=38。
  const tinyPkcs1Der = hex(
    '301d02010002020ca102011102020ac102013d020135020135020131020126',
  );

  test('pemToDer parses a PEM block', () => {
    const pem = Buffer.from(
      '-----BEGIN RSA PRIVATE KEY-----\n' +
        Buffer.from(tinyPkcs1Der).toString('base64') +
        '\n-----END RSA PRIVATE KEY-----\n',
    );
    const { label, der } = pemToDer(pem);
    expect(label).toBe('RSA PRIVATE KEY');
    expect(Buffer.from(der).equals(Buffer.from(tinyPkcs1Der))).toBe(true);
  });

  test('pemToDer passes raw DER through with an empty label', () => {
    const { label, der } = pemToDer(tinyPkcs1Der);
    expect(label).toBe('');
    expect(Buffer.from(der).equals(Buffer.from(tinyPkcs1Der))).toBe(true);
  });

  test('parseRsaPrivateKey reads a tiny PKCS#1 key', () => {
    const k = parseRsaPrivateKey(tinyPkcs1Der);
    expect(k.n).toBe(3233n);
    expect(k.d).toBe(2753n);
  });

  test('modPow matches the textbook RSA example', () => {
    // 65^17 mod 3233 = 2790（任何密碼學課本的例子）。
    expect(modPow(65n, 17n, 3233n)).toBe(2790n);
    expect(modPow(2790n, 2753n, 3233n)).toBe(65n);
  });

  test('rsaPkcs1v15Encrypt rejects messages that do not fit', () => {
    const k = parseRsaPrivateKey(tinyPkcs1Der);
    // 這個小金鑰 k=2，k-11 為負，任何訊息都塞不下。
    expect(() => rsaPkcs1v15Encrypt({ n: k.n, e: 17n }, Uint8Array.of(1))).toThrow(
      TlsError,
    );
  });

  test('rsaPkcs1v15SignRaw produces verifiable type-1 padding', () => {
    const k = parseRsaPrivateKey(tinyPkcs1Der);
    // 這個小金鑰 k=2，塞不下 digest；改用「訊息太長必須報錯」的行為測試。
    expect(() => rsaPkcs1v15SignRaw(k, new Uint8Array(36))).toThrow(TlsError);
  });
});

// ---------------------------------------------------------------------------
// 與 openssl 的互通測試
// ---------------------------------------------------------------------------

interface Fixtures {
  dir: string;
  certPem: Uint8Array;
  keyPem: Uint8Array;
  keyPkcs8Pem: Uint8Array;
}

let fixturesCache: Fixtures | null = null;

function fixtures(): Fixtures {
  if (fixturesCache) return fixturesCache;
  const dir = mkdtempSync(join(tmpdir(), 'tls-client-test-'));
  try {
    execFileSync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', join(dir, 'key.pem'),
        '-out', join(dir, 'cert.pem'),
        '-days', '2', '-nodes', '-subj', '/CN=tls-client-test',
      ],
      { stdio: 'ignore' },
    );
    execFileSync(
      'openssl',
      ['pkcs8', '-topk8', '-nocrypt', '-in', join(dir, 'key.pem'), '-out', join(dir, 'key-pkcs8.pem')],
      { stdio: 'ignore' },
    );
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  fixturesCache = {
    dir,
    certPem: readFileSync(join(dir, 'cert.pem')),
    keyPem: readFileSync(join(dir, 'key.pem')),
    keyPkcs8Pem: readFileSync(join(dir, 'key-pkcs8.pem')),
  };
  return fixturesCache;
}

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s: Server = createServer();
    s.listen(0, '127.0.0.1', () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

function socketTransport(sock: Socket): Transport {
  let buf = new Uint8Array(0);
  let closed = false;
  const pending: Array<{
    n: number;
    resolve: (b: Uint8Array) => void;
    reject: (e: Error) => void;
  }> = [];
  const pump = () => {
    while (pending.length > 0 && buf.length >= pending[0].n) {
      const w = pending.shift()!;
      const out = buf.slice(0, w.n);
      buf = buf.slice(w.n);
      w.resolve(out);
    }
    if (closed) {
      while (pending.length > 0) pending.shift()!.reject(new Error('socket closed'));
    }
  };
  sock.on('data', (d: Buffer) => {
    const merged = new Uint8Array(buf.length + d.length);
    merged.set(buf, 0);
    merged.set(d, buf.length);
    buf = merged;
    pump();
  });
  sock.on('close', () => {
    closed = true;
    pump();
  });
  sock.on('error', (e) => {
    closed = true;
    while (pending.length > 0) pending.shift()!.reject(e);
  });
  return {
    read: (n) =>
      new Promise<Uint8Array>((resolve, reject) => {
        pending.push({ n, resolve, reject });
        pump();
      }),
    write: (data) =>
      new Promise<void>((resolve, reject) => {
        sock.write(data, (e) => (e ? reject(e) : resolve()));
      }),
    close: () => {
      sock.destroy();
    },
  };
}

interface TestTlsServer {
  proc: ChildProcess;
  port: number;
  sawOutput: (needle: string) => boolean;
  writeStdin: (data: Uint8Array) => void;
  waitExit: (timeoutMs: number) => Promise<boolean>;
  kill: () => void;
}

async function startServer(
  extraArgs: string[],
  tlsVersion = '-tls1',
): Promise<TestTlsServer> {
  const fx = fixtures();
  const port = await freePort();
  const proc = spawn(
    'openssl',
    [
      's_server', tlsVersion,
      '-cert', join(fx.dir, 'cert.pem'),
      '-key', join(fx.dir, 'key.pem'),
      '-accept', String(port),
      '-naccept', '1', '-ign_eof', '-quiet',
      ...extraArgs,
    ],
    { stdio: ['pipe', 'pipe', 'pipe'] },
  );
  let out = '';
  proc.stdout?.on('data', (d: Buffer) => {
    out += d.toString('binary');
  });
  // s_server 沒有 ready 通知；等它 bind。
  await new Promise((r) => setTimeout(r, 1000));
  return {
    proc,
    port,
    sawOutput: (needle) => out.includes(needle),
    writeStdin: (data) => {
      proc.stdin?.write(data);
    },
    waitExit: (timeoutMs) =>
      new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), timeoutMs);
        proc.on('exit', () => {
          clearTimeout(timer);
          resolve(true);
        });
      }),
    kill: () => {
      proc.kill();
    },
  };
}

async function connectTls(
  port: number,
  opts: Parameters<typeof tlsConnect>[1] = {},
) {
  const sock = connect(port, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    sock.on('connect', () => resolve());
    sock.on('error', reject);
  });
  return tlsConnect(socketTransport(sock), {
    handshakeTimeoutMs: 15000,
    ...opts,
  });
}

if (HAVE_OPENSSL) {
  describe('openssl interop', () => {
  test('parses keys the way openssl generated them', () => {
    const fx = fixtures();
    const { label, der } = pemToDer(fx.certPem);
    expect(label).toBe('CERTIFICATE');
    const pub = parseRsaPublicKeyFromCertificate(der);
    const modulus = execFileSync(
      'openssl',
      ['x509', '-in', join(fx.dir, 'cert.pem'), '-noout', '-modulus'],
    )
      .toString()
      .trim()
      .split('=')[1]
      .toLowerCase();
    expect(pub.n.toString(16)).toBe(modulus);
    expect(pub.e).toBe(65537n);

    const pkcs1 = parseRsaPrivateKey(fx.keyPem);
    const pkcs8 = parseRsaPrivateKey(fx.keyPkcs8Pem);
    expect(pkcs8.n).toBe(pkcs1.n);
    expect(pkcs8.d).toBe(pkcs1.d);
  });

  test('rsaPkcs1v15Encrypt output decrypts with openssl', () => {
    const fx = fixtures();
    const pub = parseRsaPublicKeyFromCertificate(pemToDer(fx.certPem).der);
    const pt = randomBytes(48);
    const ct = rsaPkcs1v15Encrypt(pub, pt);
    expect(ct.length).toBe(256);
    const dec = execFileSync('openssl', [
      'pkeyutl', '-decrypt',
      '-inkey', join(fx.dir, 'key.pem'),
      '-in', '/dev/stdin',
    ], { input: Buffer.from(ct) });
    expect(Buffer.from(dec).equals(pt)).toBe(true);
  });

  test('rsaPkcs1v15SignSha256 verifies with openssl dgst', () => {
    const fx = fixtures();
    const priv = parseRsaPrivateKey(fx.keyPem);
    const msg = Buffer.from('certificate-verify-test-message');
    const digest = createHash('sha256').update(msg).digest();
    const sig = rsaPkcs1v15SignSha256(priv, digest);
    expect(sig.length).toBe(256);
    execFileSync('openssl', [
      'x509', '-in', join(fx.dir, 'cert.pem'), '-pubkey', '-noout',
      '-out', join(fx.dir, 'pub.pem'),
    ]);
    const msgFile = join(fx.dir, 'cvmsg.bin');
    const sigFile = join(fx.dir, 'cvsig.bin');
    writeFileSync(msgFile, msg);
    writeFileSync(sigFile, Buffer.from(sig));
    // throws if the signature does not verify
    execFileSync('openssl', [
      'dgst', '-sha256', '-verify', join(fx.dir, 'pub.pem'),
      '-signature', sigFile, msgFile,
    ]);
  });

  test('rsaPkcs1v15SignRaw verifies with openssl (raw)', () => {
    const fx = fixtures();
    const priv = parseRsaPrivateKey(fx.keyPem);
    const digest = randomBytes(36);
    const sig = rsaPkcs1v15SignRaw(priv, digest);
    expect(sig.length).toBe(256);
    execFileSync('openssl', [
      'x509', '-in', join(fx.dir, 'cert.pem'), '-pubkey', '-noout',
      '-out', join(fx.dir, 'pub.pem'),
    ]);
    const em = execFileSync('openssl', [
      'rsautl', '-verify', '-raw',
      '-pubin', '-inkey', join(fx.dir, 'pub.pem'),
      '-in', '/dev/stdin',
    ], { input: Buffer.from(sig) });
    // EM = 00 01 FF..FF 00 || digest
    expect(em[0]).toBe(0x00);
    expect(em[1]).toBe(0x01);
    expect(em[em.length - 37]).toBe(0x00);
    expect(Buffer.from(em.subarray(em.length - 36)).equals(digest)).toBe(true);
    for (let i = 2; i < em.length - 37; i++) expect(em[i]).toBe(0xff);
  });

  test('handshake without client cert (AES128-SHA) + app data both ways', async () => {
    const srv = await startServer(['-cipher', 'AES128-SHA:@SECLEVEL=0']);
    try {
      const tls = await connectTls(srv.port);
      // client -> server：s_server 把收到的 application data 寫到 stdout。
      const ping = new TextEncoder().encode('ping-from-client');
      await tls.write(ping);
      await new Promise((r) => setTimeout(r, 600));
      expect(srv.sawOutput('ping-from-client')).toBe(true);
      // server -> client：寫進 s_server 的 stdin。
      srv.writeStdin(new TextEncoder().encode('pong-from-server\n'));
      const got = await tls.read(17);
      expect(Buffer.from(got).toString()).toBe('pong-from-server\n');
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('handshake with client cert (AES256-SHA, CertificateRequest)', async () => {
    const fx = fixtures();
    const srv = await startServer([
      '-cipher', 'AES256-SHA:@SECLEVEL=0',
      '-Verify', '1',
    ]);
    try {
      const tls = await connectTls(srv.port, {
        clientCertificateDer: pemToDer(fx.certPem).der,
        clientPrivateKey: parseRsaPrivateKey(fx.keyPem),
      });
      const ping = new TextEncoder().encode('after-client-auth');
      await tls.write(ping);
      await new Promise((r) => setTimeout(r, 600));
      expect(srv.sawOutput('after-client-auth')).toBe(true);
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('100KB transfer fragments across records correctly', async () => {
    const srv = await startServer(['-cipher', 'AES128-SHA:@SECLEVEL=0']);
    try {
      const tls = await connectTls(srv.port);
      const marker = 'BIG' + '0123456789'.repeat(8);
      const big = new Uint8Array(100000);
      for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
      await tls.write(new TextEncoder().encode(marker));
      await tls.write(big);
      await new Promise((r) => setTimeout(r, 1200));
      expect(srv.sawOutput(marker)).toBe(true);
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('server demanding a client cert without one configured fails cleanly', async () => {
    const srv = await startServer(['-Verify', '1']);
    try {
      await expect(connectTls(srv.port)).rejects.toThrow(TlsError);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('TLS 1.2 handshake (ECDHE-RSA-AES256-SHA) + app data both ways', async () => {
    const srv = await startServer(
      ['-cipher', 'ECDHE-RSA-AES256-SHA:@SECLEVEL=0'],
      '-tls1_2',
    );
    try {
      const tls = await connectTls(srv.port);
      const ping = new TextEncoder().encode('ping-tls12-ecdhe');
      await tls.write(ping);
      await new Promise((r) => setTimeout(r, 600));
      expect(srv.sawOutput('ping-tls12-ecdhe')).toBe(true);
      srv.writeStdin(new TextEncoder().encode('pong-tls12\n'));
      const got = await tls.read(11);
      expect(Buffer.from(got).toString()).toBe('pong-tls12\n');
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('TLS 1.2 handshake with client cert (CertificateRequest, rsa_pkcs1_sha256)', async () => {
    const fx = fixtures();
    const srv = await startServer(
      ['-cipher', 'ECDHE-RSA-AES128-SHA:@SECLEVEL=0', '-Verify', '1'],
      '-tls1_2',
    );
    try {
      const tls = await connectTls(srv.port, {
        clientCertificateDer: pemToDer(fx.certPem).der,
        clientPrivateKey: parseRsaPrivateKey(fx.keyPem),
      });
      const ping = new TextEncoder().encode('after-tls12-client-auth');
      await tls.write(ping);
      await new Promise((r) => setTimeout(r, 600));
      expect(srv.sawOutput('after-tls12-client-auth')).toBe(true);
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);

  test('100KB transfer over TLS 1.2 ECDHE fragments correctly', async () => {
    const srv = await startServer(
      ['-cipher', 'ECDHE-RSA-AES256-SHA:@SECLEVEL=0'],
      '-tls1_2',
    );
    try {
      const tls = await connectTls(srv.port);
      const marker = 'BIG12' + '0123456789'.repeat(8);
      const big = new Uint8Array(100000);
      for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
      await tls.write(new TextEncoder().encode(marker));
      await tls.write(big);
      await new Promise((r) => setTimeout(r, 1200));
      expect(srv.sawOutput(marker)).toBe(true);
      tls.close();
      expect(await srv.waitExit(5000)).toBe(true);
    } finally {
      srv.kill();
    }
  }, 30000);
}); // describe('openssl interop')
} // if (HAVE_OPENSSL)

describe('handshake failure modes', () => {
  test('connection refused surfaces a TlsError', async () => {
    const port = await freePort();
    await expect(connectTls(port, { handshakeTimeoutMs: 3000 })).rejects.toThrow();
  });

  test('handshake timeout fires against a silent server', async () => {
    const blackhole: Server = createServer((sock) => {
      // 接受連線但永遠不說話。
      sock.on('error', () => undefined);
    });
    await new Promise<void>((r) => blackhole.listen(0, '127.0.0.1', () => r()));
    const port = (blackhole.address() as { port: number }).port;
    try {
      await expect(
        connectTls(port, { handshakeTimeoutMs: 1500 }),
      ).rejects.toThrow(TlsError);
    } finally {
      blackhole.close();
    }
  }, 15000);
});
