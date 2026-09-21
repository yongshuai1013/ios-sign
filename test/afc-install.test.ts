/**
 * afc.ts / installation-proxy.ts 的測試（bun:test）。
 *
 * 用記憶體假 transport 模擬裝置端：AFC 假裝置按 opcode 回覆腳本化封包，
 * installation_proxy 假裝置回覆腳本化 plist 訊框。
 */

import { describe, expect, test } from 'bun:test';
import plist, { type PlistObject } from 'plist';
import {
  AFC_E_OBJECT_EXISTS,
  AFC_HEADER_LEN,
  AFC_MAGIC,
  AFC_WRITE_CHUNK_SIZE,
  AfcClient,
  AfcError,
  AfcFopenMode,
  AfcOpcode,
  type ByteTransport,
} from '../src/pairing/afc.js';
import {
  InstallationProxyClient,
  InstallationProxyError,
  installIpa,
  sanitizeIpaFileName,
  type InstallProgressEvent,
} from '../src/pairing/installation-proxy.js';

// ---------------------------------------------------------------------------
// 測試共用小工具
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

function tU64le(value: number): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), true);
  return buf;
}

function tReadU64le(data: Uint8Array, offset = 0): number {
  return Number(new DataView(data.buffer, data.byteOffset + offset, 8).getBigUint64(0, true));
}

function statusReply(code: number): { operation: number; headerPayload: Uint8Array; payload: Uint8Array } {
  return { operation: AfcOpcode.Status, headerPayload: tU64le(code), payload: new Uint8Array(0) };
}

// ---------------------------------------------------------------------------
// 假 AFC 裝置
// ---------------------------------------------------------------------------

interface AfcRequest {
  opcode: number;
  packetNum: bigint;
  headerPayload: Uint8Array;
  payload: Uint8Array;
}

type AfcHandler = (
  opcode: number,
  headerPayload: Uint8Array,
  payload: Uint8Array,
) => { operation: number; headerPayload: Uint8Array; payload: Uint8Array };

class FakeAfcDevice implements ByteTransport {
  readonly requests: AfcRequest[] = [];
  private pending: Uint8Array = new Uint8Array(0);

  constructor(private readonly handler: AfcHandler) {}

  async write(data: Uint8Array): Promise<void> {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const magic = dv.getBigUint64(0, true);
    if (magic !== AFC_MAGIC) {
      throw new Error('fake AFC device: bad request magic');
    }
    const entireLen = Number(dv.getBigUint64(8, true));
    const headerPayloadLen = Number(dv.getBigUint64(16, true));
    const packetNum = dv.getBigUint64(24, true);
    const opcode = Number(dv.getBigUint64(32, true));
    const headerPayload = data.slice(AFC_HEADER_LEN, headerPayloadLen);
    const payload = data.slice(headerPayloadLen, entireLen);
    this.requests.push({ opcode, packetNum, headerPayload, payload });

    const res = this.handler(opcode, headerPayload, payload);
    const respHeaderPayloadLen = AFC_HEADER_LEN + res.headerPayload.length;
    const respEntireLen = respHeaderPayloadLen + res.payload.length;
    const out = new Uint8Array(respEntireLen);
    const odv = new DataView(out.buffer);
    odv.setBigUint64(0, AFC_MAGIC, true);
    odv.setBigUint64(8, BigInt(respEntireLen), true);
    odv.setBigUint64(16, BigInt(respHeaderPayloadLen), true);
    odv.setBigUint64(24, packetNum, true); // echo the request packet_num
    odv.setBigUint64(32, BigInt(res.operation), true);
    out.set(res.headerPayload, AFC_HEADER_LEN);
    out.set(res.payload, respHeaderPayloadLen);
    this.pending = tConcat(this.pending, out);
  }

  async readExact(n: number): Promise<Uint8Array> {
    if (this.pending.length < n) {
      throw new Error(`fake AFC device: wanted ${n} bytes, only ${this.pending.length} queued`);
    }
    const out = this.pending.slice(0, n);
    this.pending = this.pending.slice(n);
    return out;
  }

  close(): void {
    // no-op
  }
}

// ---------------------------------------------------------------------------
// 假 installation_proxy 裝置（u32 BE 長度 + XML plist 訊框）
// ---------------------------------------------------------------------------

class FakePlistDevice implements ByteTransport {
  readonly requests: Uint8Array[] = [];
  private pending: Uint8Array;

  constructor(responses: Array<Record<string, unknown>>) {
    const frames = responses.map((r) => {
      const body = new TextEncoder().encode(plist.build(r as unknown as PlistObject));
      const frame = new Uint8Array(4 + body.length);
      new DataView(frame.buffer).setUint32(0, body.length, false);
      frame.set(body, 4);
      return frame;
    });
    this.pending = tConcat(...frames);
  }

  async write(data: Uint8Array): Promise<void> {
    this.requests.push(data.slice());
  }

  async readExact(n: number): Promise<Uint8Array> {
    if (this.pending.length < n) {
      throw new Error(`fake plist device: wanted ${n} bytes, only ${this.pending.length} queued`);
    }
    const out = this.pending.slice(0, n);
    this.pending = this.pending.slice(n);
    return out;
  }

  close(): void {
    // no-op
  }
}

function parsePlistFrame(frame: Uint8Array): Record<string, unknown> {
  const length = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false);
  const body = frame.slice(4, 4 + length);
  return plist.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// AFC 測試
// ---------------------------------------------------------------------------

describe('AfcClient', () => {
  test('makeDir: Status(16) 視為成功，且 path 以 null 結尾', async () => {
    const device = new FakeAfcDevice(() => statusReply(AFC_E_OBJECT_EXISTS));
    const client = new AfcClient(device);

    await client.makeDir('/PublicStaging'); // 不應拋錯

    expect(device.requests.length).toBe(1);
    const req = device.requests[0];
    expect(req.opcode).toBe(AfcOpcode.MakeDir);
    expect(req.packetNum).toBe(0n);
    const expected = new TextEncoder().encode('/PublicStaging\0');
    expect(req.headerPayload).toEqual(expected);
  });

  test('writeFile: 100KB 資料產生 2 個 Write（60KB + 40KB）', async () => {
    const writes: Array<{ headerPayload: Uint8Array; payload: Uint8Array }> = [];
    const device = new FakeAfcDevice((opcode, headerPayload, payload) => {
      if (opcode === AfcOpcode.FileOpen) return { operation: AfcOpcode.FileOpenRes, headerPayload: tU64le(3), payload: new Uint8Array(0) };
      if (opcode === AfcOpcode.Write) {
        writes.push({ headerPayload, payload });
        return statusReply(0);
      }
      if (opcode === AfcOpcode.FileClose) return statusReply(0);
      throw new Error(`unexpected opcode ${opcode}`);
    });
    const client = new AfcClient(device);

    const total = 100 * 1024;
    const data = new Uint8Array(total);
    for (let i = 0; i < total; i++) data[i] = i & 0xff;
    const progress: Array<[number, number]> = [];
    await client.writeFile('/PublicStaging/app.ipa', data, (sent, t) => progress.push([sent, t]));

    // FileOpen 的 header_payload = u64LE(Wr=4) + path\0
    const openReq = device.requests[0];
    expect(openReq.opcode).toBe(AfcOpcode.FileOpen);
    expect(tReadU64le(openReq.headerPayload)).toBe(AfcFopenMode.Wr);
    expect(openReq.headerPayload.slice(8)).toEqual(new TextEncoder().encode('/PublicStaging/app.ipa\0'));

    // 2 個 Write，大小分別為 60KB 與 40KB，且 handle 一致
    expect(writes.length).toBe(2);
    expect(writes[0].payload.length).toBe(AFC_WRITE_CHUNK_SIZE);
    expect(writes[1].payload.length).toBe(total - AFC_WRITE_CHUNK_SIZE);
    expect(tReadU64le(writes[0].headerPayload)).toBe(3);
    expect(tReadU64le(writes[1].headerPayload)).toBe(3);
    expect(writes[0].payload).toEqual(data.slice(0, AFC_WRITE_CHUNK_SIZE));
    expect(writes[1].payload).toEqual(data.slice(AFC_WRITE_CHUNK_SIZE));

    // FileClose 帶同一個 handle
    const closeReq = device.requests[device.requests.length - 1];
    expect(closeReq.opcode).toBe(AfcOpcode.FileClose);
    expect(tReadU64le(closeReq.headerPayload)).toBe(3);

    // packet_num 遞增配對
    expect(device.requests.map((r) => r.packetNum)).toEqual([0n, 1n, 2n, 3n]);

    // 進度回呼
    expect(progress).toEqual([
      [AFC_WRITE_CHUNK_SIZE, total],
      [total, total],
    ]);
  });

  test('writeFile: 任一步非 0 status 拋 AfcError', async () => {
    const device = new FakeAfcDevice((opcode) => {
      if (opcode === AfcOpcode.FileOpen) return { operation: AfcOpcode.FileOpenRes, headerPayload: tU64le(7), payload: new Uint8Array(0) };
      if (opcode === AfcOpcode.Write) return statusReply(5); // WriteError
      return statusReply(0);
    });
    const client = new AfcClient(device);

    let caught: unknown;
    try {
      await client.writeFile('/x.ipa', new Uint8Array(10));
    } catch (e) {
      caught = e;
    }
    expect(caught instanceof AfcError).toBe(true);
    expect((caught as AfcError).status).toBe(5);
    // 失敗後仍嘗試 FileClose
    const last = device.requests[device.requests.length - 1];
    expect(last.opcode).toBe(AfcOpcode.FileClose);
  });

  test('回應 magic 錯誤時拋錯', async () => {
    const bad: ByteTransport = {
      write: async () => {},
      readExact: async (n: number) => new Uint8Array(n), // magic 全 0
      close: () => {},
    };
    const client = new AfcClient(bad);
    let caught: unknown;
    try {
      await client.request(AfcOpcode.GetDevInfo, new Uint8Array(0));
    } catch (e) {
      caught = e;
    }
    expect(caught instanceof AfcError).toBe(true);
  });

  test('makeDirectory / uploadFile：正規名稱與別名行為一致', async () => {
    const device = new FakeAfcDevice((opcode, headerPayload, _payload) => {
      if (opcode === AfcOpcode.MakeDir) return statusReply(0);
      if (opcode === AfcOpcode.FileOpen)
        return { operation: AfcOpcode.FileOpenRes, headerPayload: tU64le(9), payload: new Uint8Array(0) };
      if (opcode === AfcOpcode.Write) return statusReply(0);
      if (opcode === AfcOpcode.FileClose) return statusReply(0);
      throw new Error(`unexpected opcode ${opcode}`);
    });
    const client = new AfcClient(device);

    await client.makeDirectory('/PublicStaging');
    await client.uploadFile('/PublicStaging/a.ipa', new Uint8Array([1, 2, 3]));

    const opcodes = device.requests.map((r) => r.opcode);
    expect(opcodes).toEqual([
      AfcOpcode.MakeDir,
      AfcOpcode.FileOpen,
      AfcOpcode.Write,
      AfcOpcode.FileClose,
    ]);
  });

  test('removePath：送 RemovePath 且 path 以 null 結尾', async () => {
    const device = new FakeAfcDevice(() => statusReply(0));
    const client = new AfcClient(device);

    await client.removePath('/PublicStaging/old.ipa');

    expect(device.requests.length).toBe(1);
    const req = device.requests[0];
    expect(req.opcode).toBe(AfcOpcode.RemovePath);
    expect(req.headerPayload).toEqual(new TextEncoder().encode('/PublicStaging/old.ipa\0'));
  });

  test('removePathRecursive：送 RemovePathAndContents (0x22)', async () => {
    const device = new FakeAfcDevice(() => statusReply(0));
    const client = new AfcClient(device);

    await client.removePathRecursive('/PublicStaging/old_dir');

    expect(device.requests.length).toBe(1);
    expect(device.requests[0].opcode).toBe(0x22);
  });

  test('listDirectory：ReadDir 回 Data，解析 null 分隔檔名', async () => {
    const names = new TextEncoder().encode('app.ipa\0.\0..\0sub\0');
    const device = new FakeAfcDevice((opcode) => {
      if (opcode === AfcOpcode.ReadDir)
        return { operation: AfcOpcode.Data, headerPayload: names, payload: new Uint8Array(0) };
      throw new Error(`unexpected opcode ${opcode}`);
    });
    const client = new AfcClient(device);

    const entries = await client.listDirectory('/PublicStaging');
    expect(entries).toEqual(['app.ipa', '.', '..', 'sub']);
    expect(device.requests[0].opcode).toBe(AfcOpcode.ReadDir);
    expect(device.requests[0].headerPayload).toEqual(
      new TextEncoder().encode('/PublicStaging\0'),
    );
  });

  test('listDirectory：回覆非 Data 時拋錯', async () => {
    const device = new FakeAfcDevice(() => statusReply(0));
    const client = new AfcClient(device);

    let caught: unknown;
    try {
      await client.listDirectory('/PublicStaging');
    } catch (e) {
      caught = e;
    }
    expect(caught instanceof Error).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// installation_proxy 測試
// ---------------------------------------------------------------------------

describe('InstallationProxyClient', () => {
  test('install: 狀態回覆觸發 onProgress，Complete 結束', async () => {
    const device = new FakePlistDevice([
      { Status: 'CreatingStagingDirectory', PercentComplete: 5 },
      { Status: 'Complete' },
    ]);
    const client = new InstallationProxyClient(device);

    const seen: Array<[string, number | undefined]> = [];
    await client.install('PublicStaging/app.ipa', (status, percent) => seen.push([status, percent]));

    expect(seen).toEqual([
      ['CreatingStagingDirectory', 5],
      ['Complete', undefined],
    ]);

    // 驗證送出的 Install plist
    expect(device.requests.length).toBe(1);
    const req = parsePlistFrame(device.requests[0]);
    expect(req['Command']).toBe('Install');
    expect(req['PackagePath']).toBe('PublicStaging/app.ipa');
    expect((req['ClientOptions'] as Record<string, unknown>)['PackageType']).toBe('Developer');
  });

  test('install: 回覆含 Error 時拋錯', async () => {
    const device = new FakePlistDevice([{ Error: 'ApplicationVerificationFailed' }]);
    const client = new InstallationProxyClient(device);

    let caught: unknown;
    try {
      await client.install('PublicStaging/app.ipa');
    } catch (e) {
      caught = e;
    }
    expect(caught instanceof InstallationProxyError).toBe(true);
    expect(String((caught as Error).message)).toContain('ApplicationVerificationFailed');
  });

  test('installEvents：逐個 yield 進度事件，Complete 結束', async () => {
    const device = new FakePlistDevice([
      { Status: 'CreatingStagingDirectory', PercentComplete: 5 },
      { Status: 'PreflightingApplication', PercentComplete: 50 },
      { Status: 'Complete' },
    ]);
    const client = new InstallationProxyClient(device);

    const events: InstallProgressEvent[] = [];
    for await (const event of client.installEvents('PublicStaging/app.ipa')) {
      events.push(event);
    }

    expect(events).toEqual([
      { status: 'CreatingStagingDirectory', percentComplete: 5, error: undefined, errorDescription: undefined },
      { status: 'PreflightingApplication', percentComplete: 50, error: undefined, errorDescription: undefined },
      { status: 'Complete', percentComplete: undefined, error: undefined, errorDescription: undefined },
    ]);
  });

  test('installEvents：ClientOptions 預設 PackageType=Developer，可覆寫與加 ApplicationType', async () => {
    const device = new FakePlistDevice([{ Status: 'Complete' }]);
    const client = new InstallationProxyClient(device);

    for await (const _e of client.installEvents('/PublicStaging/app.ipa', {
      PackageType: 'Enterprise',
      ApplicationType: 'Any',
    })) {
      // 只有一個 Complete 事件
    }

    expect(device.requests.length).toBe(1);
    const req = parsePlistFrame(device.requests[0]);
    expect(req['Command']).toBe('Install');
    // 前導斜線已被去除
    expect(req['PackagePath']).toBe('PublicStaging/app.ipa');
    const clientOptions = req['ClientOptions'] as Record<string, unknown>;
    expect(clientOptions['PackageType']).toBe('Enterprise');
    expect(clientOptions['ApplicationType']).toBe('Any');
  });

  test('installEvents：Error + ErrorDescription 時拋 InstallationProxyError', async () => {
    const device = new FakePlistDevice([
      { Status: 'CreatingStagingDirectory', PercentComplete: 5 },
      { Error: 'ApplicationVerificationFailed', ErrorDescription: 'Failed to verify code signature' },
    ]);
    const client = new InstallationProxyClient(device);

    const seen: InstallProgressEvent[] = [];
    let caught: unknown;
    try {
      for await (const event of client.installEvents('PublicStaging/app.ipa')) {
        seen.push(event);
      }
    } catch (e) {
      caught = e;
    }

    expect(caught instanceof InstallationProxyError).toBe(true);
    const message = String((caught as Error).message);
    expect(message).toContain('ApplicationVerificationFailed');
    expect(message).toContain('Failed to verify code signature');
    // 錯誤前的事件已 yield
    expect(seen.length).toBe(1);
    expect(seen[0].status).toBe('CreatingStagingDirectory');
  });
});

// ---------------------------------------------------------------------------
// sanitizeIpaFileName / installIpa 測試
// ---------------------------------------------------------------------------

describe('sanitizeIpaFileName', () => {
  test('非法字元轉底線、確保 .ipa 結尾', () => {
    expect(sanitizeIpaFileName('My App (1).IPA')).toBe('My_App_1_.IPA');
    expect(sanitizeIpaFileName('app')).toBe('app.ipa');
    expect(sanitizeIpaFileName('weird/name?.ipa')).toBe('weird_name_.ipa');
    expect(sanitizeIpaFileName('  spaced .ipa  ')).toBe('spaced_.ipa');
  });

  test('空字串使用 fallback', () => {
    expect(sanitizeIpaFileName('   ')).toBe('webmuxd-upload.ipa');
  });
});

describe('installIpa', () => {
  test('完整流程：消毒檔名 → AFC staging → instproxy 安裝（PackagePath 不帶前導斜線）', async () => {
    const afcDevice = new FakeAfcDevice((opcode, headerPayload, _payload) => {
      if (opcode === AfcOpcode.MakeDir) return statusReply(AFC_E_OBJECT_EXISTS);
      if (opcode === AfcOpcode.FileOpen) {
        // 路徑應為 /PublicStaging/<消毒後檔名>（sanitize 不轉小寫）
        expect(headerPayload.slice(8)).toEqual(new TextEncoder().encode('/PublicStaging/My_Cool_App_.ipa\0'));
        return { operation: AfcOpcode.FileOpenRes, headerPayload: tU64le(3), payload: new Uint8Array(0) };
      }
      if (opcode === AfcOpcode.Write) return statusReply(0);
      if (opcode === AfcOpcode.FileClose) return statusReply(0);
      throw new Error(`unexpected opcode ${opcode}`);
    });
    const plistDevice = new FakePlistDevice([
      { Status: 'CreatingStagingDirectory', PercentComplete: 5 },
      { Status: 'PreflightingApplication', PercentComplete: 50 },
      { Status: 'Complete' },
    ]);
    const afc = new AfcClient(afcDevice);
    const instProxy = new InstallationProxyClient(plistDevice);

    const logs: string[] = [];
    const ipa = new Uint8Array(100);
    await installIpa(afc, instProxy, ipa, 'My Cool App!', (msg) => logs.push(msg));

    // AFC 端：makeDir /PublicStaging（16 視為成功）+ 寫檔
    const opcodes = afcDevice.requests.map((r) => r.opcode);
    expect(opcodes[0]).toBe(AfcOpcode.MakeDir);
    expect(afcDevice.requests[0].headerPayload).toEqual(new TextEncoder().encode('/PublicStaging\0'));

    // instproxy 端：PackagePath 不帶前導斜線
    const req = parsePlistFrame(plistDevice.requests[0]);
    expect(req['Command']).toBe('Install');
    expect(req['PackagePath']).toBe('PublicStaging/My_Cool_App_.ipa');

    // 有 log 輸出且流程走完
    expect(logs.length).toBeGreaterThanOrEqual(3);
    expect(logs[logs.length - 1]).toBe('install: complete.');
  });
});
