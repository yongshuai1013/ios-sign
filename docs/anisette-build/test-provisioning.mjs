/**
 * 自建 anisette WASM 功能測試：
 * 1. 載入構建好的 anisette_rs.node.js
 * 2. init_from_blobs（Apple 私有 .so，需自行從 Apple Music APK 提取，不隨附）
 * 3. 檢查未 provisioning 狀態
 * 4. 跑完整 Apple provisioning（lookup → start → finish）
 * 5. request_otp 產生 X-Apple-I-MD 等 headers 並驗證格式
 *
 * 用法：先把下面三個路徑改成你本機的檔案位置，再 `node test-provisioning.mjs`
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// ===== 按本機環境修改這三個路徑 =====
const GLUE = '/path/to/anisette_rs.node.js'; // 構建產出的 node 版 glue
const SS_PATH = '/path/to/libstoreservicescore.so'; // Apple 私有 .so（arm64-v8a）
const CA_PATH = '/path/to/libCoreADI.so'; // Apple 私有 .so（arm64-v8a）
// =====================================

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = __dirname;
const DSID = BigInt('-2');

const LOOKUP_URL = 'https://gsa.apple.com/grandslam/GsService2/lookup';
const START_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Header</key><dict/><key>Request</key><dict/></dict></plist>`;

function allocBytes(m, bytes) { const p = m._malloc(bytes.length); m.HEAPU8.set(bytes, p); return p; }
function allocStr(m, s) { if (!s) return 0; const n = m.lengthBytesUTF8(s) + 1; const p = m._malloc(n); m.stringToUTF8(s, p, n); return p; }
function readBytes(m, ptr, len) { return (!ptr || !len) ? new Uint8Array() : m.HEAPU8.slice(ptr, ptr + len); }
function lastError(m) {
  const p = m._anisette_last_error_ptr(), l = m._anisette_last_error_len();
  return (!p || !l) ? '' : new TextDecoder().decode(m.HEAPU8.subarray(p, p + l));
}
function check(m, rc, what) { if (rc !== 0) throw new Error(`${what} failed rc=${rc}: ${lastError(m)}`); }

// 最小 plist 解析：只取 <key>k</key><string>v</string> / <dict>
function parsePlist(xml) {
  const out = {};
  const re = /<key>([^<]*)<\/key>\s*(<string>([^<]*)<\/string>|<dict>([\s\S]*?)<\/dict>)/g;
  let mm;
  while ((mm = re.exec(xml)) !== null) {
    if (mm[3] !== undefined) out[mm[1]] = mm[3];
    else if (mm[4] !== undefined) out[mm[1]] = parsePlist(mm[4]);
  }
  return out;
}
const b64ToBytes = (s) => new Uint8Array(Buffer.from(s, 'base64'));

const commonHeaders = {
  'User-Agent': 'akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0',
  'Content-Type': 'application/x-www-form-urlencoded',
  'Connection': 'keep-alive',
  'X-Mme-Device-Id': '00000000-0000-4000-8000-000000000000',
  'X-Mme-Client-Info': '<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>',
  'X-Apple-I-MD-LU': '0000000000000000',
  'X-Apple-Client-App-Name': 'Setup',
};

async function main() {
  console.log('[1/6] 載入 WASM glue:', GLUE);
  const factory = (await import(pathToFileURL(GLUE).href)).default;
  const m = await factory({ locateFile: (f) => f });
  console.log('      WASM 載入成功');

  console.log('[2/6] init_from_blobs');
  const ss = await fs.readFile(SS_PATH), ca = await fs.readFile(CA_PATH);
  console.log(`      libstoreservicescore.so=${ss.length} bytes, libCoreADI.so=${ca.length} bytes`);
  const ssP = allocBytes(m, ss), caP = allocBytes(m, ca);
  const libP = allocStr(m, './anisette/'), provP = allocStr(m, './anisette/'), idP = allocStr(m, '');
  const rc = m._anisette_init_from_blobs(ssP, ss.length, caP, ca.length, libP, provP, idP);
  m._free(ssP); m._free(caP); m._free(libP); m._free(provP); m._free(idP);
  check(m, rc, 'anisette_init_from_blobs');
  console.log('      init_from_blobs rc=0');

  console.log('[3/6] is_machine_provisioned（預期 0=未配置）');
  const prov0 = m._anisette_is_machine_provisioned(DSID);
  if (prov0 < 0) throw new Error('is_machine_provisioned: ' + lastError(m));
  console.log('      is_machine_provisioned =', prov0);

  console.log('[4/6] Apple provisioning（lookup → start → finish）');
  const lookupRes = await fetch(LOOKUP_URL, { headers: commonHeaders });
  if (!lookupRes.ok) throw new Error(`lookup HTTP ${lookupRes.status}`);
  const bag = parsePlist(await lookupRes.text()).urls || {};
  const startUrl = bag.midStartProvisioning, finishUrl = bag.midFinishProvisioning;
  if (!startUrl || !finishUrl) throw new Error('url bag 缺少 provisioning URL');
  console.log('      url bag OK');

  const startRes = await fetch(startUrl, { method: 'POST', headers: { ...commonHeaders, 'X-Apple-I-Client-Time': new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') }, body: START_BODY });
  if (!startRes.ok) throw new Error(`startProvisioning HTTP ${startRes.status}`);
  const spimB64 = parsePlist(await startRes.text()).spim;
  if (!spimB64) throw new Error('start 回應缺少 spim');
  console.log('      spim 取得，長度', spimB64.length);

  const spim = b64ToBytes(spimB64);
  const spimP = allocBytes(m, spim);
  const src = m._anisette_start_provisioning(DSID, spimP, spim.length);
  m._free(spimP);
  check(m, src, 'anisette_start_provisioning');
  const cpim = readBytes(m, m._anisette_get_cpim_ptr(), m._anisette_get_cpim_len());
  const session = m._anisette_get_session();
  console.log(`      cpim=${cpim.length} bytes, session=${session}`);

  const finishBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Header</key><dict/><key>Request</key><dict><key>cpim</key><string>${Buffer.from(cpim).toString('base64')}</string></dict></dict></plist>`;
  const finishRes = await fetch(finishUrl, { method: 'POST', headers: { ...commonHeaders, 'X-Apple-I-Client-Time': new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') }, body: finishBody });
  if (!finishRes.ok) throw new Error(`finishProvisioning HTTP ${finishRes.status}`);
  const finishPlist = parsePlist(await finishRes.text());
  const ptm = b64ToBytes(finishPlist.ptm), tk = b64ToBytes(finishPlist.tk);
  if (!ptm.length || !tk.length) throw new Error('finish 回應缺少 ptm/tk');
  console.log(`      ptm=${ptm.length} bytes, tk=${tk.length} bytes`);

  const ptmP = allocBytes(m, ptm), tkP = allocBytes(m, tk);
  const erc = m._anisette_end_provisioning(session, ptmP, ptm.length, tkP, tk.length);
  m._free(ptmP); m._free(tkP);
  check(m, erc, 'anisette_end_provisioning');
  console.log('      end_provisioning rc=0');

  console.log('[5/6] 再次檢查 is_machine_provisioned（預期 1）');
  const prov1 = m._anisette_is_machine_provisioned(DSID);
  if (prov1 < 0) throw new Error('is_machine_provisioned: ' + lastError(m));
  console.log('      is_machine_provisioned =', prov1);
  if (prov1 !== 1) throw new Error('provisioning 未生效');

  console.log('[6/6] request_otp → anisette headers');
  check(m, m._anisette_request_otp(DSID), 'anisette_request_otp');
  const otp = readBytes(m, m._anisette_get_otp_ptr(), m._anisette_get_otp_len());
  const mid = readBytes(m, m._anisette_get_mid_ptr(), m._anisette_get_mid_len());
  console.log(`      otp=${otp.length} bytes, mid=${mid.length} bytes`);
  if (!otp.length || !mid.length) throw new Error('OTP/MID 為空');

  const headers = {
    'X-Apple-I-MD': Buffer.from(otp).toString('base64'),
    'X-Apple-I-MD-M': Buffer.from(mid).toString('base64'),
    'X-Apple-I-MD-RINFO': '17106176',
    'X-Apple-I-SRL-NO': '0',
  };
  console.log('      X-Apple-I-MD 前 40 字元:', headers['X-Apple-I-MD'].slice(0, 40));
  console.log('      X-Apple-I-MD-M 前 40 字元:', headers['X-Apple-I-MD-M'].slice(0, 40));

  // 把 adi.pb 從 VFS 讀出來存檔，供後續重用
  const adiPathP = allocStr(m, './anisette/adi.pb');
  const frc = m._anisette_fs_read_file(adiPathP);
  m._free(adiPathP);
  if (frc === 0) {
    const adiPb = readBytes(m, m._anisette_fs_read_ptr(), m._anisette_fs_read_len());
    await fs.mkdir(path.join(ROOT, 'test-out'), { recursive: true });
    await fs.writeFile(path.join(ROOT, 'test-out/adi.pb'), adiPb);
    console.log(`      adi.pb 已存檔 (${adiPb.length} bytes) → test-out/adi.pb`);
  } else {
    console.log('      注意：VFS 內無 adi.pb（fs_read_file rc=' + frc + '）');
  }

  console.log('\n全部通過 ✅ 自建 WASM 可正常 provisioning＋產生 OTP');
}

main().catch((e) => { console.error('\n❌ 測試失敗:', e.message); process.exit(1); });
