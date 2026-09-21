/**
 * Anisette provisioning via `@lbr77/anisette-js` (WASM).
 *
 * The Emscripten glue is served from `/assets/anisette_rs.js` with its
 * binary at `/assets/anisette_rs.wasm` (copied into `public/assets/`
 * because the npm package does not ship the `.wasm`). The two Android
 * native libraries are served from `/anisette/*.so`. Provisioning HTTP
 * goes through the routed transport in `lib/network.ts` (libcurl-WASM
 * over WISP, falling back to direct fetch).
 *
 * `adi.pb` + `device.json` are cached in localStorage after the first
 * successful provisioning so later page loads skip the Apple round-trip.
 */
import { Anisette } from '@lbr77/anisette-js';
import { createAnisetteHttpClient, ensureLibcurl } from './lib/network';
import { base64ToBytes, bytesToBase64 } from './lib/ids';
import { loadText, removeText, saveText } from './lib/storage';

export interface AnisetteData {
  machineID: string;
  oneTimePassword: string;
  localUserID: string;
  routingInfo: number;
  deviceUniqueIdentifier: string;
  deviceDescription: string;
  deviceSerialNumber: string;
  date: Date;
  locale: string;
  timeZone: string;
}

const ADI_PB_STORAGE_KEY = 'webmuxd:anisette-adi-pb';
const DEVICE_JSON_STORAGE_KEY = 'webmuxd:anisette-device-json';

const GLUE_URL = '/assets/anisette_rs.js';
const WASM_URL = '/assets/anisette_rs.wasm';

function loadBytes(key: string): Uint8Array | null {
  const raw = loadText(key);
  if (!raw) return null;
  try {
    return base64ToBytes(raw);
  } catch {
    return null;
  }
}

function clearAnisetteCache(): void {
  removeText(ADI_PB_STORAGE_KEY);
  removeText(DEVICE_JSON_STORAGE_KEY);
  anisetteInstance = null;
}

/** Exported so the UI can offer a manual "reset anisette" action. */
export function resetAnisetteCache(): void {
  clearAnisetteCache();
}

/**
 * Validates that an OTP looks structurally sound.
 * A genuine Apple OTP (X-Apple-I-MD) is a 28-byte binary blob, base64-encoded
 * to 40 chars (e.g. "AAAABQAAABByN1SY6snwOoAC3WwpJBqbAAAAAQ==").
 * Observed in multiple working implementations (Provision, anisette-v3-server,
 * Sideloadly): 28 bytes is the correct length, not a truncation.
 */
function isPlausibleOtp(otpBase64: string | undefined): boolean {
  if (!otpBase64) return false;
  try {
    const bin = Uint8Array.from(atob(otpBase64), (c) => c.charCodeAt(0));
    // 28 bytes is the known-good length; accept 24-32 to tolerate minor variance
    return bin.length >= 24 && bin.length <= 64;
  } catch {
    return false;
  }
}

/** Loads the Emscripten glue directly, pinning the .wasm to /assets/. */
async function loadWasmModule(): Promise<unknown> {
  const glue = (await import(/* @vite-ignore */ GLUE_URL)) as {
    default: (config: Record<string, unknown>) => Promise<unknown>;
  };
  return glue.default({
    locateFile: (filename: string) =>
      filename.endsWith('.wasm') ? WASM_URL : filename,
  });
}

let anisetteInstance: Anisette | null = null;

export async function initAnisette(log?: (message: string) => void): Promise<Anisette> {
  if (anisetteInstance) return anisetteInstance;

  await ensureLibcurl(log);
  const wasmModule = await loadWasmModule();

  const [storeservicescore, coreadi] = await Promise.all([
    fetch('/anisette/libstoreservicescore.so').then(async (res) => {
      if (!res.ok) throw new Error(`libstoreservicescore.so not served (/anisette/): ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    }),
    fetch('/anisette/libCoreADI.so').then(async (res) => {
      if (!res.ok) throw new Error(`libCoreADI.so not served (/anisette/): ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    }),
  ]);

  const adiPb = loadBytes(ADI_PB_STORAGE_KEY) ?? undefined;
  const deviceJsonBytes = loadBytes(DEVICE_JSON_STORAGE_KEY) ?? undefined;
  if (adiPb) log?.('anisette: restoring cached provisioning data');

  anisetteInstance = await Anisette.fromSo(storeservicescore, coreadi, wasmModule, {
    httpClient: createAnisetteHttpClient(log),
    init: { adiPb, deviceJsonBytes },
  });

  if (!anisetteInstance.isProvisioned) {
    log?.('anisette: provisioning with Apple...');
    await anisetteInstance.provision();
    saveText(ADI_PB_STORAGE_KEY, bytesToBase64(anisetteInstance.getAdiPb()));
    saveText(DEVICE_JSON_STORAGE_KEY, bytesToBase64(anisetteInstance.getDeviceJson()));
    log?.('anisette: provisioned and cached');
  }
  return anisetteInstance;
}

export async function provisionAnisette(log?: (message: string) => void): Promise<void> {
  await initAnisette(log);
}

export async function getAnisetteData(log?: (message: string) => void): Promise<AnisetteData> {
  const anisette = await initAnisette(log);
  let headers: Record<string, string>;
  try {
    headers = (await anisette.getData()) as unknown as Record<string, string>;
  } catch (error) {
    // Cached provisioning data went stale — drop it and provision once more.
    log?.('anisette: cached data rejected, re-provisioning...');
    clearAnisetteCache();
    const fresh = await initAnisette(log);
    headers = (await fresh.getData()) as unknown as Record<string, string>;
    void error;
  }
  // Guard: a valid Apple OTP (X-Apple-I-MD) is ~150+ bytes. If the WASM
  // produced a truncated OTP (seen: 28 bytes), Apple 503s the GsService2
  // init. Discard the cache and provision once more.
  if (!isPlausibleOtp(headers['X-Apple-I-MD'])) {
    log?.('anisette: suspicious OTP length, re-provisioning...');
    clearAnisetteCache();
    const fresh = await initAnisette(log);
    headers = (await fresh.getData()) as unknown as Record<string, string>;
    if (!isPlausibleOtp(headers['X-Apple-I-MD'])) {
      throw new Error('anisette: failed to generate a valid OTP');
    }
  }
  return {
    machineID: headers['X-Apple-I-MD-M'],
    oneTimePassword: headers['X-Apple-I-MD'],
    localUserID: headers['X-Apple-I-MD-LU'],
    routingInfo: Number.parseInt(headers['X-Apple-I-MD-RINFO'] ?? '0', 10),
    deviceUniqueIdentifier: headers['X-Mme-Device-Id'],
    deviceDescription: headers['X-MMe-Client-Info'],
    deviceSerialNumber: headers['X-Apple-I-SRL-NO'] || '0',
    date: new Date(headers['X-Apple-I-Client-Time']),
    locale: headers['X-Apple-Locale'],
    timeZone: headers['X-Apple-I-TimeZone'],
  };
}

/** True when cached provisioning data exists (no WASM load performed). */
export async function checkAnisetteProvisioned(): Promise<boolean> {
  return loadBytes(ADI_PB_STORAGE_KEY) !== null;
}
