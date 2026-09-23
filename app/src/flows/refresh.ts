/**
 * Refresh flow: list installed apps via installation_proxy Browse, then
 * re-sign a cached IPA and overwrite-install it (same as a fresh sign+install,
 * iOS treats it as an app update and keeps user data).
 *
 * The IPA bytes come from the IndexedDB cache (populated when the user signs
 * through the website). If no cached IPA exists for a bundle ID, refresh
 * cannot proceed — the user must sign the IPA again from the Sign page.
 */
import { InstallationProxyClient, type ByteTransport } from '@pairing/installation-proxy';
import type { Transport } from '@pairing/usbmuxd';
import type { WebUsbMuxClient } from '../transport/webusb-mux';
import { loadPairRecordForUdid } from '../lib/pair-record';
import { getCachedIpa } from '../lib/ipa-cache';
import { signIpaFlow } from './sign';
import { installFlow } from './install';
import type { AnisetteData } from '../anisette-service';
import type { AppleDeveloperContext } from '../apple-signing';

export interface InstalledAppInfo {
  bundleId: string;
  displayName: string;
  shortVersion?: string;
  version?: string;
}

/** Adapts the `Transport` (`read`) interface to `ByteTransport` (`readExact`). */
function toByteTransport(t: Transport): ByteTransport {
  return {
    write: (data: Uint8Array) => t.write(data),
    readExact: async (n: number): Promise<Uint8Array> => {
      // Transport.read(n) may return fewer than n bytes; loop until we have all.
      const chunks: Uint8Array[] = [];
      let remaining = n;
      while (remaining > 0) {
        const chunk = await t.read(remaining);
        if (chunk.length === 0) {
          throw new Error('transport closed while reading');
        }
        chunks.push(chunk);
        remaining -= chunk.length;
      }
      if (chunks.length === 1) return chunks[0]!;
      const out = new Uint8Array(n);
      let offset = 0;
      for (const c of chunks) {
        out.set(c, offset);
        offset += c.length;
      }
      return out;
    },
    close: () => t.close(),
  };
}

export interface BrowseRequest {
  client: WebUsbMuxClient;
  targetUdid: string;
  log: (msg: string) => void;
}

/**
 * Returns user-installed apps on the device via installation_proxy Browse.
 * Requires an encrypted lockdownd session (same setup as installFlow).
 */
export async function browseInstalledApps(req: BrowseRequest): Promise<InstalledAppInfo[]> {
  const record = loadPairRecordForUdid(req.targetUdid);
  if (!record) {
    throw new Error(`no stored pairing file for UDID ${req.targetUdid}; pair the device first`);
  }

  // Load the pair record into the client (marks it paired, like pairDeviceFlow does).
  if (!req.client.isPaired) {
    req.client.loadPairRecord(record);
  }

  if (!req.client.isTlsUpgraded) {
    req.log('refresh: connecting to lockdownd…');
    // The USB link is flaky: retry with a clean reconnect before giving up.
    // NOTE: use client.reconnect() (not just retrying on the same MUX) —
    // a failed attempt can leave stale bytes in the MUX buffer, causing
    // "plist frame too large" desync on retry. reconnect() uses
    // getDevices() so it does NOT need a user gesture.
    let lastError: unknown = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        if (attempt > 1) {
          req.log(`refresh: reconnecting (attempt ${attempt}/3)…`);
          await req.client.reconnect();
          // reconnect() already did connectLockdown(); session still needed.
        }
        if (!req.client.isSessionStarted) {
          if (attempt === 1) {
            await req.client.connectLockdown();
          }
          req.log('refresh: starting session…');
          // Guard against startSession hanging forever (device not responding).
          await Promise.race([
            req.client.startSession(record.hostId, record.systemBuid),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('startSession timeout after 15000ms')), 15000),
            ),
          ]);
        }
        req.log('refresh: upgrading lockdownd to TLS…');
        await req.client.upgradeToTls(record);
        lastError = null;
        break;
      } catch (e) {
        lastError = e;
        const msg = e instanceof Error ? e.message : String(e);
        // A user-gesture error means the device picker can't reopen here;
        // retrying won't help, fail fast with a clear message.
        if (msg.includes('user gesture') || msg.includes('requestDevice')) {
          throw new Error(
            'USB device access was lost. Unplug and reconnect the iPhone via USB, then tap "Scan Installed Apps" again.',
          );
        }
        req.log(`refresh: connection attempt ${attempt}/3 failed (${msg}), retrying…`);
        await new Promise((r) => setTimeout(r, 1500));
      }
    }
    if (lastError) {
      const msg = lastError instanceof Error ? lastError.message : String(lastError);
      throw new Error(
        `device not responding after 3 attempts (${msg}). Make sure the iPhone is unlocked and connected via USB, then tap "Scan Installed Apps" again.`,
      );
    }
  }

  let instProxyTransport: Transport | null = null;
  try {
    req.log('refresh: starting com.apple.mobile.installation_proxy…');
    instProxyTransport = await req.client.startServiceAndConnect(
      'com.apple.mobile.installation_proxy',
      record,
    );
    const instProxy = new InstallationProxyClient(toByteTransport(instProxyTransport));
    req.log('refresh: browsing installed apps…');
    const raw = await instProxy.browse();
    const apps: InstalledAppInfo[] = [];
    for (const entry of raw) {
      const bundleId = entry['CFBundleIdentifier'];
      if (typeof bundleId !== 'string' || bundleId.length === 0) continue;
      const displayNameRaw = entry['CFBundleDisplayName'];
      apps.push({
        bundleId,
        displayName:
          typeof displayNameRaw === 'string' && displayNameRaw.length > 0
            ? displayNameRaw
            : bundleId,
        shortVersion:
          typeof entry['CFBundleShortVersionString'] === 'string'
            ? (entry['CFBundleShortVersionString'] as string)
            : undefined,
        version:
          typeof entry['CFBundleVersion'] === 'string'
            ? (entry['CFBundleVersion'] as string)
            : undefined,
      });
    }
    // Deterministic order for the UI.
    apps.sort((a, b) => a.displayName.localeCompare(b.displayName));
    req.log(`refresh: found ${apps.length} installed app(s)`);
    return apps;
  } finally {
    if (instProxyTransport) {
      try {
        instProxyTransport.close();
      } catch {
        /* ignore */
      }
    }
  }
}

export interface RefreshAppRequest {
  client: WebUsbMuxClient;
  targetUdid: string;
  bundleId: string;
  context: AppleDeveloperContext;
  anisetteData: AnisetteData;
  deviceName?: string;
  log: (msg: string) => void;
}

/**
 * Refreshes one app: re-signs the cached IPA with a fresh provisioning
 * profile, then overwrite-installs it. Throws when no cached IPA exists.
 */
export async function refreshAppFlow(req: RefreshAppRequest): Promise<void> {
  req.log(`refresh: looking up cached IPA for ${req.bundleId}…`);
  const cached = await getCachedIpa(req.bundleId);
  if (!cached) {
    throw new Error(
      'no cached IPA for this app — sign it once from the Sign page first, then refresh will work',
    );
  }
  const ipaFile = new File([cached.data], cached.meta.fileName, {
    type: 'application/octet-stream',
  });
  req.log(`refresh: re-signing ${cached.meta.fileName}…`);
  const { signedFile, context } = await signIpaFlow({
    ipaFile,
    context: req.context,
    anisetteData: req.anisetteData,
    deviceUdid: req.targetUdid,
    deviceName: req.deviceName,
    log: req.log,
  });
  req.log('refresh: installing refreshed build (overwrite)…');
  // The long signing step often drops the USB connection. Re-establish it
  // with reconnect() (uses getDevices, no user gesture needed) before
  // installFlow, which would otherwise hit requestDevice and fail.
  if (!req.client.isTlsUpgraded) {
    req.log('refresh: USB dropped during signing, reconnecting…');
    await req.client.reconnect();
    const rec = loadPairRecordForUdid(req.targetUdid);
    if (!rec) {
      throw new Error(`no stored pairing file for UDID ${req.targetUdid}; pair the device first`);
    }
    await req.client.loadPairRecord(rec);
    if (!req.client.isSessionStarted) {
      await req.client.startSession(rec.hostId, rec.systemBuid);
    }
    await req.client.upgradeToTls(rec);
  }
  await installFlow({
    client: req.client,
    targetUdid: req.targetUdid,
    signedFile,
    log: req.log,
  });
  void context;
  req.log('refresh: done');
}
