/**
 * Install flow: upgrades lockdownd to TLS (mTLS after `StartSession`),
 * stages a signed IPA via AFC (`PublicStaging`) and installs it through
 * `installation_proxy`.
 *
 * This is the real install path — no mocks. It has not been verified
 * end-to-end against a physical iPhone yet.
 */
import { AfcClient, type ByteTransport } from '@pairing/afc';
import { InstallationProxyClient, installIpa } from '@pairing/installation-proxy';
import type { Transport } from '@pairing/usbmuxd';
import type { WebUsbMuxClient } from '../transport/webusb-mux';
import { loadPairRecordForUdid, getOrCreateHostId, getOrCreateSystemBuid } from '../lib/pair-record';

export class InstallUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InstallUnavailableError';
  }
}

export interface InstallRequest {
  client: WebUsbMuxClient;
  /** UDID of the install target; used to load the stored pairing file. */
  targetUdid: string;
  signedFile: File;
  log: (msg: string) => void;
}

/** Adapts the `Transport` (`read`) interface to `ByteTransport` (`readExact`). */
function toByteTransport(t: Transport): ByteTransport {
  return {
    write: (data: Uint8Array) => t.write(data),
    readExact: (n: number) => t.read(n),
    close: () => t.close(),
  };
}

export async function installFlow(req: InstallRequest): Promise<void> {
  req.log('install: preparing...');
  const bytes = new Uint8Array(await req.signedFile.arrayBuffer());
  const record = loadPairRecordForUdid(req.targetUdid);
  if (!record) {
    throw new InstallUnavailableError(
      `no stored pairing file for UDID ${req.targetUdid}; pair the device first`,
    );
  }

  // The service ports are only reachable over the encrypted session.
  if (!req.client.isTlsUpgraded) {
    req.log('install: upgrading lockdownd to TLS…');
    try {
      // Ensure lockdownd is connected and session is started before TLS upgrade.
      // (A fresh client from retry logic may not have connected yet.)
      if (!req.client.isSessionStarted) {
        req.log('install: connecting to lockdownd...');
        await req.client.connectLockdown();
        req.log('install: starting session...');
        await req.client.startSession(record.hostId, record.systemBuid);
      }
      await req.client.upgradeToTls(record);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // USB often drops during the (long) signing step. Surface a clear
      // message instead of the raw transport error.
      if (msg.includes('not connected') || msg.includes('transfer')) {
        throw new InstallUnavailableError(
          'USB connection lost during signing. Unplug and reconnect the iPhone, then tap Install again.',
        );
      }
      throw e;
    }
  }

  let afcTransport: Transport | null = null;
  let instProxyTransport: Transport | null = null;
  try {
    req.log('install: starting com.apple.afc…');
    afcTransport = await req.client.startServiceAndConnect('com.apple.afc', record);
    req.log('install: starting com.apple.mobile.installation_proxy…');
    instProxyTransport = await req.client.startServiceAndConnect(
      'com.apple.mobile.installation_proxy',
      record,
    );

    const afc = new AfcClient(toByteTransport(afcTransport));
    const instProxy = new InstallationProxyClient(toByteTransport(instProxyTransport));
    await installIpa(afc, instProxy, bytes, req.signedFile.name, req.log);
    req.log('install: done');
  } finally {
    // Best-effort cleanup of the service connections.
    for (const t of [instProxyTransport, afcTransport]) {
      if (t) {
        try {
          t.close();
        } catch {
          /* ignore */
        }
      }
    }
  }
}
