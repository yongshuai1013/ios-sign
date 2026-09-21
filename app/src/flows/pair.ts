/**
 * USB pairing flow: WebUSB device picker → usbmuxd handshake → lockdownd
 * `Pair` (with trust-dialog retry driven by the UI) → `StartSession` →
 * local `{UDID}.plist` pairing file.
 */
import { WebUsbMuxClient, PairingPendingError } from '../transport/webusb-mux';
import {
  getOrCreateHostId,
  getOrCreateSystemBuid,
  loadPairRecordForUdid,
  savePairRecordForUdid,
} from '../lib/pair-record';
import { HOST_ID_STORAGE_KEY, SYSTEM_BUID_STORAGE_KEY, saveText } from '../lib/storage';

export interface PairedDeviceInfo {
  udid: string;
  name: string | null;
}

export interface PairContext {
  log: (message: string) => void;
  clientRef: { current: WebUsbMuxClient | null };
  onStateChange: () => void;
  onTrustPending: () => void;
}

export function isPairingDialogPendingError(error: unknown): boolean {
  if (error instanceof PairingPendingError) return true;
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('PairingDialogResponsePending');
}

export async function ensureClientSelected(ctx: PairContext): Promise<WebUsbMuxClient> {
  if (ctx.clientRef.current) return ctx.clientRef.current;

  const client = new WebUsbMuxClient({
    log: ctx.log,
    onTrustPending: ctx.onTrustPending,
  });
  // The browser device picker opens on first use (openAndHandshake).
  ctx.clientRef.current = client;

  ctx.log('webusb pairing client ready (device picker opens on connect)');
  ctx.onStateChange();
  return client;
}

export async function pairDeviceFlow(ctx: PairContext): Promise<PairedDeviceInfo> {
  const client = await ensureClientSelected(ctx);

  const udid = await client.getOrFetchDeviceUdid();
  const name = await client.getOrFetchDeviceName().catch(() => null);

  const hostId = getOrCreateHostId();
  const systemBuid = getOrCreateSystemBuid();

  const storedPair = loadPairRecordForUdid(udid);
  if (storedPair && !client.isPaired) {
    client.loadPairRecord(storedPair);
    saveText(HOST_ID_STORAGE_KEY, storedPair.hostId);
    saveText(SYSTEM_BUID_STORAGE_KEY, storedPair.systemBuid);
    ctx.log(`pair: loaded local pair record for ${udid}`);
  }

  if (!client.isPaired) {
    ctx.log('pair: creating pair record...');
    try {
      const pairResult = await client.pairDevice(hostId, systemBuid);
      savePairRecordForUdid(udid, pairResult);
      ctx.log('pair: success');
    } catch (error) {
      if (isPairingDialogPendingError(error)) {
        ctx.onTrustPending();
      }
      throw error;
    }
  }

  if (!client.isSessionStarted) {
    const session = await client.startSession(hostId, systemBuid);
    ctx.log(`pair: session ready, ssl=${String(session.enableSessionSSL)}`);
  }

  ctx.log(`pair: udid=${udid}${name ? ` (${name})` : ''}`);
  return { udid, name };
}
