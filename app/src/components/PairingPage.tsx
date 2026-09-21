/**
 * Pairing page: USB (Lockdown) and Remote (Wi-Fi) device pairing, plus
 * pairing-file import/export.
 *
 * - USB: pick a device over WebUSB → lockdownd `Pair` (tap "Trust" on the
 *   device when asked) → `{UDID}.plist` saved locally and offered as a
 *   download, compatible with idevice_pair / libimobiledevice tooling.
 * - Remote: enter the device's IP/hostname + the 6-digit code shown on the
 *   device → pair-verify / pair-setup (SRP) → `pairingFile.plist` download.
 * - Import: drop a previously exported pairing file to restore it.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Button } from './ui/Button';
import { Field } from './ui/Field';
import { Chip } from './ui/Chip';
import { Stepper } from './Stepper';
import type { WebUsbMuxClient } from '../transport/webusb-mux';
import { WebUsbNotSupportedError } from '../transport/webusb-mux';
import { isPairingDialogPendingError, pairDeviceFlow, type PairedDeviceInfo } from '../flows/pair';
import { remotePairSetupFlow, RemotePairingUnavailableError } from '../flows/remote-pair';
import {
  deletePairRecordForUdid,
  deleteRemotePairingFile,
  listKnownDeviceUdids,
  loadPairRecordForUdid,
  loadRemotePairingFile,
  savePairRecordForUdid,
  saveRemotePairingFile,
} from '../lib/pair-record';
import { PairingFile, RpPairingFile } from '@pairing/pairing-file';
import { downloadBytes, formatError } from '../lib/ids';

type Mode = 'usb' | 'remote';
type UsbStatus = 'idle' | 'working' | 'trust-pending' | 'paired' | 'error';

interface PairingPageProps {
  log: (message: string) => void;
  clientRef: { current: WebUsbMuxClient | null };
  onPairedDevice: (info: PairedDeviceInfo) => void;
}

const webUsbSupported = typeof navigator !== 'undefined' && 'usb' in navigator;

export function PairingPage({ log, clientRef, onPairedDevice }: PairingPageProps) {
  const [mode, setMode] = useState<Mode>('usb');

  // USB state
  const [usbStatus, setUsbStatus] = useState<UsbStatus>('idle');
  const [usbError, setUsbError] = useState<string | null>(null);
  const [pairedUdid, setPairedUdid] = useState<string | null>(null);
  const [recordsVersion, setRecordsVersion] = useState(0);

  // Remote state
  const [deviceHost, setDeviceHost] = useState('');
  const [pin, setPin] = useState('');
  const [wispUrl, setWispUrl] = useState('');
  const [remoteBusy, setRemoteBusy] = useState(false);
  const [remoteError, setRemoteError] = useState<string | null>(null);
  const [remotePaired, setRemotePaired] = useState(false);
  const [remoteVersion, setRemoteVersion] = useState(0);

  // Import state
  const [importError, setImportError] = useState<string | null>(null);
  const [importOk, setImportOk] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const knownUdids = useMemo(() => listKnownDeviceUdids(), [recordsVersion]);
  const hasRemoteFile = useMemo(() => loadRemotePairingFile() !== null, [remoteVersion]);

  useEffect(() => {
    setRemotePaired(hasRemoteFile);
  }, [hasRemoteFile]);

  const refreshRecords = useCallback(() => setRecordsVersion((v) => v + 1), []);

  // ---------- USB pairing ----------
  const runUsbPair = useCallback(async () => {
    setUsbError(null);
    setUsbStatus('working');
    log('pair: starting USB pairing...');
    try {
      const info = await pairDeviceFlow({
        log,
        clientRef,
        onStateChange: () => {},
        onTrustPending: () => {
          setUsbStatus('trust-pending');
          log('pair: waiting for trust confirmation on device');
        },
      });
      setPairedUdid(info.udid);
      setUsbStatus('paired');
      refreshRecords();
      onPairedDevice(info);
      log(`pair: paired ${info.udid}`);
    } catch (error) {
      if (isPairingDialogPendingError(error)) {
        setUsbStatus('trust-pending');
        setUsbError(null);
      } else {
        setUsbStatus('error');
        const message = error instanceof WebUsbNotSupportedError ? error.message : formatError(error);
        setUsbError(message);
        log(`pair failed: ${message}`);
      }
    }
  }, [clientRef, log, onPairedDevice, refreshRecords]);

  const handleDownloadUsb = useCallback(
    (udid: string) => {
      const record = loadPairRecordForUdid(udid);
      if (!record) {
        log(`pair: no stored record for ${udid}`);
        return;
      }
      downloadBytes(`${udid}.plist`, record.serialize(), 'application/x-plist');
      log(`pair: exported ${udid}.plist`);
    },
    [log],
  );

  const handleDeleteUsb = useCallback(
    (udid: string) => {
      deletePairRecordForUdid(udid);
      refreshRecords();
      log(`pair: deleted local record for ${udid}`);
    },
    [log, refreshRecords],
  );

  // ---------- Remote pairing ----------
  const runRemotePair = useCallback(async () => {
    const host = deviceHost.trim();
    const code = pin.trim();
    if (!host || !code) {
      setRemoteError('Please enter the device host and the 6-digit pairing code.');
      return;
    }
    setRemoteError(null);
    setRemoteBusy(true);
    log('remote-pair: starting...');
    try {
      const file = await remotePairSetupFlow({ deviceHost: host, pin: code, wispUrl: wispUrl.trim(), log });
      saveRemotePairingFile(file);
      setRemoteVersion((v) => v + 1);
      setRemotePaired(true);
      downloadBytes('pairingFile.plist', file.toBytes(), 'application/x-plist');
      log('remote-pair: pairingFile.plist saved + downloaded');
    } catch (error) {
      const message =
        error instanceof RemotePairingUnavailableError ? error.message : formatError(error);
      setRemoteError(message);
      log(`remote-pair failed: ${message}`);
    } finally {
      setRemoteBusy(false);
    }
  }, [deviceHost, pin, wispUrl, log]);

  const handleDownloadRemote = useCallback(() => {
    const file = loadRemotePairingFile();
    if (!file) return;
    downloadBytes('pairingFile.plist', file.toBytes(), 'application/x-plist');
    log('remote-pair: exported pairingFile.plist');
  }, [log]);

  const handleDeleteRemote = useCallback(() => {
    deleteRemotePairingFile();
    setRemoteVersion((v) => v + 1);
    setRemotePaired(false);
    log('remote-pair: deleted local remote pairing file');
  }, [log]);

  // ---------- Import ----------
  const handleImportFile = useCallback(
    async (file: File | null) => {
      setImportError(null);
      setImportOk(null);
      if (!file) return;
      try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        // Try USB lockdown pairing file first.
        try {
          const record = PairingFile.fromBytes(bytes);
          let udid: string | undefined = record.udid;
          if (!udid) {
            const match = file.name.match(/^([0-9a-fA-F-]{20,})\.plist$/);
            udid = match?.[1] ?? undefined;
          }
          if (!udid) {
            throw new Error('could not determine the device UDID (file has no UDID field and the filename is not {UDID}.plist)');
          }
          record.udid = udid;
          savePairRecordForUdid(udid, record);
          refreshRecords();
          setImportOk(`Imported USB pairing file for ${udid}`);
          log(`pair: imported USB pairing file for ${udid}`);
          return;
        } catch (usbError) {
          // Fall through to remote format.
          void usbError;
        }
        const rpFile = RpPairingFile.fromBytes(bytes);
        saveRemotePairingFile(rpFile);
        setRemoteVersion((v) => v + 1);
        setRemotePaired(true);
        setImportOk(`Imported remote pairing file (id ${rpFile.identifier.slice(0, 8)}…)`);
        log('pair: imported remote pairing file');
      } catch (error) {
        const message = `Not a recognized pairing file: ${formatError(error)}`;
        setImportError(message);
        log(`pair: import failed — ${message}`);
      }
    },
    [log, refreshRecords],
  );

  const usbSteps = [
    { label: 'Connect', state: usbStatus === 'idle' || usbStatus === 'error' ? 'active' : 'done' },
    { label: 'Trust', state: usbStatus === 'trust-pending' ? 'active' : usbStatus === 'paired' ? 'done' : 'idle' },
    { label: 'Paired', state: usbStatus === 'paired' ? 'done' : 'idle' },
  ] as { label: string; state: 'idle' | 'active' | 'done' }[];

  return (
    <section className="space-y-6 anim-in">
      <div>
        <h1 className="text-[clamp(1.75rem,3.5vw,2.1rem)] font-semibold tracking-tight text-ink">Pairing</h1>
        <p className="mt-2 text-[14.5px] text-muted">
          Pair a device over USB or Wi-Fi. Pairing files are stored locally and can be exported for use with
          other tools.
        </p>
      </div>

      <nav className="seg w-fit" aria-label="Pairing mode">
        <button type="button" className="seg-btn" data-active={mode === 'usb'} onClick={() => setMode('usb')}>
          USB
        </button>
        <button type="button" className="seg-btn" data-active={mode === 'remote'} onClick={() => setMode('remote')}>
          Remote (Wi-Fi)
        </button>
      </nav>

      {mode === 'usb' ? (
        <div className="space-y-5">
          <Stepper steps={usbSteps} />

          {!webUsbSupported && (
            <p className="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
              WebUSB is not available in this browser. Use Chrome or Edge over HTTPS / localhost.
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              busy={usbStatus === 'working'}
              busyLabel={usbStatus === 'trust-pending' ? 'Waiting for trust…' : 'Pairing…'}
              disabled={!webUsbSupported || usbStatus === 'working'}
              onClick={() => void runUsbPair()}
              className="min-w-[180px]"
            >
              {usbStatus === 'trust-pending' ? 'I Tapped Trust — Retry' : pairedUdid ? 'Pair Again' : 'Connect & Pair Device'}
            </Button>
            {usbStatus === 'trust-pending' && (
              <Chip tone="accent">Tap “Trust” on the device, then retry</Chip>
            )}
            {usbStatus === 'paired' && pairedUdid && <Chip tone="success">Paired: {pairedUdid.slice(0, 12)}…</Chip>}
          </div>

          {usbError && (
            <p className="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
              {usbError}
            </p>
          )}

          <div>
            <h2 className="mb-2 text-[13px] font-semibold text-ink">Stored USB pairing files</h2>
            {knownUdids.length === 0 ? (
              <p className="text-[12.5px] text-muted">No paired devices yet.</p>
            ) : (
              <div className="space-y-2">
                {knownUdids.map((udid) => (
                  <div key={udid} className="acct-row" data-active="false">
                    <div className="flex items-center justify-between gap-3">
                      <p className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">{udid}</p>
                      <div className="flex shrink-0 items-center gap-1.5">
                        <Button size="sm" variant="ghost" onClick={() => handleDownloadUsb(udid)}>
                          Export
                        </Button>
                        <button
                          type="button"
                          onClick={() => handleDeleteUsb(udid)}
                          className="flex h-7 w-7 items-center justify-center rounded-md text-subtle transition-colors hover:bg-[var(--color-danger-soft)] hover:text-[var(--color-danger)]"
                          title="Delete pairing file"
                        >
                          <svg className="h-4 w-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                            <path d="M4 4l8 8M12 4l-8 8" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Device host or IP"
              placeholder="192.168.1.10"
              value={deviceHost}
              onChange={(e) => setDeviceHost(e.target.value)}
              hint="The iPhone/iPad must be on the same network with Wi-Fi sync enabled."
            />
            <Field
              label="Pairing code"
              placeholder="6-digit code"
              inputMode="numeric"
              maxLength={6}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
              hint="Shown on the device when pairing (Settings → General → VPN & Device Management)."
            />
          </div>
          <Field
            label="WISP proxy URL (optional)"
            placeholder="wss://your-worker.workers.dev"
            value={wispUrl}
            onChange={(e) => setWispUrl(e.target.value)}
            hint="Browsers can't open raw TCP sockets; the proxy bridges WebSocket → device TCP. Defaults to VITE_WISP_URL."
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              busy={remoteBusy}
              busyLabel="Pairing…"
              disabled={remoteBusy}
              onClick={() => void runRemotePair()}
              className="min-w-[180px]"
            >
              Pair over Wi-Fi
            </Button>
            {remotePaired && <Chip tone="success">Remote pairing file stored</Chip>}
          </div>

          {remoteError && (
            <p className="rounded-lg border border-danger/30 bg-danger-soft px-3 py-2 text-[12.5px] text-danger">
              {remoteError}
            </p>
          )}

          {hasRemoteFile && (
            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="ghost" onClick={handleDownloadRemote}>
                Export pairingFile.plist
              </Button>
              <Button size="sm" variant="ghost" onClick={handleDeleteRemote}>
                Delete
              </Button>
            </div>
          )}
        </div>
      )}

      <div className="border-t border-border pt-5">
        <h2 className="mb-2 text-[13px] font-semibold text-ink">Import pairing file</h2>
        <p className="mb-3 text-[12.5px] text-muted">
          Restore a previously exported <code className="font-mono">{'{UDID}.plist'}</code> or{' '}
          <code className="font-mono">pairingFile.plist</code>.
        </p>
        <input
          ref={fileInputRef}
          type="file"
          accept=".plist,application/x-plist,text/xml"
          className="hidden"
          onChange={(e) => {
            void handleImportFile(e.target.files?.[0] ?? null);
            e.target.value = '';
          }}
        />
        <Button variant="ghost" onClick={() => fileInputRef.current?.click()}>
          Choose pairing file…
        </Button>
        {importOk && <p className="mt-2 text-[12.5px] text-[var(--color-success)]">{importOk}</p>}
        {importError && <p className="mt-2 text-[12.5px] text-danger">{importError}</p>}
      </div>

      <details className="rounded-lg border border-border px-4 py-3">
        <summary className="cursor-pointer text-[13px] font-medium text-ink">Advanced: inspect raw pairing data</summary>
        <div className="mt-3 space-y-2">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              const rec = pairedUdid ? loadPairRecordForUdid(pairedUdid) : null;
              log(`pair: ${rec ? rec.toDebugString() : 'no USB record loaded'}`);
              const rp = loadRemotePairingFile();
              log(`remote-pair: ${rp ? rp.toDebugString() : 'no remote file stored'}`);
            }}
          >
            Log debug summary (no secrets)
          </Button>
          <p className="text-[11.5px] text-subtle">
            Only non-secret metadata is logged; private keys are never printed.
          </p>
        </div>
      </details>
    </section>
  );
}
