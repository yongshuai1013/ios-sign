/**
 * Browser pairing client built on the repo's own USB-mux stack.
 *
 * - `WebUsbMux` (`@pairing/webusb-mux`) speaks the real usbmux packet/TCP
 *   protocol over WebUSB bulk endpoints and yields per-service
 *   `ByteTransport` connections.
 * - This module adapts those connections to the `Transport` interface used
 *   by `LockdownClient` and exposes the pairing-oriented API the UI needs
 *   (mirroring the original frontend's `DirectUsbMuxClient` surface).
 * - After `StartSession` returns `EnableSessionSSL`, `upgradeToTls()`
 *   performs the mTLS upgrade with the pairing-file client certificate
 *   using the repo's dependency-free TypeScript TLS 1.2 client
 *   (`@pairing/tls-client`), then rebuilds the lockdownd client over the
 *   encrypted transport.
 */
import {
  WebUsbMux,
  LOCKDOWN_PORT,
  type ByteTransport as MuxByteTransport,
} from '@pairing/webusb-mux';
import type { Transport } from '@pairing/usbmuxd';
import {
  LockdownClient,
  PairingPendingError,
  pairDevice,
  pairRecordToDict,
} from '@pairing/lockdown';
import { PairingFile } from '@pairing/pairing-file';
import {
  tlsConnect,
  pemToDer,
  parseRsaPrivateKey,
  type TlsTransport,
} from '@pairing/tls-client';

export { PairingPendingError, LOCKDOWN_PORT };

export class WebUsbNotSupportedError extends Error {
  constructor() {
    super(
      'WebUSB is not available in this browser. ' +
        'Use a Chromium-based browser (Chrome / Edge) over HTTPS or localhost.',
    );
    this.name = 'WebUsbNotSupportedError';
  }
}

/** Adapts the mux `ByteTransport` (`readExact`) to the `Transport` (`read`) interface. */
function toTransport(muxTransport: MuxByteTransport): Transport {
  return {
    write: (data: Uint8Array) => muxTransport.write(data),
    read: (n: number) => muxTransport.readExact(n),
    close: () => muxTransport.close(),
  };
}

export interface WebUsbMuxCallbacks {
  log: (message: string) => void;
  onTrustPending?: () => void;
}

/**
 * High-level client: WebUSB mux handshake, then lockdownd sessions.
 */
export class WebUsbMuxClient {
  private mux: WebUsbMux | null = null;
  private lockdown: LockdownClient | null = null;
  /** Raw (pre-TLS) lockdownd byte transport; kept for the TLS upgrade. */
  private lockdownRaw: Transport | null = null;
  private lockdownTls: TlsTransport | null = null;
  private connectedUdid: string | null = null;
  private sessionStarted = false;
  private pairedUdid: string | null = null;

  constructor(private readonly cb: WebUsbMuxCallbacks) {}

  get isLockdownConnected(): boolean {
    return this.lockdown !== null;
  }

  get isPaired(): boolean {
    return this.pairedUdid !== null;
  }

  get isSessionStarted(): boolean {
    return this.sessionStarted;
  }

  /** Lightweight heartbeat to keep the USB connection alive during long
   * operations (e.g. signing). Throws if the connection is dead. */
  async ping(): Promise<void> {
    const lockdown = this.lockdown;
    if (!lockdown) throw new Error('ping: lockdownd not connected');
    await lockdown.getValue();
  }

  /** Drops the current lockdownd connection (keeping the MUX) and opens a
   * fresh one. Used before install to avoid a stale lockdownd session that
   * confuses the TLS handshake. */
  async resetLockdown(): Promise<LockdownClient> {
    this.cb.log('lockdownd: resetting connection...');
    // Close existing lockdownd transports (best effort).
    const tls = this.lockdownTls;
    this.lockdownTls = null;
    if (tls) {
      try { tls.close(); } catch { /* ignore */ }
    }
    const raw = this.lockdownRaw;
    this.lockdownRaw = null;
    this.lockdown = null;
    if (raw) {
      try { raw.close(); } catch { /* ignore */ }
    }
    this.sessionStarted = false;
    // Open a fresh lockdownd connection over the existing MUX.
    return this.connectLockdown();
  }

  get udid(): string | null {
    return this.connectedUdid;
  }

  private assertWebUsb(): void {
    if (typeof navigator === 'undefined' || !('usb' in navigator) || !navigator.usb) {
      throw new WebUsbNotSupportedError();
    }
  }

  /** Device picker + mux handshake. */
  async openAndHandshake(): Promise<WebUsbMux> {
    this.assertWebUsb();
    if (this.mux) return this.mux;
    const mux = await WebUsbMux.requestDevice({ log: this.cb.log });
    const version = await mux.handshake();
    this.cb.log(`mux: handshake complete (version ${version})`);
    this.mux = mux;
    return mux;
  }

  /**
   * Drops the current MUX + lockdownd state and reconnects to the
   * already-authorized device without user interaction. Used when the USB
   * connection drops during a long operation (e.g. signing).
   */
  async reconnect(): Promise<void> {
    this.assertWebUsb();
    this.cb.log('usb: reconnecting to authorized device...');
    // Tear down old state (best effort).
    try { this.close(); } catch { /* ignore */ }
    // Wait for the old USB device state to settle before reopening.
    // Without this, claimInterface() fails with "An operation that changes
    // the device state is in progress".
    await new Promise((r) => setTimeout(r, 2000));
    const mux = await WebUsbMux.reconnect({ log: this.cb.log });
    this.cb.log(`mux: reconnected (version ${mux.negotiatedVersion})`);
    this.mux = mux;
    // Reopen lockdownd; the caller will StartSession / upgradeToTls as needed.
    await this.connectLockdown();
    this.cb.log('usb: reconnect complete');
  }

  /** Opens a TCP-over-mux connection to lockdownd (port 62078). */
  async connectLockdown(): Promise<LockdownClient> {
    if (this.lockdown) return this.lockdown;
    const mux = await this.openAndHandshake();
    const conn = await mux.connectLockdown();
    const raw = toTransport(conn);
    this.lockdownRaw = raw;
    this.lockdown = new LockdownClient(raw, 'sideimpactor');
    this.cb.log('mux: lockdownd connected');
    return this.lockdown;
  }

  async getOrFetchDeviceUdid(): Promise<string> {
    if (this.connectedUdid) return this.connectedUdid;
    const lockdown = await this.connectLockdown();
    const udid = await lockdown.getValue('UniqueDeviceID');
    if (typeof udid !== 'string' || udid.length === 0) {
      throw new Error('lockdownd did not return UniqueDeviceID');
    }
    this.connectedUdid = udid;
    return udid;
  }

  async getOrFetchDeviceName(): Promise<string | null> {
    try {
      const lockdown = await this.connectLockdown();
      const name = await lockdown.getValue('DeviceName');
      return typeof name === 'string' ? name : null;
    } catch {
      return null;
    }
  }

  /**
   * Loads a previously stored pairing file so a known device can skip the
   * trust dialog on reconnect.
   */
  loadPairRecord(record: PairingFile): void {
    this.pairedUdid = record.udid ?? this.connectedUdid;
    this.cb.log(`mux: loaded stored pair record${this.pairedUdid ? ` for ${this.pairedUdid}` : ''}`);
  }

  /**
   * Single-shot pairing attempt (no retry loop): throws
   * {@link PairingPendingError} when the user must tap "Trust" on the
   * device — the caller (UI) surfaces the trust dialog and retries.
   * Returns the on-disk `{UDID}.plist`-compatible {@link PairingFile}.
   */
  async pairDevice(hostId: string, systemBuid: string): Promise<PairingFile> {
    const lockdown = await this.connectLockdown();
    const udid = await this.getOrFetchDeviceUdid();

    const devicePublicKey = await lockdown.getValue('DevicePublicKey');
    if (!(devicePublicKey instanceof Uint8Array)) {
      throw new Error('lockdownd did not return DevicePublicKey data');
    }
    const wifiMac = await lockdown.getValue('WiFiAddress');
    if (typeof wifiMac !== 'string') {
      throw new Error('lockdownd did not return WiFiAddress');
    }

    this.cb.log('pair: generating certificates, requesting Pair...');
    const record = await pairDevice(lockdown, devicePublicKey, wifiMac, hostId, systemBuid, undefined, {
      maxAttempts: 1,
      hostName: 'sideimpactor',
      onTrustPending: () => this.cb.onTrustPending?.(),
    });

    const file = toPairingFile(record, udid);
    this.pairedUdid = udid;
    this.cb.log('pair: success');
    return file;
  }

  /** `StartSession`; the mTLS upgrade must be done by the caller. */
  async startSession(hostId: string, systemBuid: string): Promise<{ sessionId: string; enableSessionSSL?: boolean }> {
    const lockdown = await this.connectLockdown();
    const session = await lockdown.startSession(hostId, systemBuid);
    this.sessionStarted = true;
    this.cb.log(`pair: session ${session.sessionId} ready (ssl=${String(session.enableSessionSSL)})`);
    return session;
  }

  /**
   * Upgrades the current lockdownd stream to TLS with the pairing-file
   * client certificate (mTLS), as required after `StartSession` returns
   * `EnableSessionSSL`.
   *
   * The pairing file's `HostCertificate`/`HostPrivateKey` become the client
   * identity; the device certificate is not verified (mirrors
   * libimobiledevice/idevice). The lockdownd client is rebuilt over the
   * encrypted transport, keeping the session id. Returns the TLS-upgraded
   * `LockdownClient` (also installed as the client's lockdownd client, so
   * `startService()` afterwards goes over TLS).
   */
  async upgradeToTls(record: PairingFile): Promise<LockdownClient> {
    if (this.lockdownTls) return this.lockdown!;
    const raw = this.lockdownRaw;
    if (!raw || !this.lockdown) {
      throw new Error('upgradeToTls: lockdownd is not connected');
    }
    this.cb.log('tls: upgrading lockdownd session to TLS (mTLS)…');
    const tls = await tlsConnect(raw, {
      clientCertificateDer: pemToDer(record.hostCertificate).der,
      clientPrivateKey: parseRsaPrivateKey(record.hostPrivateKey),
      onLog: (m) => this.cb.log(m),
    });
    this.lockdownTls = tls;
    // The TLS transport owns the raw transport now; drop our reference so
    // close() doesn't double-close the underlying mux connection.
    this.lockdownRaw = null;
    const upgraded = new LockdownClient(tls, 'sideimpactor');
    upgraded.adoptSessionId(this.lockdown.sessionIdOrNull);
    this.lockdown = upgraded;
    this.cb.log('tls: lockdownd session is now encrypted');
    return upgraded;
  }

  /** Whether the lockdownd session has been TLS-upgraded. */
  get isTlsUpgraded(): boolean {
    return this.lockdownTls !== null;
  }

  async startService(serviceName: string): Promise<{ port: number; enableServiceSSL?: boolean }> {
    const lockdown = await this.connectLockdown();
    return lockdown.startService(serviceName);
  }

  /**
   * Opens a raw TCP-over-mux connection to a device port, e.g. a port
   * returned by `startService`. The caller owns the returned transport.
   */
  async connectService(port: number): Promise<Transport> {
    const mux = await this.openAndHandshake();
    const conn = await mux.connect(port);
    return toTransport(conn);
  }

  /**
   * `StartService` over the (TLS-upgraded) lockdownd session, then opens a
   * mux connection to the returned port. When the service response asks for
   * SSL (`EnableServiceSSL`), the service transport is TLS-upgraded with
   * the pairing-file client certificate as well. The caller owns the
   * returned transport and must close it when done.
   */
  async startServiceAndConnect(
    serviceName: string,
    record: PairingFile,
  ): Promise<Transport> {
    const { port, enableServiceSSL } = await this.startService(serviceName);
    this.cb.log(`mux: service ${serviceName} on port ${port} (ssl=${String(!!enableServiceSSL)})`);
    const raw = await this.connectService(port);
    if (!enableServiceSSL) return raw;
    this.cb.log(`tls: upgrading ${serviceName} to TLS…`);
    const tls = await tlsConnect(raw, {
      clientCertificateDer: pemToDer(record.hostCertificate).der,
      clientPrivateKey: parseRsaPrivateKey(record.hostPrivateKey),
      onLog: (m) => this.cb.log(m),
    });
    return tls;
  }

  close(): void {
    this.lockdown = null;
    this.lockdownRaw = null;
    const tls = this.lockdownTls;
    this.lockdownTls = null;
    this.sessionStarted = false;
    const mux = this.mux;
    this.mux = null;
    // Closing the TLS transport closes the underlying mux connection.
    if (tls) {
      try {
        tls.close();
      } catch {
        /* best effort */
      }
    }
    if (mux) {
      void mux.close().catch(() => undefined);
    }
  }
}

/** Builds the on-disk `{UDID}.plist`-compatible PairingFile from a finished pair record. */
function toPairingFile(
  record: {
    hostId: string;
    systemBuid: string;
    hostCertificate: Uint8Array;
    hostPrivateKey: Uint8Array;
    rootCertificate: Uint8Array;
    rootPrivateKey: Uint8Array;
    deviceCertificate: Uint8Array;
    devicePublicKey: Uint8Array;
    wifiMacAddress: string;
    escrowBag?: Uint8Array;
  },
  udid: string,
): PairingFile {
  const dict = pairRecordToDict(record);
  // `pairRecordToDict` omits HostPrivateKey for the wire request; the
  // on-disk file must include it.
  dict['HostPrivateKey'] = record.hostPrivateKey.slice();
  dict['UDID'] = udid;
  // Keep the EscrowBag when the device sent one (matches idevice's
  // PairingFile; used by backup tooling).
  if (record.escrowBag) dict['EscrowBag'] = record.escrowBag.slice();
  return PairingFile.fromValue(dict);
}
