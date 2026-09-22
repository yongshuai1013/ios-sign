/**
 * lockdownd client — TypeScript port of the pairing-relevant subset of the
 * Rust `idevice` crate's `services/lockdown.rs`:
 * `get_value`, `pair` (`build_pair_request` + the trust-retry loop),
 * `validate_pair`, `start_session`, `stop_session`, `start_service`, `unpair`.
 *
 * Runs on a {@link PlistSocket} (or any {@link Transport}) already connected
 * to the device's lockdown port (62078, usually via usbmuxd `Connect`).
 *
 * Wire format (mirrors `Idevice::send_plist` / `read_plist_value`):
 *   u32 big-endian length + XML plist body.
 *
 * NOTE on TLS: like the Rust original, `startSession` only performs the
 * `StartSession` handshake. When the response sets `EnableSessionSSL`, the
 * caller must upgrade `socket.transport` to TLS itself (mTLS with the
 * pairing record's certificates); this module deliberately does not bundle
 * a TLS stack so it stays runnable in a pure browser context.
 */

import { PlistSocket, copyBytes, type Transport } from './usbmuxd.js';
import { generateCertificates } from './ca.js';

/* ------------------------------------------------------------------ */
/* Pair record                                                          */
/* ------------------------------------------------------------------ */

/**
 * Host-side lockdown pairing record. Serializes to the `PairRecord`
 * dictionary of the lockdownd `Pair` request and to the on-disk
 * `{UDID}.plist` pairing file format.
 *
 * Certificate/key fields hold PEM bytes (matching `idevice`'s `CaReturn`,
 * whose fields are PEM-encoded); `devicePublicKey` holds the raw
 * `DevicePublicKey` bytes returned by `GetValue` (PKCS#1 PEM).
 */
export interface LockdownPairRecord {
  hostId: string;
  systemBuid: string;
  /** Host certificate (PEM bytes). Doubles as the root CA certificate. */
  hostCertificate: Uint8Array;
  /** Host/CA private key (PEM bytes). Added only after the device accepts. */
  hostPrivateKey: Uint8Array;
  /** Root CA certificate (PEM bytes). */
  rootCertificate: Uint8Array;
  /** Root CA private key (PEM bytes). */
  rootPrivateKey: Uint8Array;
  /** Device certificate issued by the host CA (PEM bytes). */
  deviceCertificate: Uint8Array;
  /** Raw `DevicePublicKey` bytes from `GetValue`. */
  devicePublicKey: Uint8Array;
  wifiMacAddress: string;
  /** Escrow bag returned by the device on successful pairing (optional). */
  escrowBag?: Uint8Array;
}

/**
 * Serializes a {@link LockdownPairRecord} to the `PairRecord` dictionary
 * sent inside the lockdownd `Pair` request.
 *
 * Mirrors Rust `build_pair_request`: `HostPrivateKey` is deliberately
 * omitted from the outgoing request — it is merged into the local record
 * only after the device accepts the pairing.
 */
export function pairRecordToDict(record: LockdownPairRecord): Record<string, unknown> {
  return {
    DevicePublicKey: copyBytes(record.devicePublicKey),
    DeviceCertificate: copyBytes(record.deviceCertificate),
    HostCertificate: copyBytes(record.hostCertificate),
    HostID: record.hostId,
    RootCertificate: copyBytes(record.rootCertificate),
    RootPrivateKey: copyBytes(record.rootPrivateKey),
    WiFiMACAddress: record.wifiMacAddress,
    SystemBUID: record.systemBuid,
  };
}

/* ------------------------------------------------------------------ */
/* Errors                                                               */
/* ------------------------------------------------------------------ */

/** Pairing error codes surfaced by lockdownd's `Error` field. */
export type LockdownPairingErrorCode =
  | 'PairingDialogResponsePending'
  | 'UserDeniedPairing'
  | 'PasswordProtected';

/** Generic lockdownd failure. */
export class LockdownError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'LockdownError';
  }
}

/**
 * Thrown by {@link LockdownClient.pair} when the device reports
 * `PairingDialogResponsePending` — i.e. the user has not tapped "Trust"
 * yet and the attempt must be retried. Use {@link pairDevice} for a flow
 * that retries automatically, or drive your own "Trust This Computer" UI.
 */
export class PairingPendingError extends LockdownError {
  constructor(message = 'PairingDialogResponsePending: user has not trusted this host yet') {
    super('PairingDialogResponsePending', message);
    this.name = 'PairingPendingError';
  }
}

const PAIRING_ERROR_CODES: Record<string, LockdownPairingErrorCode> = {
  PairingDialogResponsePending: 'PairingDialogResponsePending',
  UserDeniedPairing: 'UserDeniedPairing',
  PasswordProtected: 'PasswordProtected',
};

/**
 * Maps a lockdownd response dictionary carrying an `Error` field to a thrown
 * error, mirroring Rust `read_plist`. Returns `null` when there is no error.
 */
function errorFromResponse(dict: Record<string, unknown>): LockdownError | null {
  const raw = dict['Error'];
  if (raw === undefined || raw === null) return null;

  let kind: string;
  if (typeof raw === 'string') {
    kind = raw;
  } else if (typeof raw === 'number') {
    // Rust falls back to the `ErrorString` field for integer errors.
    kind = typeof dict['ErrorString'] === 'string' ? (dict['ErrorString'] as string) : String(raw);
  } else {
    return new LockdownError('UnexpectedResponse', 'error value is not a string or integer');
  }

  const desc = dict['ErrorDescription'];
  const message = typeof desc === 'string' ? `${kind} (${desc})` : kind;
  if (kind === 'PairingDialogResponsePending') {
    return new PairingPendingError(`lockdownd reported error: ${message}`);
  }
  const code: string = PAIRING_ERROR_CODES[kind] ?? 'Unknown';
  return new LockdownError(code, `lockdownd reported error: ${message}`);
}

/* ------------------------------------------------------------------ */
/* Client                                                               */
/* ------------------------------------------------------------------ */

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('aborted'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new Error('aborted'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export class LockdownClient {
  private readonly socket: PlistSocket;
  private sessionId: string | null = null;

  /**
   * @param socketOrTransport An already-connected {@link PlistSocket}, or a
   * raw {@link Transport} (which is wrapped in a `PlistSocket`).
   * @param label The `Label` sent with every request.
   */
  constructor(
    socketOrTransport: PlistSocket | Transport,
    private readonly label = 'sideimpactor',
  ) {
    this.socket =
      socketOrTransport instanceof PlistSocket
        ? socketOrTransport
        : new PlistSocket(socketOrTransport);
  }

  /** The underlying framed channel (e.g. for the StartSession TLS upgrade). */
  get plistSocket(): PlistSocket {
    return this.socket;
  }

  /**
   * The session id remembered from the last `startSession` call, if any.
   * Used to carry the session across a transport upgrade (e.g. rebuilding
   * this client over a TLS-upgraded transport).
   */
  get sessionIdOrNull(): string | null {
    return this.sessionId;
  }

  /** Adopts a session id (e.g. after rebuilding over a TLS-upgraded transport). */
  adoptSessionId(id: string | null): void {
    this.sessionId = id;
  }

  /** Sends a request and returns the raw response dictionary (no error mapping). */
  private async requestRaw(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    await this.socket.sendPlist({ Label: this.label, ...request });
    return this.socket.recvPlist();
  }

  /** Sends a request; throws {@link LockdownError} when the response carries `Error`. */
  private async request(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await this.requestRaw(request);
    const err = errorFromResponse(res);
    if (err) throw err;
    return res;
  }

  /**
   * `GetValue` — returns `response["Value"]` directly, throwing when absent.
   * Mirrors Rust `get_value`.
   */
  async getValue(key?: string, domain?: string): Promise<unknown> {
    const request: Record<string, unknown> = { Request: 'GetValue' };
    if (key !== undefined) request['Key'] = key;
    if (domain !== undefined) request['Domain'] = domain;
    const res = await this.request(request);
    if (!('Value' in res)) {
      throw new LockdownError('UnexpectedResponse', 'missing Value in GetValue response');
    }
    return res['Value'];
  }

  /**
   * Single-shot `Pair` attempt (mirrors Rust `pair_once`): sends the pair
   * request built from `record` exactly once — no looping or sleeping.
   *
   * @param pairRecord The host pair record (its `HostPrivateKey` is NOT sent;
   * see {@link pairRecordToDict}).
   * @param buid SystemBUID placed in the outgoing `PairRecord`; when empty,
   * the record's own `systemBuid` is used.
   * @throws {PairingPendingError} when the device reports
   * `PairingDialogResponsePending` — retry after the user taps "Trust".
   * @returns `{ success: true }` plus the device's `EscrowBag` when present.
   */
  async pair(
    pairRecord: LockdownPairRecord,
    buid: string,
    hostName?: string,
  ): Promise<{ success: boolean; escrowBag?: Uint8Array }> {
    const dict = pairRecordToDict(pairRecord);
    dict['SystemBUID'] = buid && buid.length > 0 ? buid : pairRecord.systemBuid;
    await this.socket.sendPlist({
      Label: this.label,
      Request: 'Pair',
      PairRecord: dict,
      ProtocolVersion: '2',
      PairingOptions: { ExtendedPairingErrors: true },
      // Mirrors idevice/idevice_pair: optional host label in the Pair request.
      ...(hostName ? { HostName: hostName } : {}),
    });
    const res = await this.socket.recvPlist();
    const err = errorFromResponse(res);
    if (err) throw err;
    const escrow = res['EscrowBag'];
    return {
      success: true,
      escrowBag: escrow instanceof Uint8Array ? copyBytes(escrow) : undefined,
    };
  }

  /**
   * `ValidatePair` — asks the device whether this host is currently paired.
   * Returns `true` when the device accepts, `false` when it reports an error
   * (e.g. not paired). Transport-level failures still throw.
   */
  async validatePair(hostID: string): Promise<boolean> {
    const res = await this.requestRaw({ Request: 'ValidatePair', HostID: hostID });
    return res['Error'] === undefined || res['Error'] === null;
  }

  /**
   * `StartSession` (mirrors Rust `start_session` up to the TLS upgrade).
   * On success the session id is remembered for {@link stopSession}.
   *
   * When `enableSessionSSL` is true the caller must upgrade
   * `plistSocket.transport` to TLS (mTLS with the pairing record,
   * SNI "lockdownd") before issuing further requests.
   */
  async startSession(
    hostID: string,
    systemBUID: string,
  ): Promise<{ success: boolean; enableSessionSSL: boolean; sessionId: string }> {
    const res = await this.request({
      Request: 'StartSession',
      HostID: hostID,
      SystemBUID: systemBUID,
    });
    const sessionId = res['SessionID'];
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      throw new LockdownError('UnexpectedResponse', 'missing SessionID in StartSession response');
    }
    const enableSessionSSL = res['EnableSessionSSL'] === true;
    this.sessionId = sessionId;
    return { success: true, enableSessionSSL, sessionId };
  }

  /**
   * `StartService` (mirrors Rust `start_service`): asks lockdownd to start a
   * service (e.g. `com.apple.afc`, `com.apple.mobile.installation_proxy`) and
   * returns the TCP port it listens on.
   *
   * The caller is expected to open a NEW connection to the returned port
   * (via usbmuxd `Connect`) and hand it to the service client. If
   * `enableServiceSSL` is true, the caller must perform the TLS upgrade on
   * that new transport itself.
   */
  async startService(serviceName: string): Promise<{ port: number; enableServiceSSL?: boolean }> {
    const res = await this.request({ Request: 'StartService', Service: serviceName });
    const port = res['Port'];
    if (typeof port !== 'number' || !Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new LockdownError('UnexpectedResponse', 'missing Port in StartService response');
    }
    // Over USB this option usually doesn't exist; default to false like Rust.
    return { port, enableServiceSSL: res['EnableServiceSSL'] === true };
  }

  /**
   * `StopSession` for a previously started session.
   *
   * @param sessionId The `sessionId` returned by {@link startSession}; when
   * omitted, the id remembered from the last `startSession` call is used.
   */
  async stopSession(sessionId?: string): Promise<void> {
    const id = sessionId ?? this.sessionId;
    const request: Record<string, unknown> = { Request: 'StopSession' };
    if (id) request['SessionID'] = id;
    await this.request(request);
    this.sessionId = null;
  }

  /**
   * `Unpair` — removes this host's pairing from the device side.
   * (The host-side record in usbmuxd's cache must be removed separately via
   * `UsbmuxdClient.deletePairRecord`.)
   */
  async unpair(hostId: string): Promise<void> {
    await this.request({ Request: 'Unpair', PairRecord: { HostID: hostId } });
  }
}

/* ------------------------------------------------------------------ */
/* Full pairing flow                                                    */
/* ------------------------------------------------------------------ */

/** Pluggable certificate generator; defaults to this package's `ca.ts`. */
export interface CertificateAuthority {
  generateCertificates(
    devicePublicKeyPem: string | Uint8Array,
  ): Promise<{ hostCert: Uint8Array; devCert: Uint8Array; privateKey: Uint8Array }>;
}

const defaultCa: CertificateAuthority = { generateCertificates };

export interface PairDeviceOptions {
  /** Optional `HostName` sent with the `Pair` request. */
  hostName?: string;
  /** Delay between trust retries (default 1000 ms, like Rust `pair`). */
  retryDelayMs?: number;
  /** Maximum Pair attempts before giving up (default: retry indefinitely). */
  maxAttempts?: number;
  /** Aborts the trust-retry loop. */
  signal?: AbortSignal;
  /** Called once when the first `PairingDialogResponsePending` arrives. */
  onTrustPending?: () => void;
}

/**
 * Full pairing flow (mirrors Rust `LockdownClient::pair`):
 * generates the host CA + device certificates, sends the `Pair` request,
 * and retries every `retryDelayMs` while the device reports
 * `PairingDialogResponsePending` (user hasn't tapped "Trust" yet).
 *
 * On success, `HostPrivateKey` and the device's `EscrowBag` (when sent)
 * are merged into the returned {@link LockdownPairRecord}.
 *
 * Note: certificate/key fields are stored as PEM bytes (matching `idevice`'s
 * `CaReturn` and the on-disk `{UDID}.plist` format). Callers that need DER
 * (e.g. the TLS client) must convert via `pemToDer` themselves.
 *
 * Note: this does NOT store the record in usbmuxd's cache — that is the
 * caller's job (e.g. `UsbmuxdClient.savePairRecord`, or
 * `PairingFile.fromValue(pairRecordToDict(record))` for the on-disk
 * `{UDID}.plist` format).
 */

export async function pairDevice(
  client: LockdownClient,
  devicePublicKey: Uint8Array,
  wifiMac: string,
  hostId: string,
  systemBUID: string,
  ca: CertificateAuthority = defaultCa,
  opts: PairDeviceOptions = {},
): Promise<LockdownPairRecord> {
  const certs = await ca.generateCertificates(copyBytes(devicePublicKey));

  // generateCertificates returns PEM bytes; store as-is (PEM is the
  // on-disk PairRecord format and what lockdownd expects in the Pair request).
  const record: LockdownPairRecord = {
    hostId,
    systemBuid: systemBUID,
    hostCertificate: copyBytes(certs.hostCert),
    hostPrivateKey: copyBytes(certs.privateKey),
    rootCertificate: copyBytes(certs.hostCert),
    rootPrivateKey: copyBytes(certs.privateKey),
    deviceCertificate: copyBytes(certs.devCert),
    devicePublicKey: copyBytes(devicePublicKey),
    wifiMacAddress: wifiMac,
  };

  const retryDelayMs = opts.retryDelayMs ?? 1000;
  const maxAttempts = opts.maxAttempts ?? Number.POSITIVE_INFINITY;
  let trustNotified = false;

  for (let attempt = 1; ; attempt++) {
    if (opts.signal?.aborted) {
      throw new LockdownError('Aborted', 'pairing aborted by caller');
    }
    try {
      const res = await client.pair(record, systemBUID, opts.hostName);
      if (res.escrowBag) record.escrowBag = res.escrowBag;
      return record;
    } catch (e) {
      if (!(e instanceof PairingPendingError)) throw e;
      if (attempt >= maxAttempts) throw e;
      if (!trustNotified) {
        trustNotified = true;
        opts.onTrustPending?.();
      }
      await sleep(retryDelayMs, opts.signal);
    }
  }
}
