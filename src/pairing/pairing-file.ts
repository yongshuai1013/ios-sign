// Port of `idevice/src/pairing_file.rs` and
// `idevice/src/remote_pairing/rp_pairing_file.rs` (Jackson Coxson).
//
// XML-plist based pairing records: the classic USB/lockdown `PairingFile`
// (certificates + keys + device identifiers) and the remote-pairing
// `RpPairingFile` (Ed25519 signing keys + identifier).

import { parse as parsePlist, build as buildPlist } from 'plist';
import type { PlistObject } from 'plist';
import { ed25519 } from '@noble/curves/ed25519.js';
import { v3 as uuidv3, v4 as uuidv4 } from 'uuid';

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8');
const utf8DecoderStrict = new TextDecoder('utf-8', { fatal: true });

/** Node's custom-inspect hook, so console.log never leaks key material. */
const INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function tryDecodeUtf8(data: Uint8Array): string | undefined {
  try {
    return utf8DecoderStrict.decode(data);
  } catch {
    return undefined;
  }
}

/** Mirrors Rust's `is_pem_formatted`: already wrapped in BEGIN/END headers. */
function isPemFormatted(data: Uint8Array): boolean {
  const s = tryDecodeUtf8(data);
  return s !== undefined && s.includes('-----BEGIN') && s.includes('-----END');
}

/** Mirrors Rust's `is_base64`: only base64-alphabet characters/whitespace. */
function isBase64(data: Uint8Array): boolean {
  const s = tryDecodeUtf8(data);
  if (s === undefined) {
    return false;
  }
  for (const c of s) {
    const ok =
      (c >= '0' && c <= '9') ||
      (c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      c === '+' ||
      c === '/' ||
      c === '=' ||
      c === '\n' ||
      c === '\r' ||
      c === '\t' ||
      c === '\x0b' ||
      c === '\x0c' ||
      c === ' ';
    if (!ok) {
      return false;
    }
  }
  return true;
}

function base64Encode(data: Uint8Array): string {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < data.length; i += CHUNK) {
    binary += String.fromCharCode(...data.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/**
 * Mirrors Rust's `ensure_pem_headers`: returns the data untouched when it is
 * already PEM-formatted, otherwise wraps it in BEGIN/END headers with the
 * base64 body re-wrapped at 64 characters per line (LF).
 */
function ensurePemHeaders(data: Uint8Array, pemType: string): Uint8Array {
  if (isPemFormatted(data)) {
    return data;
  }

  let base64Content: string;
  const asText = tryDecodeUtf8(data);
  if (asText !== undefined && isBase64(data)) {
    // Already base64 text (maybe with stray whitespace): clean it up.
    base64Content = asText.replace(/[\n\r ]/g, '');
  } else {
    base64Content = base64Encode(data);
  }

  const lines: string[] = [];
  for (let i = 0; i < base64Content.length; i += 64) {
    lines.push(base64Content.slice(i, i + 64));
  }
  const pem =
    `-----BEGIN ${pemType}-----\n` + lines.join('\n') + `\n-----END ${pemType}-----`;
  return utf8Encoder.encode(pem);
}

/** Copies any Uint8Array/Buffer into a fresh, tightly-packed Uint8Array. */
function copyBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    const out = new Uint8Array(value.byteLength);
    out.set(value);
    return out;
  }
  throw new Error('expected binary data for pairing file field');
}

/**
 * Normalizes a Uint8Array so its backing buffer starts at offset 0 with
 * exactly `byteLength` bytes. (The `plist` package encodes typed arrays via
 * `new Uint8Array(value.buffer)`, which ignores `byteOffset`.)
 */
function cleanBytes(value: Uint8Array): Uint8Array {
  if (value.byteOffset === 0 && value.buffer.byteLength === value.byteLength) {
    return value;
  }
  return copyBytes(value);
}

function requireBytes(
  dict: Record<string, unknown>,
  key: string,
  expectedLength: number,
): Uint8Array {
  const value = dict[key];
  if (value === undefined || value === null) {
    throw new Error(`pairing file is missing required field: ${key}`);
  }
  const bytes = copyBytes(value);
  if (bytes.length !== expectedLength) {
    throw new Error(
      `pairing file field ${key} must be ${expectedLength} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

function optionalBytes(
  dict: Record<string, unknown>,
  key: string,
): Uint8Array | undefined {
  const value = dict[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  return copyBytes(value);
}

function requireString(dict: Record<string, unknown>, key: string): string {
  const value = dict[key];
  if (typeof value !== 'string') {
    throw new Error(`pairing file is missing required field: ${key}`);
  }
  return value;
}

function optionalString(
  dict: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = dict[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new Error(`pairing file field ${key} must be a string`);
  }
  return value;
}

function asDict(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${what} plist root is not a dictionary`);
  }
  return value as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// PairingFile (USB / lockdown pairing record)
// ---------------------------------------------------------------------------

export interface PairingFileInit {
  /** Device certificate: PEM text bytes or DER. */
  deviceCertificate: Uint8Array;
  /** Host private key: PEM text bytes or DER. */
  hostPrivateKey: Uint8Array;
  /** Host certificate: PEM text bytes or DER. */
  hostCertificate: Uint8Array;
  /** Root CA private key: PEM text bytes or DER. */
  rootPrivateKey: Uint8Array;
  /** Root CA certificate: PEM text bytes or DER. */
  rootCertificate: Uint8Array;
  systemBuid: string;
  hostId: string;
  /** Absent on e.g. Apple Watch. */
  escrowBag?: Uint8Array;
  wifiMacAddress: string;
  udid?: string;
}

/**
 * A complete iOS device pairing record: the cryptographic materials and
 * identifiers needed for secure communication with a device.
 */
export class PairingFile {
  deviceCertificate: Uint8Array;
  hostPrivateKey: Uint8Array;
  hostCertificate: Uint8Array;
  rootPrivateKey: Uint8Array;
  rootCertificate: Uint8Array;
  systemBuid: string;
  hostId: string;
  escrowBag?: Uint8Array;
  wifiMacAddress: string;
  udid?: string;

  constructor(init: PairingFileInit) {
    this.deviceCertificate = copyBytes(init.deviceCertificate);
    this.hostPrivateKey = copyBytes(init.hostPrivateKey);
    this.hostCertificate = copyBytes(init.hostCertificate);
    this.rootPrivateKey = copyBytes(init.rootPrivateKey);
    this.rootCertificate = copyBytes(init.rootCertificate);
    this.systemBuid = init.systemBuid;
    this.hostId = init.hostId;
    this.escrowBag =
      init.escrowBag === undefined ? undefined : copyBytes(init.escrowBag);
    this.wifiMacAddress = init.wifiMacAddress;
    this.udid = init.udid;
    (this as unknown as Record<symbol, () => string>)[INSPECT_CUSTOM] = () =>
      this.toDebugString();
  }

  /** Parses a pairing file from raw XML-plist bytes. */
  static fromBytes(bytes: Uint8Array): PairingFile {
    let parsed: unknown;
    try {
      parsed = parsePlist(utf8Decoder.decode(bytes));
    } catch (e) {
      throw new Error(
        `failed to parse pairing file plist: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    return PairingFile.fromValue(asDict(parsed, 'pairing file'));
  }

  /** Builds a pairing file from an already-parsed plist dictionary. */
  static fromValue(dict: Record<string, unknown>): PairingFile {
    return new PairingFile({
      deviceCertificate: requireData(dict, 'DeviceCertificate'),
      hostPrivateKey: requireData(dict, 'HostPrivateKey'),
      hostCertificate: requireData(dict, 'HostCertificate'),
      rootPrivateKey: requireData(dict, 'RootPrivateKey'),
      rootCertificate: requireData(dict, 'RootCertificate'),
      systemBuid: requireString(dict, 'SystemBUID'),
      hostId: requireString(dict, 'HostID'),
      escrowBag: optionalBytes(dict, 'EscrowBag'),
      wifiMacAddress: requireString(dict, 'WiFiMACAddress'),
      udid: optionalString(dict, 'UDID'),
    });
  }

  /** Serializes to XML-plist bytes, adding missing PEM headers. */
  serialize(): Uint8Array {
    const dict: Record<string, unknown> = {
      DeviceCertificate: cleanBytes(
        ensurePemHeaders(this.deviceCertificate, 'CERTIFICATE'),
      ),
      HostPrivateKey: cleanBytes(
        ensurePemHeaders(this.hostPrivateKey, 'PRIVATE KEY'),
      ),
      HostCertificate: cleanBytes(
        ensurePemHeaders(this.hostCertificate, 'CERTIFICATE'),
      ),
      RootPrivateKey: cleanBytes(
        ensurePemHeaders(this.rootPrivateKey, 'PRIVATE KEY'),
      ),
      RootCertificate: cleanBytes(
        ensurePemHeaders(this.rootCertificate, 'CERTIFICATE'),
      ),
      SystemBUID: this.systemBuid,
      HostID: this.hostId,
    };
    if (this.escrowBag !== undefined) {
      dict['EscrowBag'] = cleanBytes(this.escrowBag);
    }
    dict['WiFiMACAddress'] = this.wifiMacAddress;
    if (this.udid !== undefined) {
      dict['UDID'] = this.udid;
    }
    return utf8Encoder.encode(buildPlist(dict as unknown as PlistObject));
  }

  /** Debug representation that never includes private key material. */
  toDebugString(): string {
    const bytes = (b: Uint8Array | undefined) =>
      b === undefined ? 'none' : `<${b.length} bytes>`;
    return (
      `PairingFile { deviceCertificate: ${bytes(this.deviceCertificate)}, ` +
      `hostCertificate: ${bytes(this.hostCertificate)}, ` +
      `rootCertificate: ${bytes(this.rootCertificate)}, ` +
      `hostPrivateKey: <redacted>, rootPrivateKey: <redacted>, ` +
      `systemBuid: "${this.systemBuid}", hostId: "${this.hostId}", ` +
      `escrowBag: ${bytes(this.escrowBag)}, ` +
      `wifiMacAddress: "${this.wifiMacAddress}", ` +
      `udid: ${this.udid === undefined ? 'none' : `"${this.udid}"`} }`
    );
  }
}

function requireData(dict: Record<string, unknown>, key: string): Uint8Array {
  const value = dict[key];
  if (value === undefined || value === null) {
    throw new Error(`pairing file is missing required field: ${key}`);
  }
  return copyBytes(value);
}

// ---------------------------------------------------------------------------
// RpPairingFile (remote-pairing record)
// ---------------------------------------------------------------------------

export interface RpPairingFileInit {
  /** Ed25519 private key seed, 32 bytes. */
  privateKey: Uint8Array;
  /** Ed25519 public key, 32 bytes. */
  publicKey: Uint8Array;
  identifier: string;
  /** Alternate IRK, 16 bytes when present. */
  altIrk?: Uint8Array;
}

/** Remote-pairing record: Ed25519 signing keys plus a host identifier. */
export class RpPairingFile {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  identifier: string;
  altIrk?: Uint8Array;

  constructor(init: RpPairingFileInit) {
    if (init.privateKey.length !== 32) {
      throw new Error(
        `remote pairing private key must be 32 bytes, got ${init.privateKey.length}`,
      );
    }
    if (init.publicKey.length !== 32) {
      throw new Error(
        `remote pairing public key must be 32 bytes, got ${init.publicKey.length}`,
      );
    }
    if (init.altIrk !== undefined && init.altIrk.length !== 16) {
      throw new Error(
        `remote pairing alt_irk must be 16 bytes, got ${init.altIrk.length}`,
      );
    }
    this.privateKey = copyBytes(init.privateKey);
    this.publicKey = copyBytes(init.publicKey);
    this.identifier = init.identifier;
    this.altIrk =
      init.altIrk === undefined ? undefined : copyBytes(init.altIrk);
    (this as unknown as Record<symbol, () => string>)[INSPECT_CUSTOM] = () =>
      this.toDebugString();
  }

  /** Returns the Ed25519 public key bytes (32 bytes). */
  publicKeyBytes(): Uint8Array {
    return this.publicKey.slice();
  }

  /** Returns the Ed25519 private key bytes (32 bytes). */
  privateKeyBytes(): Uint8Array {
    return this.privateKey.slice();
  }

  /** Generates fresh Ed25519 signing keys and a v3 UUID identifier. */
  static generate(sendingHost: string): RpPairingFile {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    const identifier = uuidv3(sendingHost, uuidv3.DNS);
    return new RpPairingFile({ privateKey, publicKey, identifier });
  }

  /** Rotates the Ed25519 signing keys and clears the alt IRK. */
  recreateSigningKeys(): void {
    const privateKey = ed25519.utils.randomSecretKey();
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);
    this.altIrk = undefined;
  }

  /** Serializes to XML-plist bytes. */
  toBytes(): Uint8Array {
    const dict: Record<string, unknown> = {
      public_key: cleanBytes(this.publicKey),
      private_key: cleanBytes(this.privateKey),
      identifier: this.identifier,
    };
    if (this.altIrk !== undefined) {
      dict['alt_irk'] = cleanBytes(this.altIrk);
    }
    return utf8Encoder.encode(buildPlist(dict as unknown as PlistObject));
  }

  /** Parses from XML-plist bytes, validating key lengths. */
  static fromBytes(bytes: Uint8Array): RpPairingFile {
    let parsed: unknown;
    try {
      parsed = parsePlist(utf8Decoder.decode(bytes));
    } catch (e) {
      throw new Error(
        `failed to parse remote pairing file plist: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    const dict = asDict(parsed, 'remote pairing file');
    return new RpPairingFile({
      publicKey: requireBytes(dict, 'public_key', 32),
      privateKey: requireBytes(dict, 'private_key', 32),
      identifier: requireString(dict, 'identifier'),
      altIrk: optionalBytes(dict, 'alt_irk'),
    });
  }

  /** Debug representation that never includes private key material. */
  toDebugString(): string {
    return (
      `RpPairingFile { publicKey: <${this.publicKey.length} bytes>, ` +
      `identifier: "${this.identifier}", ` +
      `altIrk: ${this.altIrk === undefined ? 'none' : `<${this.altIrk.length} bytes>`} }`
    );
  }
}

// ---------------------------------------------------------------------------
// Plain record interfaces + parse/serialize functions
// (field naming mirrors the on-disk plist keys)
// ---------------------------------------------------------------------------

/**
 * Classic USB/lockdown pairing record, as stored in `{UDID}.plist`.
 * Certificate/key fields hold the raw file bytes (PEM text or DER).
 */
export interface LockdownPairRecord {
  DeviceCertificate: Uint8Array;
  HostCertificate: Uint8Array;
  HostPrivateKey: Uint8Array;
  RootCertificate: Uint8Array;
  RootPrivateKey: Uint8Array;
  SystemBUID: string;
  HostID: string;
  EscrowBag?: Uint8Array;
  WiFiMACAddress?: string;
  UDID?: string;
}

/**
 * Remote-pairing record, as stored in `pairingFile.plist`.
 */
export interface RemotePairingFile {
  /** Ed25519 public key, 32 bytes. */
  public_key: Uint8Array;
  /** Ed25519 private key seed, 32 bytes. */
  private_key: Uint8Array;
  /** Host identifier (UUID string). */
  identifier: string;
  /** Alternate IRK, 16 bytes when present. */
  alt_irk?: Uint8Array;
}

function lockdownToClass(rec: LockdownPairRecord): PairingFile {
  return new PairingFile({
    deviceCertificate: rec.DeviceCertificate,
    hostCertificate: rec.HostCertificate,
    hostPrivateKey: rec.HostPrivateKey,
    rootCertificate: rec.RootCertificate,
    rootPrivateKey: rec.RootPrivateKey,
    systemBuid: rec.SystemBUID,
    hostId: rec.HostID,
    escrowBag: rec.EscrowBag,
    // WiFiMACAddress is required by the class; default to empty when absent.
    wifiMacAddress: rec.WiFiMACAddress ?? '',
    udid: rec.UDID,
  });
}

function lockdownFromClass(pf: PairingFile): LockdownPairRecord {
  const rec: LockdownPairRecord = {
    DeviceCertificate: pf.deviceCertificate,
    HostCertificate: pf.hostCertificate,
    HostPrivateKey: pf.hostPrivateKey,
    RootCertificate: pf.rootCertificate,
    RootPrivateKey: pf.rootPrivateKey,
    SystemBUID: pf.systemBuid,
    HostID: pf.hostId,
  };
  if (pf.escrowBag !== undefined) rec.EscrowBag = pf.escrowBag;
  if (pf.wifiMacAddress !== '') rec.WiFiMACAddress = pf.wifiMacAddress;
  if (pf.udid !== undefined) rec.UDID = pf.udid;
  return rec;
}

/** Parses a lockdown pairing record from an XML plist string. */
export function parseLockdownPairRecord(plistXml: string): LockdownPairRecord {
  return lockdownFromClass(PairingFile.fromBytes(utf8Encoder.encode(plistXml)));
}

/** Serializes a lockdown pairing record to an XML plist string. */
export function serializeLockdownPairRecord(rec: LockdownPairRecord): string {
  return utf8Decoder.decode(lockdownToClass(rec).serialize());
}

function remoteToClass(f: RemotePairingFile): RpPairingFile {
  return new RpPairingFile({
    privateKey: f.private_key,
    publicKey: f.public_key,
    identifier: f.identifier,
    altIrk: f.alt_irk,
  });
}

function remoteFromClass(f: RpPairingFile): RemotePairingFile {
  const rec: RemotePairingFile = {
    public_key: f.publicKey,
    private_key: f.privateKey,
    identifier: f.identifier,
  };
  if (f.altIrk !== undefined) rec.alt_irk = f.altIrk;
  return rec;
}

/** Parses a remote-pairing file from an XML plist string. */
export function parseRemotePairingFile(plistXml: string): RemotePairingFile {
  return remoteFromClass(RpPairingFile.fromBytes(utf8Encoder.encode(plistXml)));
}

/** Serializes a remote-pairing file to an XML plist string. */
export function serializeRemotePairingFile(f: RemotePairingFile): string {
  return utf8Decoder.decode(remoteToClass(f).toBytes());
}

/**
 * Generates a fresh remote-pairing record: random Ed25519 signing keys and
 * a UUIDv3 identifier derived from `hostname` (mirrors idevice).
 */
export function generateRemotePairingFile(hostname: string): RemotePairingFile {
  return remoteFromClass(RpPairingFile.generate(hostname));
}

/** Generates a random HostID (uppercase UUID v4). */
export function generateHostID(): string {
  return uuidv4().toUpperCase();
}

/** Generates a random SystemBUID (uppercase UUID v4). */
export function generateSystemBUID(): string {
  return uuidv4().toUpperCase();
}
