/**
 * Remote Pairing (RPPairing) client — TypeScript port of the Rust `idevice`
 * crate's `src/remote_pairing/{mod.rs, tls_psk.rs, tunnel.rs}`.
 *
 * Implements:
 *  - RPPairing framing ("RPPairing" magic + u16 BE length + JSON body)
 *  - handshake (attemptPairVerify)
 *  - pair-verify (X25519 + Ed25519 + ChaCha20-Poly1305)
 *  - pair-setup (SRP-3072 + ChaCha20-Poly1305, OPACK device info)
 *  - encrypted RPC (ClientEncrypt-main / ServerEncrypt-main)
 *  - createListener (TCP tunnel listener)
 *  - TLS 1.2 PSK handshake (PSK-AES256-CBC-SHA384 / PSK-AES128-CBC-SHA)
 *  - CDTunnel handshake over the TLS-PSK stream
 *
 * The transport is abstracted as {@link RpTransport}; the caller is responsible
 * for connecting to the device's Remote Pairing port (e.g. via lockdownd
 * RemoteXPC service or a direct TCP connection).
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { cbc } from '@noble/ciphers/aes.js';
import { sha512, sha384, sha256 } from '@noble/hashes/sha2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import type { CHash } from '@noble/hashes/utils.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
  PairingDataComponentType,
  serializeTlv8,
  deserializeTlv8,
  collectComponentData,
  containsComponent,
} from './tlv.js';
import type { TLV8Entry } from './tlv.js';
import { plistToOpack, opackToPlist } from './opack.js';
import type { PlistValue } from './opack.js';
import { SrpClient } from './srp.js';
import type { SrpVerifier } from './srp.js';
import { RpPairingFile } from './pairing-file.js';

export { RpPairingFile };
/** Alias matching the task API: the remote-pairing record type. */
export type RemotePairingFile = RpPairingFile;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type RemotePairingErrorCode =
  | 'ProtocolError'
  | 'UnexpectedResponse'
  | 'PairVerifyFailed'
  | 'PairingRejected'
  | 'SrpAuthFailed'
  | 'NotPaired'
  | 'TlsError'
  | 'TunnelError'
  | 'CryptoError';

export class RemotePairingError extends Error {
  readonly code: RemotePairingErrorCode;
  constructor(code: RemotePairingErrorCode, message: string) {
    super(`[RemotePairing:${code}] ${message}`);
    this.name = 'RemotePairingError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Transport abstraction
// ---------------------------------------------------------------------------

/**
 * Raw byte transport to the device's Remote Pairing port.
 * The caller owns the connection (TCP socket, RemoteXPC channel, ...).
 */
export interface RpTransport {
  write(data: Uint8Array): Promise<void>;
  readExact(n: number): Promise<Uint8Array>;
  close(): void;
}

/** Alias matching the task API: the byte-stream transport type. */
export type Transport = RpTransport;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const te = new TextEncoder();
const td = new TextDecoder();

function concat(...parts: Uint8Array[]): Uint8Array {
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

function u16be(v: number): Uint8Array {
  return new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
}

function u64be(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(0, BigInt(v), false);
  return out;
}

function u64leBytes(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(0, v, true);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function bytesToBase64(b: Uint8Array): string {
  // Manual base64: no Node Buffer dependency, works in browsers.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const b0 = b[i];
    const b1 = i + 1 < b.length ? b[i + 1] : 0;
    const b2 = i + 2 < b.length ? b[i + 2] : 0;
    out += alphabet[b0 >> 2];
    out += alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < b.length ? alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < b.length ? alphabet[b2 & 0x3f] : '=';
  }
  return out;
}

function base64ToBytes(s: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const clean = s.replace(/\s+/g, '');
  if (clean.length % 4 !== 0) {
    throw new RemotePairingError('ProtocolError', 'invalid base64 length');
  }
  const idx = (ch: string): number => {
    if (ch === '=') return 0;
    const i = alphabet.indexOf(ch);
    if (i < 0) throw new RemotePairingError('ProtocolError', `invalid base64 character '${ch}'`);
    return i;
  };
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const n = (idx(clean[i]) << 18) | (idx(clean[i + 1]) << 12) | (idx(clean[i + 2]) << 6) | idx(clean[i + 3]);
    out.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  return Uint8Array.from(out.slice(0, out.length - pad));
}

/** HKDF-SHA512(ikm, salt, info) -> `length` bytes. `salt` may be undefined (= 64 zero bytes, RFC 5869). */
function hkdfSha512(
  ikm: Uint8Array,
  salt: Uint8Array | undefined,
  info: string | Uint8Array,
  length: number,
): Uint8Array {
  const infoBytes = typeof info === 'string' ? te.encode(info) : info;
  return hkdf(sha512, ikm, salt, infoBytes, length);
}

function chachaEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return chacha20poly1305(key, nonce).encrypt(plaintext);
}

function chachaDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  try {
    return chacha20poly1305(key, nonce).decrypt(ciphertext);
  } catch (e) {
    throw new RemotePairingError('CryptoError', `ChaCha20-Poly1305 decrypt failed: ${(e as Error).message}`);
  }
}

function tlvEntry(type: PairingDataComponentType, data: Uint8Array): TLV8Entry {
  return { type, data };
}

// ---------------------------------------------------------------------------
// RPPairing framing
// ---------------------------------------------------------------------------

const RPPAIRING_MAGIC = te.encode('RPPairing'); // 9 bytes
/** Wire protocol version negotiated in the handshake. */
export const WIRE_PROTOCOL_VERSION = 19;
/** The raw wire magic bytes. */
export const RPPAIRING_MAGIC_BYTES: Uint8Array = RPPAIRING_MAGIC;

/** Frame a JSON object: "RPPairing" + u16 BE length + UTF-8 JSON. */
export async function sendFrame(transport: RpTransport, obj: unknown): Promise<void> {
  const body = te.encode(JSON.stringify(obj));
  await transport.write(concat(RPPAIRING_MAGIC, u16be(body.length), body));
}

/** Read one frame and return the parsed JSON body. */
export async function readFrame(transport: RpTransport): Promise<any> {
  const magic = await transport.readExact(RPPAIRING_MAGIC.length);
  if (!bytesEqual(magic, RPPAIRING_MAGIC)) {
    throw new RemotePairingError('ProtocolError', 'bad RPPairing magic');
  }
  const lenBytes = await transport.readExact(2);
  const len = (lenBytes[0] << 8) | lenBytes[1];
  const body = await transport.readExact(len);
  return JSON.parse(td.decode(body));
}

// ---------------------------------------------------------------------------
// RemotePairingClient
// ---------------------------------------------------------------------------

export interface PairingDataPayload {
  data: string; // base64-encoded TLV8
  kind: 'verifyManualPairing' | 'setupManualPairing';
  sendingHost?: string;
  startNewSession: boolean;
}

export class RemotePairingClient {
  private sequenceNumber = 0;
  private encryptedSequenceNumber = 0n;
  /** Nonce used by the last sendEncryptedRequest; the paired response uses the same nonce. */
  private pendingResponseNonce?: Uint8Array;

  private clientAeadKey: Uint8Array;
  private serverAeadKey: Uint8Array;

  /** Shared secret from X25519 (pair-verify) or SRP (pair-setup); used as TLS-PSK. */
  private encryptionKeyValue?: Uint8Array;
  /**
   * The session encryption key (TLS-PSK), established by pair-verify or
   * pair-setup. Throws RemotePairingError('NotPaired') when called before
   * pairing has completed.
   */
  get encryptionKey(): Uint8Array {
    const k = this.encryptionKeyValue;
    if (!k) {
      throw new RemotePairingError('NotPaired', 'no encryption key: pair with the device first');
    }
    return k;
  }
  /** The pairing file that was successfully verified / created. */
  public pairingFile?: RpPairingFile;
  /** Host name advertised to the device in pairing messages. */
  public readonly sendingHost: string;
  /**
   * Optional callback invoked when the device reports `awaitingUserConsent`
   * (tvOS-style flow). Receives the pairing identifier.
   */
  public onAwaitingUserConsent?: (identifier: string) => void;

  /**
   * @param transport byte stream to the device's remote-pairing port
   * @param pairingFileOrHost an existing pairing file, or (legacy position)
   *   the sending-host name as a string
   * @param sendingHost host name advertised to the device
   */
  constructor(
    private readonly transport: Transport,
    pairingFileOrHost?: RpPairingFile | string,
    sendingHost = 'SideImpactor',
  ) {
    if (typeof pairingFileOrHost === 'string') {
      this.sendingHost = pairingFileOrHost;
    } else {
      this.sendingHost = sendingHost;
      this.pairingFile = pairingFileOrHost;
    }
    // Placeholder ciphers, re-derived once pair-verify or pair-setup completes.
    const zero = new Uint8Array(32);
    this.clientAeadKey = hkdfSha512(zero, undefined, 'ClientEncrypt-main', 32);
    this.serverAeadKey = hkdfSha512(zero, undefined, 'ServerEncrypt-main', 32);
  }

  private deriveMainCiphers(key: Uint8Array): void {
    // Mirrors Rust's derive_main_ciphers: Hkdf::new(None, key).expand("ClientEncrypt-main" / "ServerEncrypt-main")
    this.clientAeadKey = hkdfSha512(key, undefined, 'ClientEncrypt-main', 32);
    this.serverAeadKey = hkdfSha512(key, undefined, 'ServerEncrypt-main', 32);
  }

  // -- low-level message IO -------------------------------------------------

  private async sendPlain(payload: unknown): Promise<void> {
    await sendFrame(this.transport, {
      message: { plain: { _0: payload } },
      originatedBy: 'host',
      sequenceNumber: this.sequenceNumber,
    });
    this.sequenceNumber += 1;
  }

  private async sendEncryptedFrame(ciphertext: Uint8Array): Promise<void> {
    await sendFrame(this.transport, {
      message: { streamEncrypted: { _0: bytesToBase64(ciphertext) } },
      originatedBy: 'host',
      sequenceNumber: this.sequenceNumber,
    });
    this.sequenceNumber += 1;
  }

  /**
   * Receive one frame. Returns `message.plain._0` when present, otherwise the
   * whole frame object (for streamEncrypted handling).
   */
  private async recvPlain(): Promise<any> {
    const frame = await readFrame(this.transport);
    const plain = frame?.message?.plain?._0;
    return plain !== undefined ? plain : frame;
  }

  // -- handshake -------------------------------------------------------------

  /**
   * Send the handshake request (attemptPairVerify) and return
   * `response._1.handshake._0`.
   */
  async handshake(): Promise<any> {
    await this.sendPlain({
      request: {
        _0: {
          handshake: {
            _0: {
              hostOptions: { attemptPairVerify: true },
              wireProtocolVersion: WIRE_PROTOCOL_VERSION,
            },
          },
        },
      },
    });
    const response = await this.recvPlain();
    const h = response?.response?._1?.handshake?._0;
    if (h === undefined) {
      throw new RemotePairingError('UnexpectedResponse', 'missing handshake response in attemptPairVerify');
    }
    return h;
  }

  // -- pairing data messages --------------------------------------------------

  private async sendPairingData(payload: PairingDataPayload): Promise<void> {
    await this.sendPlain({
      event: { _0: { pairingData: { _0: payload } } },
    });
  }

  /** Receive a pairingData message and return the raw TLV8 bytes (base64-decoded). */
  private async receivePairingData(): Promise<Uint8Array> {
    const e0 = await this.receivePairingEvent();
    const b64 = e0?.pairingData?._0?.data;
    if (typeof b64 !== 'string') {
      throw new RemotePairingError('UnexpectedResponse', 'pairing data response contained neither data nor rejection');
    }
    return base64ToBytes(b64);
  }

  /** Receive one frame and return its `event._0` object (handles pairingRejectedWithError). */
  private async receivePairingEvent(): Promise<any> {
    const response = await this.recvPlain();
    // Two response shells are seen in the wild: `event._0` (most devices) and
    // `response._1` (as in idevice's socket.rs).
    const e0 = response?.event?._0 ?? response?.response?._1;
    if (e0 === undefined) {
      throw new RemotePairingError(
        'UnexpectedResponse',
        'missing event._0/response._1 in pairing data response',
      );
    }
    const rejected = e0.pairingRejectedWithError;
    if (rejected !== undefined) {
      const desc =
        rejected?.wrappedError?.userInfo?.NSLocalizedDescription ?? 'pairing rejected by device';
      throw new RemotePairingError('PairingRejected', String(desc));
    }
    return e0;
  }

  private async sendPairVerifiedFailed(): Promise<void> {
    await this.sendPlain({ event: { _0: { pairVerifyFailed: {} } } });
  }

  // -- pair-verify ------------------------------------------------------------

  /**
   * Validate an existing pairing (pair-verify). On success `encryptionKey` is
   * set and the main ciphers are derived. Throws RemotePairingError with code
   * 'PairVerifyFailed' when the device rejects verification (caller should then
   * run pairSetup).
   */
  private async attemptPairVerify(pairingFile: RpPairingFile): Promise<void> {
    const xPriv = x25519.utils.randomSecretKey();
    const xPub = x25519.getPublicKey(xPriv);

    await this.sendPairingData({
      data: bytesToBase64(
        serializeTlv8([
          tlvEntry(PairingDataComponentType.State, new Uint8Array([0x01])),
          tlvEntry(PairingDataComponentType.PublicKey, xPub),
        ]),
      ),
      kind: 'verifyManualPairing',
      startNewSession: true,
    });

    let entries = deserializeTlv8(await this.receivePairingData());
    if (containsComponent(entries, PairingDataComponentType.ErrorResponse)) {
      await this.sendPairVerifiedFailed();
      throw new RemotePairingError('PairVerifyFailed', 'pair-verify rejected by device');
    }

    const devicePub = collectComponentData(entries, PairingDataComponentType.PublicKey);
    if (devicePub.length !== 32) {
      throw new RemotePairingError('UnexpectedResponse', 'missing public key in pair-verify TLV data');
    }

    const sharedSecret = x25519.getSharedSecret(xPriv, devicePub);
    // Save the raw shared secret as the encryption key for the tunnel PSK.
    this.encryptionKeyValue = sharedSecret;

    const setupKey = hkdfSha512(
      sharedSecret,
      te.encode('Pair-Verify-Encrypt-Salt'),
      'Pair-Verify-Encrypt-Info',
      32,
    );
    const nonce = concat(new Uint8Array(4), te.encode('PV-Msg03')); // 12-byte nonce

    const idBytes = te.encode(pairingFile.identifier);
    const signbuf = concat(xPub, idBytes, devicePub);
    const signature = ed25519.sign(signbuf, pairingFile.privateKey);

    const plaintext = serializeTlv8([
      tlvEntry(PairingDataComponentType.Identifier, idBytes),
      tlvEntry(PairingDataComponentType.Signature, signature),
    ]);
    const ciphertext = chachaEncrypt(setupKey, nonce, plaintext);

    await this.sendPairingData({
      data: bytesToBase64(
        serializeTlv8([
          tlvEntry(PairingDataComponentType.State, new Uint8Array([0x03])),
          tlvEntry(PairingDataComponentType.EncryptedData, ciphertext),
        ]),
      ),
      kind: 'verifyManualPairing',
      startNewSession: false,
    });

    entries = deserializeTlv8(await this.receivePairingData());
    if (containsComponent(entries, PairingDataComponentType.ErrorResponse)) {
      await this.sendPairVerifiedFailed();
      throw new RemotePairingError('PairVerifyFailed', 'pair-verify signature rejected by device');
    }

    // Re-derive main encryption ciphers from the X25519 shared secret.
    this.deriveMainCiphers(sharedSecret);
  }

  // -- pair-setup ---------------------------------------------------------------

  /**
   * Run handshake, then pair-verify; when the device rejects verification,
   * fall back to a full pair-setup. `pairingFileOrPin` selects the pairing
   * file to verify, or — when a string — the PIN used for the pair-setup
   * fallback (a fresh pairing file is generated in that case).
   */
  async startSession(pairingFileOrPin?: RpPairingFile | string): Promise<void> {
    await this.handshake();
    const pf =
      typeof pairingFileOrPin === 'object'
        ? pairingFileOrPin
        : (this.pairingFile ?? RpPairingFile.generate(this.sendingHost));
    try {
      await this.attemptPairVerify(pf);
      this.pairingFile = pf;
    } catch (e) {
      if (e instanceof RemotePairingError && e.code === 'PairVerifyFailed') {
        const provider =
          typeof pairingFileOrPin === 'string' ? async () => pairingFileOrPin : undefined;
        await this.pairSetup(pf, provider);
        return;
      }
      throw e;
    }
  }

  /**
   * Full pair-setup: request consent, SRP-3072 auth with the on-device PIN,
   * then save our pair record on the peer. Sets `encryptionKey`,
   * `pairingFile.altIrk` and derives the main ciphers.
   *
   * `pairingFileOrPin` is either the pairing file to use (with an optional
   * PIN provider) or the PIN string directly, in which case the pairing file
   * from the constructor is used (or a fresh one is generated).
   */
  async pairSetup(
    pairingFileOrPin: RpPairingFile | string,
    pinProvider?: () => Promise<string>,
  ): Promise<void> {
    let pairingFile: RpPairingFile;
    let provider: () => Promise<string>;
    if (typeof pairingFileOrPin === 'string') {
      pairingFile = this.pairingFile ?? RpPairingFile.generate(this.sendingHost);
      const pin = pairingFileOrPin;
      provider = async () => pin;
    } else {
      pairingFile = pairingFileOrPin;
      if (!pinProvider) {
        throw new RemotePairingError('ProtocolError', 'pairSetup requires a PIN provider');
      }
      provider = pinProvider;
    }
    pairingFile.recreateSigningKeys();

    await this.sendPairingData({
      data: bytesToBase64(
        serializeTlv8([
          tlvEntry(PairingDataComponentType.Method, new Uint8Array([0x00])),
          tlvEntry(PairingDataComponentType.State, new Uint8Array([0x01])),
        ]),
      ),
      kind: 'setupManualPairing',
      sendingHost: this.sendingHost,
      startNewSession: true,
    });

    const e0 = await this.receivePairingEvent();

    let pin: string;
    let pairingDataBytes: Uint8Array;
    if (e0.awaitingUserConsent !== undefined) {
      // tvOS-style flow: wait for the user to accept, then read the next frame.
      this.onAwaitingUserConsent?.(pairingFile.identifier);
      pin = '000000';
      pairingDataBytes = await this.receivePairingData();
    } else {
      const b64 = e0?.pairingData?._0?.data;
      if (typeof b64 !== 'string') {
        throw new RemotePairingError('UnexpectedResponse', 'missing pairing data in pair consent response');
      }
      pairingDataBytes = base64ToBytes(b64);
      pin = await provider();
    }

    const consentTlv = deserializeTlv8(pairingDataBytes);
    if (containsComponent(consentTlv, PairingDataComponentType.ErrorResponse)) {
      throw new RemotePairingError('UnexpectedResponse', 'pairing data contained error response during pair consent');
    }
    const salt = collectComponentData(consentTlv, PairingDataComponentType.Salt);
    const serverPublicKey = collectComponentData(consentTlv, PairingDataComponentType.PublicKey);
    if (salt.length === 0 || serverPublicKey.length === 0) {
      throw new RemotePairingError('UnexpectedResponse', 'pairing data missing salt or public key');
    }

    const sessionKey = await this.initSrpContext(salt, serverPublicKey, pin);
    // Save the SRP session key as the encryption key (tunnel PSK).
    this.encryptionKeyValue = sessionKey;
    this.deriveMainCiphers(sessionKey);

    await this.savePairRecordOnPeer(pairingFile, sessionKey);
    this.pairingFile = pairingFile;
  }

  /**
   * Pair-verify using the pairing file from the constructor (or from a
   * previous `pairSetup`). Throws `PairVerifyFailed` when the device rejects
   * verification — the caller should then run `pairSetup(pin)`.
   */
  async pairVerify(): Promise<void> {
    const pf = this.pairingFile;
    if (!pf) {
      throw new RemotePairingError(
        'NotPaired',
        'no pairing file: pass one to the constructor or run pairSetup(pin) first',
      );
    }
    await this.attemptPairVerify(pf);
    this.pairingFile = pf;
  }

  /**
   * Serialize the active pairing file to an XML-plist string
   * (suitable for saving as `pairingFile.plist`).
   */
  savePairingFile(): string {
    const pf = this.pairingFile;
    if (!pf) {
      throw new RemotePairingError('NotPaired', 'no pairing file to save yet');
    }
    return td.decode(pf.toBytes());
  }

  /** SRP handshake; returns the session key (encryption key). */
  private async initSrpContext(
    salt: Uint8Array,
    serverPublicKey: Uint8Array,
    pin: string,
  ): Promise<Uint8Array> {
    const srp = new SrpClient();
    const aPriv = randomBytes(32);
    const aPub = srp.computePublicEphemeral(aPriv);

    let verifier: SrpVerifier;
    try {
      verifier = srp.processReply(
        aPriv,
        'Pair-Setup',
        te.encode(pin).slice(0, 6),
        salt,
        serverPublicKey,
        false,
      );
    } catch (e) {
      throw new RemotePairingError('SrpAuthFailed', `SRP verifier creation failed: ${(e as Error).message}`);
    }

    const clientProof = verifier.proof();

    await this.sendPairingData({
      data: bytesToBase64(
        serializeTlv8([
          tlvEntry(PairingDataComponentType.State, new Uint8Array([0x03])),
          tlvEntry(PairingDataComponentType.PublicKey, aPub.slice(0, 254)),
          tlvEntry(PairingDataComponentType.PublicKey, aPub.slice(254)),
          tlvEntry(PairingDataComponentType.Proof, clientProof),
        ]),
      ),
      kind: 'setupManualPairing',
      sendingHost: this.sendingHost,
      startNewSession: false,
    });

    const response = deserializeTlv8(await this.receivePairingData());
    const proofEntry = response.find((e) => e.type === PairingDataComponentType.Proof);
    if (!proofEntry) {
      throw new RemotePairingError('UnexpectedResponse', 'missing server proof in SRP response');
    }
    if (!verifier.verifyServer(proofEntry.data)) {
      throw new RemotePairingError('SrpAuthFailed', 'server auth failed');
    }
    return verifier.key();
  }

  /** Encrypt our pair record, send it, and store the peer's altIRK in the pairing file. */
  private async savePairRecordOnPeer(
    pairingFile: RpPairingFile,
    encryptionKey: Uint8Array,
  ): Promise<void> {
    const setupEncryptionKey = hkdfSha512(
      encryptionKey,
      te.encode('Pair-Setup-Encrypt-Salt'),
      'Pair-Setup-Encrypt-Info',
      32,
    );

    const controllerSignSalt = hkdfSha512(
      encryptionKey,
      te.encode('Pair-Setup-Controller-Sign-Salt'),
      'Pair-Setup-Controller-Sign-Info',
      32,
    );

    const idBytes = te.encode(pairingFile.identifier);
    const edPub = pairingFile.publicKey;
    const signbuf = concat(controllerSignSalt, idBytes, edPub);
    const signature = ed25519.sign(signbuf, pairingFile.privateKey);

    const deviceInfo: PlistValue = {
      altIRK: randomBytes(16),
      btAddr: '11:22:33:44:55:66',
      mac: new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
      remotepairing_serial_number: 'AAAAAAAAAAAA',
      accountID: pairingFile.identifier,
      model: 'computer-model',
      name: this.sendingHost,
    } as PlistValue;
    const deviceInfoOpack = plistToOpack(deviceInfo);

    const plaintext = serializeTlv8([
      tlvEntry(PairingDataComponentType.Identifier, idBytes),
      tlvEntry(PairingDataComponentType.PublicKey, edPub),
      tlvEntry(PairingDataComponentType.Signature, signature),
      tlvEntry(PairingDataComponentType.Info, deviceInfoOpack),
    ]);

    const nonce5 = concat(new Uint8Array(4), te.encode('PS-Msg05')); // 12-byte nonce
    const ciphertext = chachaEncrypt(setupEncryptionKey, nonce5, plaintext);

    await this.sendPairingData({
      data: bytesToBase64(
        serializeTlv8([
          tlvEntry(PairingDataComponentType.EncryptedData, ciphertext.slice(0, 254)),
          tlvEntry(PairingDataComponentType.EncryptedData, ciphertext.slice(254)),
          tlvEntry(PairingDataComponentType.State, new Uint8Array([0x05])),
        ]),
      ),
      kind: 'setupManualPairing',
      sendingHost: this.sendingHost,
      startNewSession: false,
    });

    const responseTlv = deserializeTlv8(await this.receivePairingData());
    if (containsComponent(responseTlv, PairingDataComponentType.ErrorResponse)) {
      throw new RemotePairingError('UnexpectedResponse', 'TLV error response in pair record save');
    }
    const encryptedData = collectComponentData(responseTlv, PairingDataComponentType.EncryptedData);

    const nonce6 = concat(new Uint8Array(4), te.encode('PS-Msg06'));
    const respPlaintext = chachaDecrypt(setupEncryptionKey, nonce6, encryptedData);
    const respEntries = deserializeTlv8(respPlaintext);

    const infoBytes = collectComponentData(respEntries, PairingDataComponentType.Info);
    if (infoBytes.length === 0) {
      throw new RemotePairingError('UnexpectedResponse', 'missing info payload in pair record response');
    }
    const info = opackToPlist(infoBytes) as unknown as Record<string, unknown>;
    const altIrk = (info as { altIRK?: unknown } | null)?.altIRK;
    if (!(altIrk instanceof Uint8Array) || altIrk.length !== 16) {
      throw new RemotePairingError('UnexpectedResponse', 'invalid altIRK in peer device info');
    }
    pairingFile.altIrk = altIrk;
  }

  // -- encrypted RPC ------------------------------------------------------------

  /**
   * Send an encrypted request (ClientEncrypt-main). The matching response must
   * be read with {@link receiveEncryptedResponse}; both use the same nonce
   * (8-byte LE encrypted sequence number + 4 zero bytes).
   */
  async sendEncryptedRequest<T>(request: T): Promise<void> {
    const plaintext = te.encode(JSON.stringify(request));
    const nonce = concat(u64leBytes(this.encryptedSequenceNumber), new Uint8Array(4));
    const ciphertext = chachaEncrypt(this.clientAeadKey, nonce, plaintext);
    this.pendingResponseNonce = nonce;
    await this.sendEncryptedFrame(ciphertext);
  }

  /** Receive and decrypt the response to the last {@link sendEncryptedRequest}. */
  async receiveEncryptedResponse<T = any>(): Promise<T> {
    const frame = await readFrame(this.transport);
    const b64 = frame?.message?.streamEncrypted?._0;
    if (typeof b64 !== 'string') {
      throw new RemotePairingError('UnexpectedResponse', 'missing encrypted data in streamEncrypted response');
    }
    const nonce = this.pendingResponseNonce ?? concat(u64leBytes(this.encryptedSequenceNumber), new Uint8Array(4));
    const decrypted = chachaDecrypt(this.serverAeadKey, nonce, base64ToBytes(b64));
    this.pendingResponseNonce = undefined;
    this.encryptedSequenceNumber += 1n;
    const value = JSON.parse(td.decode(decrypted));
    const result = value?.response?._1;
    if (result === undefined) {
      throw new RemotePairingError('UnexpectedResponse', 'missing response._1 in encrypted response');
    }
    return result as T;
  }

  /**
   * Ask the device to create a TCP tunnel listener. Returns the port the
   * device is listening on plus the listener identifier.
   */
  async createListener(): Promise<{ port: number; identifier: string }> {
    const encryptionKey = this.encryptionKey; // throws NotPaired when unpaired
    await this.sendEncryptedRequest({
      request: {
        _0: {
          createListener: {
            key: bytesToBase64(encryptionKey),
            transportProtocolType: 'tcp',
          },
        },
      },
    });
    const response = await this.receiveEncryptedResponse();
    const port = response?.createListener?.port;
    if (typeof port !== 'number') {
      throw new RemotePairingError('UnexpectedResponse', 'missing createListener.port in response');
    }
    const identifier =
      typeof response?.createListener?.identifier === 'string'
        ? response.createListener.identifier
        : (this.pairingFile?.identifier ?? '');
    return { port, identifier };
  }

  /**
   * Query Remote Service Discovery info over the encrypted channel. The
   * returned object carries the RSCI needed by establishTunnel() when the
   * caller did not supply one.
   */
  async rsdInfo(): Promise<any> {
    await this.sendEncryptedRequest({
      request: { _0: { rsdInfo: {} } },
    });
    return this.receiveEncryptedResponse();
  }
}

// ---------------------------------------------------------------------------
// TLS 1.2 PSK (port of tls_psk.rs)
// ---------------------------------------------------------------------------

const TLS_VERSION_BYTES = new Uint8Array([0x03, 0x03]);
const CT_CHANGE_CIPHER_SPEC = 0x14;
const CT_ALERT = 0x15;
const CT_HANDSHAKE = 0x16;
const CT_APPLICATION_DATA = 0x17;
const TLS_MAX_PLAINTEXT = 16384;

const HS_CLIENT_HELLO = 0x01;
const HS_SERVER_HELLO = 0x02;
const HS_SERVER_HELLO_DONE = 0x0e;
const HS_CLIENT_KEY_EXCHANGE = 0x10;
const HS_FINISHED = 0x14;

const PSK_CIPHER_SUITES: Array<readonly [number, number]> = [
  [0x00, 0xaf], // TLS_PSK_WITH_AES_256_CBC_SHA384 (preferred by iOS)
  [0x00, 0x8c], // TLS_PSK_WITH_AES_128_CBC_SHA (fallback)
];

type NobleHash = CHash;

interface TlsCipherSuite {
  name: string;
  /** PRF hash (P_hash) */
  prfHash: NobleHash;
  /** Record MAC hash */
  macHash: NobleHash;
  encKeyLen: number;
  macKeyLen: number;
}

export type { TlsCipherSuite };

export function cipherSuiteFromBytes(b: Uint8Array): TlsCipherSuite {
  if (b.length >= 2 && b[0] === 0x00 && b[1] === 0xaf) {
    return { name: 'TLS_PSK_WITH_AES_256_CBC_SHA384', prfHash: sha384, macHash: sha384, encKeyLen: 32, macKeyLen: 48 };
  }
  if (b.length >= 2 && b[0] === 0x00 && b[1] === 0x8c) {
    return { name: 'TLS_PSK_WITH_AES_128_CBC_SHA', prfHash: sha256, macHash: sha1, encKeyLen: 16, macKeyLen: 20 };
  }
  throw new RemotePairingError('TlsError', `server selected unsupported cipher suite`);
}

interface TlsKeyBlock {
  clientMacKey: Uint8Array;
  serverMacKey: Uint8Array;
  clientWriteKey: Uint8Array;
  serverWriteKey: Uint8Array;
}

export type { TlsKeyBlock };

/** TLS 1.2 PRF: P_hash with the suite's PRF hash. */
export function tlsPrf(
  secret: Uint8Array,
  label: Uint8Array,
  seed: Uint8Array,
  len: number,
  suite: TlsCipherSuite,
): Uint8Array {
  const labelSeed = concat(label, seed);
  let a = hmac(suite.prfHash, secret, labelSeed);
  const blocks: Uint8Array[] = [];
  let total = 0;
  while (total < len) {
    const block = hmac(suite.prfHash, secret, concat(a, labelSeed));
    blocks.push(block);
    total += block.length;
    a = hmac(suite.prfHash, secret, a);
  }
  return concat(...blocks).slice(0, len);
}

/** PSK premaster secret (RFC 4279 §2). */
export function pskPremaster(psk: Uint8Array): Uint8Array {
  const lenBytes = u16be(psk.length);
  return concat(lenBytes, new Uint8Array(psk.length), lenBytes, psk);
}

export function deriveMasterSecret(
  psk: Uint8Array,
  clientRandom: Uint8Array,
  serverRandom: Uint8Array,
  suite: TlsCipherSuite,
): Uint8Array {
  const premaster = pskPremaster(psk);
  return tlsPrf(premaster, te.encode('master secret'), concat(clientRandom, serverRandom), 48, suite);
}

export function deriveKeyBlock(
  master: Uint8Array,
  clientRandom: Uint8Array,
  serverRandom: Uint8Array,
  suite: TlsCipherSuite,
): TlsKeyBlock {
  const macLen = suite.macKeyLen;
  const keyLen = suite.encKeyLen;
  const kb = tlsPrf(master, te.encode('key expansion'), concat(serverRandom, clientRandom), macLen * 2 + keyLen * 2, suite);
  let pos = 0;
  const take = (n: number): Uint8Array => {
    const s = kb.slice(pos, pos + n);
    pos += n;
    return s;
  };
  return {
    clientMacKey: take(macLen),
    serverMacKey: take(macLen),
    clientWriteKey: take(keyLen),
    serverWriteKey: take(keyLen),
  };
}

function computeMac(
  macKey: Uint8Array,
  seq: number | bigint,
  ct: number,
  data: Uint8Array,
  suite: TlsCipherSuite,
): Uint8Array {
  const buf = concat(u64be(seq), new Uint8Array([ct, 0x03, 0x03]), u16be(data.length), data);
  return hmac(suite.macHash, macKey, buf);
}

export function encryptTlsRecord(
  keys: TlsKeyBlock,
  suite: TlsCipherSuite,
  seq: number | bigint,
  ct: number,
  plaintext: Uint8Array,
): Uint8Array {
  const mac = computeMac(keys.clientMacKey, seq, ct, plaintext, suite);
  let payload = concat(plaintext, mac);
  // Padding quirk copied from the Rust implementation: pad_len bytes of value (pad_len - 1).
  const padLen = 16 - (payload.length % 16);
  payload = concat(payload, new Uint8Array(padLen).fill(padLen - 1));

  const iv = randomBytes(16);
  const ciphertext = cbc(keys.clientWriteKey, iv, { disablePadding: true }).encrypt(payload);
  return concat(iv, ciphertext);
}

export function decryptTlsRecord(
  keys: TlsKeyBlock,
  suite: TlsCipherSuite,
  isServer: boolean,
  seq: number | bigint,
  ct: number,
  encrypted: Uint8Array,
): Uint8Array {
  if (encrypted.length < 16) {
    throw new RemotePairingError('TlsError', 'TLS record too short');
  }
  const iv = encrypted.slice(0, 16);
  const ciphertext = encrypted.slice(16);
  const readKey = isServer ? keys.serverWriteKey : keys.clientWriteKey;
  const macKey = isServer ? keys.serverMacKey : keys.clientMacKey;

  const decrypted = cbc(readKey, iv, { disablePadding: true }).decrypt(ciphertext);
  if (decrypted.length === 0) {
    throw new RemotePairingError('TlsError', 'empty decrypted TLS data');
  }
  // Remove padding: last byte is pad_value, strip (pad_value + 1) bytes.
  const padValue = decrypted[decrypted.length - 1];
  const contentLen = decrypted.length - (padValue + 1);
  const macLen = suite.macKeyLen;
  if (contentLen < macLen) {
    throw new RemotePairingError('TlsError', 'decrypted TLS content too short for MAC');
  }
  const plaintext = decrypted.slice(0, contentLen - macLen);
  const receivedMac = decrypted.slice(contentLen - macLen, contentLen);
  const expectedMac = computeMac(macKey, seq, ct, plaintext, suite);
  if (!bytesEqual(receivedMac, expectedMac)) {
    throw new RemotePairingError('TlsError', 'TLS MAC verification failed');
  }
  return plaintext;
}

export function finishedVerifyData(
  master: Uint8Array,
  label: string,
  transcript: Uint8Array,
  suite: TlsCipherSuite,
): Uint8Array {
  const hash = suite.prfHash(transcript);
  return tlsPrf(master, te.encode(label), hash, 12, suite);
}

export function makeTlsRecord(ct: number, payload: Uint8Array): Uint8Array {
  return concat(new Uint8Array([ct]), TLS_VERSION_BYTES, u16be(payload.length), payload);
}

export function makeHandshakeMessage(msgType: number, body: Uint8Array): Uint8Array {
  const len = body.length;
  return concat(
    new Uint8Array([msgType, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff]),
    body,
  );
}

async function readTlsRecord(raw: RpTransport): Promise<[number, Uint8Array]> {
  const header = await raw.readExact(5);
  const ct = header[0];
  const len = (header[3] << 8) | header[4];
  const payload = await raw.readExact(len);
  return [ct, payload];
}

interface HandshakeMessage {
  type: number;
  body: Uint8Array;
}

/** Split a handshake record payload into its handshake messages. */
function parseHandshakeMessages(data: Uint8Array): HandshakeMessage[] {
  const msgs: HandshakeMessage[] = [];
  let pos = 0;
  while (pos + 4 <= data.length) {
    const msgType = data[pos];
    const msgLen = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    if (pos + 4 + msgLen > data.length) break;
    msgs.push({ type: msgType, body: data.slice(pos + 4, pos + 4 + msgLen) });
    pos += 4 + msgLen;
  }
  return msgs;
}

function tlsAlertError(payload: Uint8Array, where: string): RemotePairingError {
  const level = payload.length > 0 ? payload[0] : 0;
  const desc = payload.length > 1 ? payload[1] : 0;
  const name =
    desc === 0 ? 'close_notify'
    : desc === 10 ? 'unexpected_message'
    : desc === 20 ? 'bad_record_mac'
    : desc === 40 ? 'handshake_failure'
    : desc === 47 ? 'illegal_parameter'
    : desc === 70 ? 'protocol_version'
    : desc === 71 ? 'insufficient_security'
    : desc === 80 ? 'internal_error'
    : 'unknown';
  return new RemotePairingError('TlsError', `TLS Alert${where}: level=${level} desc=${desc} (${name})`);
}

/**
 * An encrypted TLS-PSK stream. Also implements {@link RpTransport} so it can
 * be used as a drop-in encrypted transport (application data records).
 */
export class TlsPskStream implements RpTransport {
  private pending: Uint8Array = new Uint8Array(0);
  /** Set by establishTunnel() after the CDTunnel handshake. */
  tunnelInfo!: TunnelInfo;

  constructor(
    private readonly raw: RpTransport,
    private readonly keys: TlsKeyBlock,
    private readonly suite: TlsCipherSuite,
    private writeSeq: number,
    private readSeq: number,
  ) {}

  /** Encrypt and send application data, splitting into TLS records if needed. */
  async writeAppData(data: Uint8Array): Promise<void> {
    for (let off = 0; off < data.length; off += TLS_MAX_PLAINTEXT) {
      const chunk = data.slice(off, off + TLS_MAX_PLAINTEXT);
      const encrypted = encryptTlsRecord(this.keys, this.suite, this.writeSeq, CT_APPLICATION_DATA, chunk);
      this.writeSeq += 1;
      await this.raw.write(makeTlsRecord(CT_APPLICATION_DATA, encrypted));
    }
  }

  /** Read and decrypt one application-data record. */
  async readAppData(): Promise<Uint8Array> {
    const [ct, payload] = await readTlsRecord(this.raw);
    if (ct !== CT_APPLICATION_DATA) {
      throw new RemotePairingError('TlsError', `expected application data, got ct=${ct}`);
    }
    const plaintext = decryptTlsRecord(this.keys, this.suite, true, this.readSeq, CT_APPLICATION_DATA, payload);
    this.readSeq += 1;
    return plaintext;
  }

  async write(data: Uint8Array): Promise<void> {
    await this.writeAppData(data);
  }

  async readExact(n: number): Promise<Uint8Array> {
    while (this.pending.length < n) {
      this.pending = concat(this.pending, await this.readAppData());
    }
    const out = this.pending.slice(0, n);
    this.pending = this.pending.slice(n);
    return out;
  }

  /** Push bytes back to the front of the read buffer (for handshake leftovers). */
  pushBack(data: Uint8Array): void {
    if (data.length > 0) this.pending = concat(data, this.pending);
  }

  close(): void {
    this.raw.close();
  }
}

/**
 * Perform the TLS 1.2 PSK handshake over `raw` and return an encrypted stream.
 * Offers TLS_PSK_WITH_AES_256_CBC_SHA384 and TLS_PSK_WITH_AES_128_CBC_SHA.
 */
export async function tlsPskHandshake(raw: RpTransport, psk: Uint8Array): Promise<TlsPskStream> {
  const clientRandom = randomBytes(32);
  const serverRandom: Uint8Array = new Uint8Array(32);
  let selectedCipher: Uint8Array = new Uint8Array([0, 0]);
  let transcript: Uint8Array = new Uint8Array(0);

  // 1. ClientHello
  const suiteBytes = concat(...PSK_CIPHER_SUITES.map((s) => new Uint8Array(s)));
  const chBody = concat(
    TLS_VERSION_BYTES,
    clientRandom,
    new Uint8Array([0x00]), // session_id len = 0
    u16be(suiteBytes.length),
    suiteBytes,
    new Uint8Array([0x01, 0x00]), // compression: null
  );
  const ch = makeHandshakeMessage(HS_CLIENT_HELLO, chBody);
  transcript = concat(transcript, ch);
  await raw.write(makeTlsRecord(CT_HANDSHAKE, ch));

  // 2. Read ServerHello .. ServerHelloDone
  for (;;) {
    const [ct, payload] = await readTlsRecord(raw);
    if (ct === CT_ALERT) throw tlsAlertError(payload, '');
    if (ct !== CT_HANDSHAKE) {
      throw new RemotePairingError('TlsError', `expected handshake, got ct=${ct}`);
    }
    transcript = concat(transcript, payload);

    for (const msg of parseHandshakeMessages(payload)) {
      if (msg.type === HS_SERVER_HELLO) {
        // Body: 2 version, 32 random, 1 session_id_len, session_id, 2 cipher_suite
        if (msg.body.length >= 38) {
          serverRandom.set(msg.body.slice(2, 34));
          const sidLen = msg.body[34];
          if (msg.body.length >= 37 + sidLen) {
            selectedCipher = msg.body.slice(35 + sidLen, 37 + sidLen);
          }
        }
      }
    }
    if (parseHandshakeMessages(payload).some((m) => m.type === HS_SERVER_HELLO_DONE)) break;
  }

  // 3. Derive keys
  const suite = cipherSuiteFromBytes(selectedCipher);
  const master = deriveMasterSecret(psk, clientRandom, serverRandom, suite);
  const keys = deriveKeyBlock(master, clientRandom, serverRandom, suite);

  // 4. ClientKeyExchange (empty PSK identity)
  const cke = makeHandshakeMessage(HS_CLIENT_KEY_EXCHANGE, new Uint8Array([0x00, 0x00]));
  transcript = concat(transcript, cke);
  await raw.write(makeTlsRecord(CT_HANDSHAKE, cke));

  // 5. ChangeCipherSpec
  await raw.write(makeTlsRecord(CT_CHANGE_CIPHER_SPEC, new Uint8Array([0x01])));

  // 6. Client Finished (encrypted)
  const clientVd = finishedVerifyData(master, 'client finished', transcript, suite);
  const fin = makeHandshakeMessage(HS_FINISHED, clientVd);
  transcript = concat(transcript, fin);
  await raw.write(makeTlsRecord(CT_HANDSHAKE, encryptTlsRecord(keys, suite, 0, CT_HANDSHAKE, fin)));

  // 7. Read server ChangeCipherSpec + Finished
  let serverSeq = 0;
  for (;;) {
    const [ct, payload] = await readTlsRecord(raw);
    if (ct === CT_ALERT) throw tlsAlertError(payload, ' after Finished');
    if (ct === CT_CHANGE_CIPHER_SPEC) continue;
    const plaintext = decryptTlsRecord(keys, suite, true, serverSeq, CT_HANDSHAKE, payload);
    serverSeq += 1;
    if (plaintext.length >= 4 && plaintext[0] === HS_FINISHED) {
      const serverVd = finishedVerifyData(master, 'server finished', transcript, suite);
      // The Rust implementation logs a mismatch but continues; do the same.
      if (!bytesEqual(plaintext.slice(4), serverVd)) {
        // mismatch tolerated
      }
      break;
    }
  }

  return new TlsPskStream(raw, keys, suite, 1, serverSeq);
}

// ---------------------------------------------------------------------------
// CDTunnel (port of tunnel.rs)
// ---------------------------------------------------------------------------

const CDTUNNEL_MAGIC = te.encode('CDTunnel'); // 8 bytes
const DEFAULT_MTU = 16000;

/** Client parameters for establishing a CDTunnel. */
export interface TunnelClientParameters {
  /** Remote session channel identifier; fetched via rsdInfo() when omitted. */
  rsci?: Uint8Array;
  /** Desired client address (optional; the device assigns one). */
  clientAddress?: string;
  /** Desired netmask (optional). */
  netmask?: string;
  /** Desired MTU (optional; defaults to 16000). */
  mtu?: number;
}

/** Negotiated tunnel parameters from the CDTunnel handshake. */
export class TunnelInfo {
  readonly clientAddress: string;
  readonly netmask: string;
  readonly serverAddress: string;
  readonly mtu: number;
  readonly serverRsdPort: number;

  constructor(
    clientAddress: string,
    netmask: string,
    serverAddress: string,
    mtu: number,
    serverRsdPort: number,
  ) {
    this.clientAddress = clientAddress;
    this.netmask = netmask;
    this.serverAddress = serverAddress;
    this.mtu = mtu;
    this.serverRsdPort = serverRsdPort;
  }

  /** Parse a CDTunnel handshake response JSON object. */
  static fromHandshakeResponse(response: any): TunnelInfo {
    const clientParams = response?.clientParameters;
    if (clientParams === undefined || clientParams === null) {
      throw new RemotePairingError('TunnelError', 'missing clientParameters in CDTunnel response');
    }
    const str = (v: unknown, field: string): string => {
      if (typeof v !== 'string') {
        throw new RemotePairingError('TunnelError', `missing ${field} in CDTunnel response`);
      }
      return v;
    };
    return new TunnelInfo(
      str(clientParams.address, 'client address'),
      typeof clientParams.netmask === 'string' ? clientParams.netmask : '',
      str(response.serverAddress, 'server address'),
      typeof clientParams.mtu === 'number' ? clientParams.mtu : 1500,
      typeof response.serverRSDPort === 'number' ? response.serverRSDPort : 0,
    );
  }
}

/** An encrypted tunnel transport that also carries the negotiated {@link TunnelInfo}. */
export interface TunnelTransport extends RpTransport {
  tunnelInfo: TunnelInfo;
}

/** A CDTunnel: an encrypted tunnel transport plus its negotiated info. */
export class CDTunnel {
  readonly tunnel: TunnelTransport;
  constructor(transport: TunnelTransport) {
    this.tunnel = transport;
  }
  async close(): Promise<void> {
    this.tunnel.close();
  }
}

/** Perform the CDTunnel handshake over an established TLS-PSK stream. */
export async function performCdTunnelHandshake(tls: TlsPskStream, mtu: number): Promise<TunnelTransport> {
  const body = te.encode(JSON.stringify({ type: 'clientHandshakeRequest', mtu }));
  await tls.writeAppData(concat(CDTUNNEL_MAGIC, u16be(body.length), body));

  // The response may span multiple application-data records; accumulate.
  let buf: Uint8Array = new Uint8Array(0);
  for (;;) {
    if (buf.length >= CDTUNNEL_MAGIC.length + 2) {
      const bodyLen = (buf[CDTUNNEL_MAGIC.length] << 8) | buf[CDTUNNEL_MAGIC.length + 1];
      if (buf.length >= CDTUNNEL_MAGIC.length + 2 + bodyLen) break;
    }
    buf = concat(buf, await tls.readAppData());
  }

  if (!bytesEqual(buf.slice(0, CDTUNNEL_MAGIC.length), CDTUNNEL_MAGIC)) {
    throw new RemotePairingError('TunnelError', 'CDTunnel handshake response missing magic header');
  }
  const bodyLen = (buf[CDTUNNEL_MAGIC.length] << 8) | buf[CDTUNNEL_MAGIC.length + 1];
  const responseBody = buf.slice(CDTUNNEL_MAGIC.length + 2, CDTUNNEL_MAGIC.length + 2 + bodyLen);
  tls.pushBack(buf.slice(CDTUNNEL_MAGIC.length + 2 + bodyLen));

  let response: any;
  try {
    response = JSON.parse(td.decode(responseBody));
  } catch (e) {
    throw new RemotePairingError('TunnelError', `invalid CDTunnel handshake JSON: ${(e as Error).message}`);
  }

  const transport: TunnelTransport = tls;
  transport.tunnelInfo = TunnelInfo.fromHandshakeResponse(response);
  return transport;
}

/**
 * Establish a CDTunnel: pair (if needed), fetch the RSCI, run the TLS-PSK
 * handshake, then the CDTunnel handshake.
 *
 * @param raw transport to the device's Remote Pairing port
 * @param clientParams tunnel parameters (rsci fetched via rsdInfo() when omitted)
 * @param onAwaitingUserConsent optional callback for the tvOS consent flow
 * @param pairingFileOrPin existing pairing file, or a PIN string for pair-setup
 */
export async function establishTunnel(
  raw: RpTransport,
  clientParams: TunnelClientParameters,
  onAwaitingUserConsent?: (identifier: string) => void,
  pairingFileOrPin?: RpPairingFile | string,
): Promise<CDTunnel> {
  const client = new RemotePairingClient(
    raw,
    typeof pairingFileOrPin === 'object' ? pairingFileOrPin : undefined,
  );
  if (onAwaitingUserConsent) {
    client.onAwaitingUserConsent = onAwaitingUserConsent;
  }
  const mtu = clientParams.mtu ?? DEFAULT_MTU;

  const connect = async (): Promise<CDTunnel> => {
    await client.startSession(pairingFileOrPin);
    // Resolve the RSCI when the caller didn't provide one. (The CDTunnel
    // handshake itself only carries type+mtu, matching the Rust reference.)
    let rsci = clientParams.rsci;
    if (!rsci) {
      const info = await client.rsdInfo();
      const rawRsci = info?.rsci;
      rsci = typeof rawRsci === 'string' ? base64ToBytes(rawRsci) : undefined;
    }
    void rsci; // (kept for API parity; the device-side handshake is type+mtu)
    const tls = await tlsPskHandshake(raw, client.encryptionKey);
    const transport = await performCdTunnelHandshake(tls, mtu);
    return new CDTunnel(transport);
  };

  try {
    return await connect();
  } catch (e) {
    // If the TLS handshake fails and we paired with a PIN, the stored pairing
    // is likely stale (e.g. the device was restored). Drop it, re-pair with
    // the PIN, and retry once.
    if (e instanceof RemotePairingError && e.code === 'TlsError' && typeof pairingFileOrPin === 'string') {
      client.pairingFile = undefined;
      return await connect();
    }
    throw e;
  }
}

// Keep the SrpVerifier import referenced for type-checking consumers.
export type { SrpVerifier };
