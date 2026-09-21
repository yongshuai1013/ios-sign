/**
 * Barrel for the SideImpactor pairing stack (TypeScript port of
 * https://github.com/lbr77/SideImpactor pairing flows, with pairing-file
 * formats from https://github.com/jkcoxson/idevice_pair).
 *
 * Naming conflicts between modules are resolved explicitly:
 * - `Transport` is the canonical usbmuxd transport `{ read(n), write, close() }`.
 * - `ByteTransport` is the exact-read transport `{ write, readExact(n), close() }`.
 * - `LockdownPairRecord` is the client-side struct; `LockdownPairRecordDict`
 *   is the on-disk plist dictionary.
 * - `RemotePairingFile` is the `RpPairingFile` class alias; `RemotePairingFileDict`
 *   is the on-disk plist dictionary.
 */

// --- TLV8 -----------------------------------------------------------------
export {
  PairingDataComponentType,
  serializeTlv8,
  deserializeTlv8,
  collectComponentData,
  containsComponent,
  encodeTLV,
  decodeTLV,
} from './tlv.js';
export type { TLV8Entry, TlvEntry } from './tlv.js';

// --- OPACK -----------------------------------------------------------------
export {
  plistToOpack,
  opackToPlist,
  encode as encodeOpack,
  decode as decodeOpack,
} from './opack.js';
export type { PlistValue } from './opack.js';

// --- Pairing files (idevice_pair formats) -----------------------------------
export {
  PairingFile,
  RpPairingFile,
  parseLockdownPairRecord,
  serializeLockdownPairRecord,
  parseRemotePairingFile,
  serializeRemotePairingFile,
  generateRemotePairingFile,
  generateHostID,
  generateSystemBUID,
} from './pairing-file.js';
export type {
  PairingFileInit,
  RpPairingFileInit,
  LockdownPairRecord as LockdownPairRecordDict,
  RemotePairingFile as RemotePairingFileDict,
} from './pairing-file.js';

// --- SRP-3072 / SHA-512 ------------------------------------------------------
export {
  SRP_GROUP_N,
  SRP_GROUP_G,
  SRP_N_HEX,
  srpK,
  srpU,
  srpX,
  SrpClient,
  SrpPairSetupClient,
} from './srp.js';
export type { SrpVerifier, SrpPairSetupProof } from './srp.js';

// --- CA / X.509 (self-signed pairing certificates) ---------------------------
export {
  CERT_LIFETIME_SECS,
  createRootCA,
  issueHostCertificate,
  issueDeviceCertificate,
  generateCertificates,
} from './ca.js';
export type { RootCA, HostCertificate, CaResult } from './ca.js';

// --- usbmuxd transport + lockdownd -------------------------------------------
export { LOCKDOWN_PORT, USBMUXD_DEFAULT_PORT } from './usbmuxd.js';
export {
  UsbmuxdClient,
  UsbmuxdError,
  PlistSocket,
  createNodeTcpTransport,
  copyBytes,
  encodeUsbmuxdPacket,
  decodeUsbmuxdPacket,
  MAX_PLIST_FRAME,
} from './usbmuxd.js';
export type {
  Transport,
  DeviceInfo,
  UsbmuxdDeviceInfo,
  UsbmuxdPacket,
} from './usbmuxd.js';
export {
  LockdownClient,
  LockdownError,
  PairingPendingError,
  pairDevice,
  pairRecordToDict,
} from './lockdown.js';
export type {
  LockdownPairRecord,
  LockdownPairingErrorCode,
  CertificateAuthority,
  PairDeviceOptions,
} from './lockdown.js';

// --- WebUSB MUX (TCP-over-MUX in the browser) ---------------------------------
// `LOCKDOWN_PORT` (62078) is exported once from usbmuxd.js above.
export {
  WebUsbMuxDevice,
  WebUsbMux,
  MuxTcpChannel,
  MuxTcpConnection,
  TcpTransport,
  WebUsbMuxError,
  APPLE_VENDOR_ID,
  USBMUX_INTERFACE_CLASS,
  USBMUX_INTERFACE_SUBCLASS,
  USBMUX_INTERFACE_PROTOCOL,
  MUX_PROTO_VERSION,
  MUX_PROTO_CONTROL,
  MUX_PROTO_SETUP,
  MUX_PROTO_TCP,
  MUX_MAGIC_HOST,
  MUX_MAGIC_DEVICE_ALT,
  TCP_FLAG_FIN,
  buildAppleUsbFilters,
  encodeMuxHeader,
  decodeMuxHeader,
  encodeMuxPacket,
  encodeTcpPacket,
  decodeTcpPacket,
} from './webusb-mux.js';
export type {
  Transport as WebUsbTransport,
  ByteTransport as WebUsbByteTransport,
  UsbDisconnectHandler,
  WebUsbMuxOptions,
  WebUsbMuxDeviceOptions,
  MuxConnectOptions,
  MuxEncodeOptions,
  DecodedMuxHeader,
  TcpHeaderFields,
  MuxTcpState,
  TcpFrameSink,
} from './webusb-mux.js';

// --- AFC ---------------------------------------------------------------------
export { AfcClient, AfcError, AFC_MAGIC, AFC_HEADER_LEN } from './afc.js';

// Minimal TLS 1.0–1.2 client for the lockdownd StartSession TLS upgrade.
export {
  tlsConnect,
  TlsTransport,
  TlsError,
  pemToDer,
  parseRsaPrivateKey,
} from './tls-client.js';
export type { TlsConnectOptions, RsaPrivateKey, PemBlock } from './tls-client.js';export type {
  ByteTransport,
  AfcResponse,
  AfcOpcode,
  AfcFopenMode,
} from './afc.js';
export type { ByteTransport as InstallByteTransport } from './installation-proxy.js';

// --- installation_proxy ------------------------------------------------------
export {
  InstallationProxyClient,
  InstallationProxyError,
  INSTALL_MESSAGE_TIMEOUT_MS,
  MAX_INSTALL_MESSAGES,
  sanitizeIpaFileName,
  installIpa,
} from './installation-proxy.js';
export type { InstallProgressEvent, InstallOptions } from './installation-proxy.js';

// --- Remote Pairing (idevice Remote Pairing port) -------------------------------
export {
  RemotePairingClient,
  RemotePairingError,
  WIRE_PROTOCOL_VERSION,
  RPPAIRING_MAGIC_BYTES,
  sendFrame,
  readFrame,
  cipherSuiteFromBytes,
  tlsPrf,
  pskPremaster,
  deriveMasterSecret,
  deriveKeyBlock,
  encryptTlsRecord,
  decryptTlsRecord,
  finishedVerifyData,
  makeTlsRecord,
  makeHandshakeMessage,
  TlsPskStream,
  tlsPskHandshake,
  TunnelInfo,
  CDTunnel,
  performCdTunnelHandshake,
  establishTunnel,
} from './remote-pairing.js';
export type {
  RemotePairingFile,
  RemotePairingErrorCode,
  RpTransport,
  Transport as RemoteTransport,
  PairingDataPayload,
  TunnelClientParameters,
  TunnelTransport,
} from './remote-pairing.js';
