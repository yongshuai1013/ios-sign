/**
 * Apple Developer signing via `altsign.js`.
 *
 * - Login: Apple SRP (`AppleAPI.authenticate`) with anisette data; 2FA is
 *   bridged to the UI through {@link TwoFactorContext} (trusted-device
 *   push codes; SMS is not implemented by altsign.js and reports a clear
 *   error).
 * - Teams / certificates / devices / App IDs / provisioning profiles come
 *   from the developer portal API.
 * - Signing: `signIPA` (zsign-WASM) with a developer certificate whose
 *   private key is cached in localStorage per `appleId::teamId`.
 *
 * All HTTP goes through the routed transport in `lib/network.ts`
 * (libcurl-WASM over WISP, direct-fetch fallback).
 */
import {
  AppleAPI,
  signIPA,
  type AnisetteData as AltAnisetteData,
  type AppleAPISession,
  type Certificate as AltCertificate,
  type Device as AltDevice,
  type Team as AltTeam,
} from 'altsign.js';
import { unzipSync, zipSync } from 'fflate';
import { parsePlist, plistString, type PlistValue } from './lib/plist';
import { sanitizeFilename } from './lib/filenames';
import type { AnisetteData } from './anisette-service';
import { getAnisetteData } from './anisette-service';
import { createAppleFetch, ensureLibcurl } from './lib/network';
import { base64ToBytes, bytesToBase64 } from './lib/ids';
import { loadText, saveText } from './lib/storage';

export interface AppleSigningCredentials {
  appleId: string;
  password: string;
}

export interface Team {
  identifier: string;
  name: string;
}

export interface Certificate {
  id: string;
  name: string;
  serialNumber: string;
  pem: string;
}

export interface Device {
  udid: string;
  name: string;
}

export interface AppleDeveloperSession {
  anisetteData: AnisetteData;
  dsid: string;
  authToken: string;
}

export interface AppleDeveloperContext {
  appleId: string;
  session: AppleDeveloperSession;
  team: Team;
  certificates: Certificate[];
  devices: Device[];
}

export interface TrustedPhoneNumber {
  id: number;
  numberWithDialCode: string;
  obfuscatedNumber: string;
  pushMode: string;
}

export interface TwoFactorContext {
  /** Submit a 6-digit code that was pushed to a trusted device. */
  submitDeviceCode: (code: string) => void;
  /** Available trusted phone numbers for SMS fallback. Empty when none. */
  trustedPhoneNumbers: TrustedPhoneNumber[];
  /** Request an SMS be sent to the given phone id, then call submitSmsCode. */
  requestSms: (phoneId: number) => Promise<void>;
  /** Submit the code received via SMS for the given phone id. */
  submitSmsCode: (phoneId: number, code: string) => Promise<void>;
}

export interface AppleDeveloperLoginRequest {
  anisetteData: AnisetteData;
  credentials: AppleSigningCredentials;
  onLog?: (message: string) => void;
  onTwoFactorRequired?: (ctx: TwoFactorContext) => void;
}

export interface AppleSigningWithContextRequest {
  ipaFile: File;
  context: AppleDeveloperContext;
  deviceUdid: string;
  deviceName?: string;
  bundleIdOverride?: string;
  displayNameOverride?: string;
  onLog: (message: string) => void;
}

export interface SignIpaResult {
  signedFile: File;
  outputBundleId: string;
  teamId: string;
}

const CERT_KEY_STORAGE_KEY = 'webmuxd:cert-keys';
/** Apple "maximum number of certificates" result code. */
const CERT_LIMIT_RESULT_CODE = '7460';

let apiInstance: AppleAPI | null = null;

function getApi(log?: (message: string) => void): AppleAPI {
  if (!apiInstance) {
    apiInstance = new AppleAPI(createAppleFetch(log));
  }
  return apiInstance;
}

function toAltAnisette(data: AnisetteData): AltAnisetteData {
  return {
    machineID: data.machineID,
    oneTimePassword: data.oneTimePassword,
    localUserID: data.localUserID,
    routingInfo: data.routingInfo,
    deviceUniqueIdentifier: data.deviceUniqueIdentifier,
    deviceDescription: data.deviceDescription,
    deviceSerialNumber: data.deviceSerialNumber,
    date: data.date,
    locale: data.locale,
    timeZone: data.timeZone,
  };
}

function toAltTeam(context: AppleDeveloperContext): AltTeam {
  return {
    identifier: context.team.identifier,
    name: context.team.name,
    type: 'Free',
    account: {
      identifier: context.session.dsid,
      name: context.appleId,
      email: context.appleId,
    },
  };
}

function toSession(context: AppleDeveloperContext): AppleAPISession {
  return {
    dsid: context.session.dsid,
    authToken: context.session.authToken,
    anisetteData: toAltAnisette(context.session.anisetteData),
  };
}

function derToPem(der: Uint8Array): string {
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

function toCertificate(cert: AltCertificate): Certificate {
  return {
    id: String(cert.identifier),
    name: cert.machineName || 'iOS Development',
    serialNumber: String(cert.identifier),
    pem: derToPem(cert.publicKey),
  };
}

interface CertKeyCache {
  certId: string;
  certDerB64: string;
  privateKeyB64: string;
}

function certCacheKey(appleId: string, teamId: string): string {
  return `${appleId.trim().toLowerCase()}::${teamId.trim().toUpperCase()}`;
}

function readCertCache(): Record<string, CertKeyCache> {
  const raw = loadText(CERT_KEY_STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, CertKeyCache>) : {};
  } catch {
    return {};
  }
}

function writeCertCacheEntry(appleId: string, teamId: string, entry: CertKeyCache): void {
  const map = readCertCache();
  map[certCacheKey(appleId, teamId)] = entry;
  saveText(CERT_KEY_STORAGE_KEY, JSON.stringify(map));
}

/** Apple ID SRP login + team/cert/device bootstrap. */
export async function loginAppleDeveloperAccount(
  req: AppleDeveloperLoginRequest,
): Promise<AppleDeveloperContext> {
  const log = req.onLog ?? (() => {});
  const api = getApi(log);
  await ensureLibcurl(log);

  const { appleId, password } = req.credentials;
  const anisetteData = toAltAnisette(req.anisetteData);

  let resolveCode: ((code: string) => void) | null = null;
  const codePromise = new Promise<string>((resolve) => {
    resolveCode = resolve;
  });

  const verificationHandler = (submitCode: (code: string) => void): void => {
    if (!req.onTwoFactorRequired) {
      throw new Error('two-factor authentication required but no UI handler is wired up');
    }
    const ctx: TwoFactorContext = {
      submitDeviceCode: (code: string) => {
        resolveCode?.(code);
      },
      trustedPhoneNumbers: [],
      requestSms: async () => {
        throw new Error(
          'SMS two-factor is not supported by this build (altsign.js only handles trusted-device codes).',
        );
      },
      submitSmsCode: async () => {
        throw new Error(
          'SMS two-factor is not supported by this build (altsign.js only handles trusted-device codes).',
        );
      },
    };
    req.onTwoFactorRequired(ctx);
    void codePromise.then(async (code) => {
      // Refresh anisette data before submitting the 2FA code.
      // isideload re-fetches anisette for every 2FA request because Apple's
      // OTP expires quickly; altsign.js reuses the login-time data, so the
      // /validate request would carry a stale OTP and return 401.
      // Update the object in place: altsign.js holds the same reference.
      try {
        log('auth: refreshing anisette data for 2FA...');
        const fresh = await getAnisetteData(log);
        anisetteData.machineID = fresh.machineID;
        anisetteData.oneTimePassword = fresh.oneTimePassword;
        anisetteData.localUserID = fresh.localUserID;
        anisetteData.routingInfo = fresh.routingInfo;
        anisetteData.deviceUniqueIdentifier = fresh.deviceUniqueIdentifier;
        anisetteData.deviceDescription = fresh.deviceDescription;
        anisetteData.deviceSerialNumber = fresh.deviceSerialNumber;
        anisetteData.date = fresh.date;
        anisetteData.locale = fresh.locale;
        anisetteData.timeZone = fresh.timeZone;
      } catch (e) {
        log(`auth: anisette refresh failed, using stale data: ${e}`);
      }
      submitCode(code);
    });
  };

  log('auth: starting SRP authentication...');
  const { account, session } = await (api as any).authenticate(
    appleId,
    password,
    anisetteData,
    verificationHandler,
    {
      // Vendored altsign.js calls this before /trusteddevice and /validate
      // (isideload re-fetches anisette for every 2FA request).
      refreshAnisette: async () => {
        log('auth: refreshing anisette data for 2FA...');
        const fresh = await getAnisetteData(log);
        // Update the shared object in place too, for any code holding the ref.
        Object.assign(anisetteData, fresh);
        return fresh;
      },
    },
  );
  log(`auth: authenticated (${account.email || account.name})`);

  const team = await api.fetchTeam(session); // Individual -> Free -> first
  log(`auth: using team ${team.name} (${team.identifier})`);

  const [certificates, devices] = await Promise.all([
    api.fetchCertificates(session, team).catch((e: unknown) => {
      log(`auth: could not list certificates (${e instanceof Error ? e.message : String(e)})`);
      return [] as AltCertificate[];
    }),
    api.fetchDevices(session, team).catch((e: unknown) => {
      log(`auth: could not list devices (${e instanceof Error ? e.message : String(e)})`);
      return [] as AltDevice[];
    }),
  ]);

  return {
    appleId,
    session: {
      anisetteData: req.anisetteData,
      dsid: session.dsid,
      authToken: session.authToken,
    },
    team: { identifier: team.identifier, name: team.name },
    certificates: certificates.map(toCertificate),
    devices: devices.map((d) => ({ udid: d.identifier, name: d.name })),
  };
}

/** Refresh teams, certificates and devices for an existing context. */
export async function refreshAppleDeveloperContext(
  context: AppleDeveloperContext,
  log?: (message: string) => void,
): Promise<AppleDeveloperContext> {
  const api = getApi(log);
  // isideload refreshes anisette before every developer API request because
  // X-Apple-I-MD (oneTimePassword) is single-use. Using the login-time
  // anisette here makes Apple return 1100 "session expired".
  const freshAnisette = await getAnisetteData(log);
  const session = toSession({
    ...context,
    session: { ...context.session, anisetteData: freshAnisette },
  });
  const teams = await api.fetchTeams(session);
  const team =
    teams.find((t) => t.identifier === context.team.identifier) ??
    (await api.fetchTeam(session));
  const [certificates, devices] = await Promise.all([
    api.fetchCertificates(session, team).catch(() => [] as AltCertificate[]),
    api.fetchDevices(session, team).catch(() => [] as AltDevice[]),
  ]);
  return {
    ...context,
    session: { ...context.session, anisetteData: freshAnisette },
    team: { identifier: team.identifier, name: team.name },
    certificates: certificates.map(toCertificate),
    devices: devices.map((d) => ({ udid: d.identifier, name: d.name })),
  };
}

interface IpaInfo {
  bundleId: string;
  bundleName: string;
  bundleVersion: string;
}

function stripAppExtensions(ipaBytes: Uint8Array, log: (m: string) => void): Uint8Array {
  const entries = unzipSync(ipaBytes);
  const names = Object.keys(entries);
  // Match Payload/<App>.app/PlugIns/<Name>.appex/... (case-insensitive).
  const appexPrefix = names.find((n) => /\/PlugIns\/[^/]+\.appex\//i.test(n))
    ?.match(/^(.+\/PlugIns\/[^/]+\.appex\/)/i)?.[1];
  if (!appexPrefix) {
    return ipaBytes; // No app extensions; nothing to strip.
  }
  const pluginsDir = appexPrefix.replace(/[^/]+\.appex\/$/i, '');
  let removed = 0;
  for (const name of names) {
    if (name.toLowerCase().startsWith(pluginsDir.toLowerCase())) {
      delete entries[name];
      removed++;
    }
  }
  if (removed > 0) {
    log(`sign: stripped ${removed} app extension files (PlugIns/)`);
  }
  return zipSync(entries);
}

function parseIpaInfo(ipaBytes: Uint8Array, log: (m: string) => void): IpaInfo {
  const entries = unzipSync(ipaBytes);
  const names = Object.keys(entries);
  const infoPlistName = names.find(
    (n) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(n),
  );
  if (!infoPlistName) {
    throw new Error('IPA has no Payload/*.app/Info.plist');
  }
  const raw = entries[infoPlistName];
  const info = parsePlist(raw) as { [key: string]: PlistValue };
  const bundleId = plistString(info, 'CFBundleIdentifier');
  if (!bundleId) {
    throw new Error('Info.plist has no CFBundleIdentifier');
  }
  const bundleName =
    plistString(info, 'CFBundleDisplayName') ??
    plistString(info, 'CFBundleName') ??
    bundleId;
  const bundleVersion = plistString(info, 'CFBundleShortVersionString') ?? '1.0';
  log(`ipa: ${bundleName} (${bundleId}) v${bundleVersion}`);
  return { bundleId, bundleName, bundleVersion };
}

/**
 * Ensures a signing identity exists: reuse the cached certificate when it is
 * still valid, otherwise create a new one. On Apple's 7460 certificate
 * limit, revoke the oldest certificate first and retry once.
 */
async function ensureSigningIdentity(
  api: AppleAPI,
  session: AppleAPISession,
  team: AltTeam,
  appleId: string,
  log: (m: string) => void,
): Promise<{ certDer: Uint8Array; privateKey: Uint8Array }> {
  const cache = readCertCache()[certCacheKey(appleId, team.identifier)];
  const certificates = await api.fetchCertificates(session, team);
  if (cache) {
    const stillThere = certificates.find((c) => String(c.identifier) === cache.certId);
    if (stillThere) {
      log(`sign: reusing certificate ${cache.certId}`);
      return {
        certDer: base64ToBytes(cache.certDerB64),
        privateKey: base64ToBytes(cache.privateKeyB64),
      };
    }
    log('sign: cached certificate no longer exists, creating a new one');
  }

  const machineName = 'SideImpactor Web';
  const create = async (): Promise<{ certDer: Uint8Array; privateKey: Uint8Array }> => {
    const { certificate, privateKey } = await api.addCertificate(session, team, machineName);
    log(`sign: created certificate ${certificate.identifier}`);
    writeCertCacheEntry(appleId, team.identifier, {
      certId: String(certificate.identifier),
      certDerB64: bytesToBase64(certificate.publicKey),
      privateKeyB64: bytesToBase64(privateKey),
    });
    return { certDer: certificate.publicKey, privateKey };
  };

  try {
    return await create();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes(CERT_LIMIT_RESULT_CODE) || certificates.length === 0) {
      throw error;
    }
    const oldest = certificates[0];
    log(`sign: certificate limit reached, revoking oldest (${oldest.identifier})...`);
    await api.revokeCertificate(session, team, oldest);
    return create();
  }
}

async function ensureDeviceRegistered(
  api: AppleAPI,
  session: AppleAPISession,
  team: AltTeam,
  deviceUdid: string,
  deviceName: string | undefined,
  log: (m: string) => void,
): Promise<void> {
  const devices = await api.fetchDevices(session, team);
  if (devices.some((d) => (d as any).udid === deviceUdid || d.identifier === deviceUdid)) {
    log('sign: device already registered');
    return;
  }
  log(`sign: registering device ${deviceUdid}...`);
  await api.registerDevice(session, team, deviceName ?? 'iPhone', deviceUdid);
  log('sign: device registered');
}

/** Sign an IPA with the developer context (zsign-WASM re-sign). */
export async function signIpaWithAppleContext(
  req: AppleSigningWithContextRequest,
): Promise<SignIpaResult> {
  const log = req.onLog;
  const api = getApi(log);
  // Refresh anisette: X-Apple-I-MD is single-use, and signing makes many
  // developer API calls (certificates, devices, App IDs, profiles).
  const freshAnisette = await getAnisetteData(log);
  const refreshedContext = {
    ...req.context,
    session: { ...req.context.session, anisetteData: freshAnisette },
  };
  const session = toSession(refreshedContext);
  const team = toAltTeam(refreshedContext);

  const ipaBytes = new Uint8Array(await req.ipaFile.arrayBuffer());
  // Strip App Extensions (PlugIns/*.appex): we don't provision separate App
  // IDs/profiles for them yet, and an unsigned appex blocks the host app from
  // launching ("missing a valid provisioning profile"). Removing PlugIns lets
  // the main app install and launch; extensions simply won't be present.
  const strippedIpaBytes = stripAppExtensions(ipaBytes, log);
  const info = parseIpaInfo(strippedIpaBytes, log);

  const outputBundleId = req.bundleIdOverride ?? `${info.bundleId}.${team.identifier}`;
  log(`sign: provisioning for ${outputBundleId}`);

  const identity = await ensureSigningIdentity(api, session, team, req.context.appleId, log);
  await ensureDeviceRegistered(api, session, team, req.deviceUdid, req.deviceName, log);

  const appIds = await api.fetchAppIDs(session, team);
  let appId = appIds.find((a) => a.bundleIdentifier === outputBundleId);
  if (!appId) {
    log('sign: creating App ID...');
    appId = await api.addAppID(session, team, info.bundleName, outputBundleId);
  } else {
    log('sign: App ID already exists');
  }

  log('sign: downloading provisioning profile...');
  const profile = await api.fetchProvisioningProfile(session, team, appId);

  log('sign: re-signing IPA (this can take a while)...');
  const result = await signIPA({
    ipaData: strippedIpaBytes,
    certificate: identity.certDer,
    privateKey: identity.privateKey,
    provisioningProfile: profile.data,
    bundleID: outputBundleId,
    displayName: req.displayNameOverride ?? info.bundleName,
    bundleVersion: info.bundleVersion,
  });

  const baseName = req.ipaFile.name.replace(/\.ipa$/i, '');
  const signedFile = new File([new Uint8Array(result.data)], sanitizeFilename(`${baseName}-signed.ipa`), {
    type: 'application/octet-stream',
  });
  log(`sign: done -> ${signedFile.name} (${(signedFile.size / 1048576).toFixed(2)} MB)`);
  return { signedFile, outputBundleId, teamId: team.identifier };
}
