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
import { build as buildPlist } from 'plist';
import * as forge from 'node-forge';
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

/**
 * Revokes the cached development certificate for the given Apple ID/team,
 * both on the portal and in the local cache. The next sign will create a
 * fresh certificate with a new machineId (used as the P12 password).
 */
export async function revokeCachedCertificate(
  context: AppleDeveloperContext,
  log?: (message: string) => void,
): Promise<void> {
  const api = getApi(log);
  const freshAnisette = await getAnisetteData(log);
  const session = toSession({
    ...context,
    session: { ...context.session, anisetteData: freshAnisette },
  });
  const team = toAltTeam(context);
  const certificates = await api.fetchCertificates(session, team);
  const cacheKey = certCacheKey(context.appleId, context.team.identifier);
  const cache = readCertCache()[cacheKey];
  const target = cache
    ? certificates.find((c) => String(c.identifier) === cache.certId)
    : certificates.find((c) => c.machineName === 'SideImpactor Web');
  if (!target) {
    log?.('revoke: no certificate found to revoke');
    return;
  }
  log?.(`revoke: revoking certificate ${target.identifier}...`);
  await api.revokeCertificate(session, team, target);
  const map = readCertCache();
  delete map[cacheKey];
  saveText(CERT_KEY_STORAGE_KEY, JSON.stringify(map));
  log?.('revoke: done, next sign will create a fresh certificate');
}

interface IpaInfo {
  bundleId: string;
  bundleName: string;
  bundleVersion: string;
}

/**
 * Provisions App Extensions (.appex) by registering dedicated App IDs,
 * downloading provisioning profiles, and embedding them into each .appex.
 * Returns the repacked IPA bytes. If no .appex is found, returns the input unchanged.
 */
async function embedExtensionProfiles(
  ipaBytes: Uint8Array,
  api: AppleAPI,
  session: AppleAPISession,
  team: AltTeam,
  originalBundleId: string,
  outputBundleId: string,
  log: (m: string) => void,
): Promise<Uint8Array> {
  const entries = unzipSync(ipaBytes);
  const names = Object.keys(entries);
  // Find all .appex bundles: Payload/<App>.app/PlugIns/<Name>.appex/
  const appexBundles = new Set<string>();
  for (const n of names) {
    const m = n.match(/^(.+\/PlugIns\/[^/]+\.appex)\//i);
    if (m) appexBundles.add(m[1]);
  }
  if (appexBundles.size === 0) {
    return ipaBytes;
  }

  log(`sign: provisioning ${appexBundles.size} app extension(s)...`);
  const appIds = await api.fetchAppIDs(session, team);

  for (const appexPath of appexBundles) {
    const infoPlistPath = `${appexPath}/Info.plist`;
    const infoRaw = entries[infoPlistPath];
    if (!infoRaw) {
      log(`sign: warning: ${appexPath} has no Info.plist, skipping`);
      continue;
    }
    const info = parsePlist(infoRaw) as { [k: string]: PlistValue };
    const origExtId = plistString(info, 'CFBundleIdentifier');
    if (!origExtId) {
      log(`sign: warning: ${appexPath} has no CFBundleIdentifier, skipping`);
      continue;
    }
    // Map extension bundle ID: replace the original host prefix with the new output ID.
    // e.g. com.SideStore.SideStore.AltWidget -> com.SideStore.SideStore.<TEAM>.AltWidget
    let newExtId: string;
    if (origExtId.startsWith(originalBundleId + '.')) {
      newExtId = outputBundleId + origExtId.slice(originalBundleId.length);
    } else {
      const lastPart = origExtId.split('.').pop() ?? 'Extension';
      newExtId = `${outputBundleId}.${lastPart}`;
    }
    log(`sign: extension ${origExtId} -> ${newExtId}`);

    let extAppId = appIds.find((a) => a.bundleIdentifier === newExtId);
    if (!extAppId) {
      log(`sign: creating App ID for extension...`);
      const displayName = plistString(info, 'CFBundleDisplayName') || plistString(info, 'CFBundleName') || 'Extension';
      extAppId = await api.addAppID(session, team, displayName, newExtId);
      appIds.push(extAppId);
    }
    const extProfile = await api.fetchProvisioningProfile(session, team, extAppId);
    // Embed the profile into the .appex.
    entries[`${appexPath}/embedded.mobileprovision`] = new Uint8Array(extProfile.data);
    // Update the extension's Info.plist with the new bundle ID.
    info['CFBundleIdentifier'] = newExtId;
    entries[infoPlistPath] = new TextEncoder().encode(buildPlist(info as unknown as Parameters<typeof buildPlist>[0]));
    log(`sign: extension profile embedded for ${newExtId}`);
  }

  return zipSync(entries);
}

/**
 * Injects the signing certificate into special apps (SideStore, AltStore,
 * StikStore, SideStoreLc) so they can refresh themselves on-device.
 * Matches isideload's `apply_special_app_behavior`:
 * - SideStore/AltStore/SideStoreLc: ALTAppGroups -> Info.plist, ALTCertificateID + ALTCertificate.p12
 * - StikStore: MachineID + Certificate.p12 (no ALTAppGroups)
 * - SideStoreLc: inject into the framework bundle (com.SideStore.SideStore), not main bundle
 *
 * @param machineID the dev-portal certificate's machineId (from the CSR),
 * not the anisette machineID.
 * @param groupIdentifier the App Group identifier (e.g. group.com.SideStore.SideStore.<TEAM>)
 */
async function injectSpecialAppCertificate(
  signedIpaBytes: Uint8Array,
  certDer: Uint8Array,
  privateKey: Uint8Array,
  machineID: string,
  specialApp: 'SideStore' | 'AltStore' | 'StikStore' | 'SideStoreLc',
  groupIdentifier: string,
  log: (m: string) => void,
): Promise<Uint8Array> {
  const entries = unzipSync(signedIpaBytes);
  const names = Object.keys(entries);
  // Find the main app bundle: Payload/<App>.app/
  const appMatch = names.find((n) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(n))?.match(/^(Payload\/[^/]+\.app)\//);
  if (!appMatch) {
    log('sign: warning: could not find app bundle for certificate injection');
    return signedIpaBytes;
  }
  const appDir = appMatch[1];

  // Determine target bundle for certificate injection.
  // SideStoreLc: inject into the framework bundle, not the main bundle.
  let targetDir = appDir;
  if (specialApp === 'SideStoreLc') {
    const fwInfo = names.find((n) =>
      n.startsWith(`${appDir}/Frameworks/`) &&
      n.endsWith('.framework/Info.plist')
    );
    if (fwInfo) {
      // Verify it's the SideStore framework by checking bundle ID
      const fwInfoRaw = entries[fwInfo];
      if (fwInfoRaw) {
        try {
          const fwPlist = parsePlist(fwInfoRaw) as { [k: string]: PlistValue };
          if (fwPlist['CFBundleIdentifier'] === 'com.SideStore.SideStore') {
            targetDir = fwInfo.substring(0, fwInfo.length - '/Info.plist'.length);
            log(`sign: SideStoreLc detected, injecting into framework: ${targetDir}`);
          }
        } catch {
          // Fall through to main bundle
        }
      }
    }
  }

  // Parse certificate to get serial number. isideload formats it as
  // uppercase hex without leading zeros.
  const certAsn1 = forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(certDer)));
  const cert = forge.pki.certificateFromAsn1(certAsn1);
  const serialNumber = (cert.serialNumber.replace(/^0+/, '') || '0').toUpperCase();

  // Generate p12 encrypted with machineID.
  const privateKeyAsn1 = forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(privateKey)));
  const forgePrivateKey = forge.pki.privateKeyFromAsn1(privateKeyAsn1);
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    forgePrivateKey,
    [cert],
    machineID,
    { algorithm: '3des' },
  );
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  const p12Bytes = new Uint8Array(p12Der.length);
  for (let i = 0; i < p12Der.length; i++) {
    p12Bytes[i] = p12Der.charCodeAt(i);
  }

  // Key names differ for StikStore (matches isideload).
  const idKey = specialApp === 'StikStore' ? 'MachineID' : 'ALTCertificateID';
  const p12Name = specialApp === 'StikStore' ? 'Certificate.p12' : 'ALTCertificate.p12';

  // Write p12 to target bundle root.
  entries[`${targetDir}/${p12Name}`] = p12Bytes;

  // Write certificate ID to target bundle's Info.plist.
  const infoPlistPath = `${targetDir}/Info.plist`;
  const infoRaw = entries[infoPlistPath];
  if (infoRaw) {
    const info = parsePlist(infoRaw) as { [k: string]: PlistValue };
    info[idKey] = serialNumber;
    // ALTAppGroups for SideStore/AltStore/SideStoreLc (not StikStore).
    // Injected into the MAIN app's Info.plist, not the framework.
    if (specialApp !== 'StikStore') {
      const mainInfoRaw = entries[`${appDir}/Info.plist`];
      if (mainInfoRaw) {
        const mainInfo = parsePlist(mainInfoRaw) as { [k: string]: PlistValue };
        mainInfo['ALTAppGroups'] = [groupIdentifier];
        entries[`${appDir}/Info.plist`] = new TextEncoder().encode(buildPlist(mainInfo as unknown as Parameters<typeof buildPlist>[0]));
        log(`sign: injected ALTAppGroups: ${groupIdentifier}`);
      }
    }
    entries[infoPlistPath] = new TextEncoder().encode(buildPlist(info as unknown as Parameters<typeof buildPlist>[0]));
  }

  log(`sign: injected certificate for ${specialApp} (serial ${serialNumber})`);
  return zipSync(entries);
}

/**
 * Detects special apps that need certificate injection (matches isideload's get_special_app).
 * Returns the special app type or null if not a special app.
 */
function detectSpecialApp(
  bundleId: string,
  ipaEntries: { [k: string]: Uint8Array },
): 'SideStore' | 'AltStore' | 'StikStore' | 'SideStoreLc' | null {
  if (bundleId === 'com.rileytestut.AltStore') return 'AltStore';
  if (bundleId === 'com.SideStore.SideStore') return 'SideStore';
  if (bundleId === 'app.stik.store') return 'StikStore';
  // SideStoreLc: check if any framework has the SideStore bundle ID
  const names = Object.keys(ipaEntries);
  for (const n of names) {
    if (n.includes('/Frameworks/') && n.endsWith('.framework/Info.plist')) {
      try {
        const raw = ipaEntries[n];
        const plist = parsePlist(raw) as { [k: string]: unknown };
        if (plist['CFBundleIdentifier'] === 'com.SideStore.SideStore') {
          return 'SideStoreLc';
        }
      } catch {
        // Continue checking
      }
    }
  }
  return null;
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
): Promise<{ certDer: Uint8Array; privateKey: Uint8Array; machineId?: string }> {
  const cache = readCertCache()[certCacheKey(appleId, team.identifier)];
  const certificates = await api.fetchCertificates(session, team);
  if (cache) {
    const stillThere = certificates.find((c) => String(c.identifier) === cache.certId);
    if (stillThere) {
      log(`sign: reusing certificate ${cache.certId}`);
      return {
        certDer: base64ToBytes(cache.certDerB64),
        privateKey: base64ToBytes(cache.privateKeyB64),
        // The dev-portal certificate record carries the machineId that was
        // sent with the CSR; SideStore needs it as the ALTCertificate.p12
        // password (matches isideload's behavior).
        machineId: (stillThere as { machineId?: string }).machineId,
      };
    }
    log('sign: cached certificate no longer exists, creating a new one');
  }

  const machineName = 'SideImpactor Web';
  const create = async (): Promise<{ certDer: Uint8Array; privateKey: Uint8Array; machineId?: string }> => {
    const { certificate, privateKey } = await api.addCertificate(session, team, machineName);
    log(`sign: created certificate ${certificate.identifier}`);
    writeCertCacheEntry(appleId, team.identifier, {
      certId: String(certificate.identifier),
      certDerB64: bytesToBase64(certificate.publicKey),
      privateKeyB64: bytesToBase64(privateKey),
    });
    return {
      certDer: certificate.publicKey,
      privateKey,
      machineId: (certificate as { machineId?: string }).machineId,
    };
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
  const info = parseIpaInfo(ipaBytes, log);

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

  // Provision App Extensions: each .appex needs its own App ID and provisioning
  // profile, otherwise iOS refuses to launch the host app ("The app extension
  // is missing a valid provisioning profile").
  let ipaForSigning = await embedExtensionProfiles(
    ipaBytes, api, session, team, info.bundleId, outputBundleId, log,
  );

  // For special apps (SideStore/AltStore/StikStore/SideStoreLc): inject the
  // signing certificate so they can refresh themselves on-device
  // (matches isideload's apply_special_app_behavior). Must be done BEFORE
  // signing, otherwise modifying the signed IPA breaks the code signature.
  // The P12 password must be the dev-portal certificate's machineId (sent
  // with the CSR), NOT the anisette machineID — they are different values.
  const specialApp = detectSpecialApp(info.bundleId, unzipSync(ipaForSigning));
  if (specialApp) {
    const machineID = identity.machineId;
    if (machineID) {
      // Group identifier for ALTAppGroups (matches isideload):
      // SideStoreLc: group.com.SideStore.SideStore.<TEAM>
      // Others: group.<bundleId>.<TEAM>
      const groupIdentifier = specialApp === 'SideStoreLc'
        ? `group.com.SideStore.SideStore.${team.identifier}`
        : `group.${info.bundleId}.${team.identifier}`;
      log(`sign: injecting certificate for ${specialApp}...`);
      ipaForSigning = await injectSpecialAppCertificate(
        ipaForSigning, identity.certDer, identity.privateKey, machineID,
        specialApp, groupIdentifier, log,
      );
    } else {
      log(`sign: warning: no certificate machineId, skipping ${specialApp} certificate injection`);
    }
  }

  log('sign: re-signing IPA (this can take a while)...');
  const result = await signIPA({
    ipaData: ipaForSigning,
    certificate: identity.certDer,
    privateKey: identity.privateKey,
    provisioningProfile: profile.data,
    bundleID: outputBundleId,
    displayName: req.displayNameOverride ?? info.bundleName,
    bundleVersion: info.bundleVersion,
  });

  const signedBytes: Uint8Array = new Uint8Array(result.data);

  const baseName = req.ipaFile.name.replace(/\.ipa$/i, '');
  const signedFile = new File([signedBytes.buffer as ArrayBuffer], sanitizeFilename(`${baseName}-signed.ipa`), {
    type: 'application/octet-stream',
  });
  log(`sign: done -> ${signedFile.name} (${(signedFile.size / 1048576).toFixed(2)} MB)`);
  return { signedFile, outputBundleId, teamId: team.identifier };
}
