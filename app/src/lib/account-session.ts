/**
 * Apple account session persistence.
 *
 * Sessions (dsid + auth token + anisette data) are restored from
 * localStorage on startup; team/certificate/device details are re-fetched
 * via `refreshAppleDeveloperContext` in apple-signing.ts before signing.
 */
import type { AnisetteData } from '../anisette-service';
import type { AppleDeveloperContext } from '../apple-signing';
import {
  APPLE_ACCOUNT_LIST_STORAGE_KEY,
  APPLE_ACCOUNT_SESSION_MAP_STORAGE_KEY,
  APPLE_ACCOUNT_SUMMARY_STORAGE_KEY,
  loadText,
  writeJson,
} from './storage';
import { accountKey } from './ids';

export interface StoredAccountSummary {
  appleId: string;
  teamId: string;
  teamName: string;
  updatedAtIso: string;
}

export interface StoredAnisetteDataPayload {
  machineID: string;
  oneTimePassword: string;
  localUserID: string;
  routingInfo: number;
  deviceUniqueIdentifier: string;
  deviceDescription: string;
  deviceSerialNumber: string;
  dateIso: string;
  locale: string;
  timeZone: string;
}

export interface StoredAccountSessionPayload {
  appleId: string;
  teamId: string;
  teamName: string;
  dsid: string;
  authToken: string;
  anisetteData: StoredAnisetteDataPayload;
  updatedAtIso: string;
}

export function encodeAnisetteData(data: AnisetteData): StoredAnisetteDataPayload {
  return {
    machineID: data.machineID,
    oneTimePassword: data.oneTimePassword,
    localUserID: data.localUserID,
    routingInfo: data.routingInfo,
    deviceUniqueIdentifier: data.deviceUniqueIdentifier,
    deviceDescription: data.deviceDescription,
    deviceSerialNumber: data.deviceSerialNumber,
    dateIso: data.date.toISOString(),
    locale: data.locale,
    timeZone: data.timeZone,
  };
}

export function decodeAnisetteData(payload: StoredAnisetteDataPayload): AnisetteData | null {
  if (
    !payload.machineID ||
    !payload.oneTimePassword ||
    !payload.localUserID ||
    !payload.deviceUniqueIdentifier ||
    !payload.deviceDescription ||
    !payload.locale ||
    !payload.timeZone
  ) {
    return null;
  }
  if (!Number.isFinite(payload.routingInfo)) return null;
  const date = new Date(payload.dateIso);
  if (Number.isNaN(date.getTime())) return null;
  return {
    machineID: payload.machineID,
    oneTimePassword: payload.oneTimePassword,
    localUserID: payload.localUserID,
    routingInfo: payload.routingInfo,
    deviceUniqueIdentifier: payload.deviceUniqueIdentifier,
    deviceDescription: payload.deviceDescription,
    deviceSerialNumber: payload.deviceSerialNumber || '0',
    date,
    locale: payload.locale,
    timeZone: payload.timeZone,
  };
}

function isSessionPayload(value: unknown): value is StoredAccountSessionPayload {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v['appleId'] === 'string' &&
    typeof v['teamId'] === 'string' &&
    typeof v['dsid'] === 'string' &&
    typeof v['authToken'] === 'string' &&
    typeof v['anisetteData'] === 'object'
  );
}

function readSessionMap(): Record<string, StoredAccountSessionPayload> {
  const raw = loadText(APPLE_ACCOUNT_SESSION_MAP_STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out: Record<string, StoredAccountSessionPayload> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (isSessionPayload(v)) out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

export function loadStoredAccountList(): StoredAccountSummary[] {
  const raw = loadText(APPLE_ACCOUNT_LIST_STORAGE_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is StoredAccountSummary =>
        !!item &&
        typeof item === 'object' &&
        typeof (item as StoredAccountSummary).appleId === 'string' &&
        typeof (item as StoredAccountSummary).teamId === 'string',
    );
  } catch {
    return [];
  }
}

export function loadStoredAccountSummary(): StoredAccountSummary | null {
  const raw = loadText(APPLE_ACCOUNT_SUMMARY_STORAGE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as StoredAccountSummary;
    if (parsed && typeof parsed.appleId === 'string' && typeof parsed.teamId === 'string') {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

export function setStoredAccountSummary(summary: StoredAccountSummary): void {
  writeJson(APPLE_ACCOUNT_SUMMARY_STORAGE_KEY, summary);
}

export const MAX_SAVED_ACCOUNTS = 12;

export function persistAccountSummary(context: AppleDeveloperContext): void {
  const summary: StoredAccountSummary = {
    appleId: context.appleId,
    teamId: context.team.identifier,
    teamName: context.team.name,
    updatedAtIso: new Date().toISOString(),
  };
  setStoredAccountSummary(summary);
  const list = loadStoredAccountList().filter(
    (item) => accountKey(item.appleId, item.teamId) !== accountKey(summary.appleId, summary.teamId),
  );
  list.unshift(summary);
  writeJson(APPLE_ACCOUNT_LIST_STORAGE_KEY, list.slice(0, MAX_SAVED_ACCOUNTS));
}

export function persistAccountSession(context: AppleDeveloperContext, anisetteData: AnisetteData): void {
  const map = readSessionMap();
  const payload: StoredAccountSessionPayload = {
    appleId: context.appleId,
    teamId: context.team.identifier,
    teamName: context.team.name,
    dsid: context.session.dsid,
    authToken: context.session.authToken,
    anisetteData: encodeAnisetteData(anisetteData),
    updatedAtIso: new Date().toISOString(),
  };
  map[accountKey(context.appleId, context.team.identifier)] = payload;
  writeJson(APPLE_ACCOUNT_SESSION_MAP_STORAGE_KEY, map);
}

export function removeStoredAccountSession(appleId: string, teamId: string): void {
  const map = readSessionMap();
  delete map[accountKey(appleId, teamId)];
  writeJson(APPLE_ACCOUNT_SESSION_MAP_STORAGE_KEY, map);
}

/**
 * Rebuilds in-memory developer contexts from persisted sessions.
 * Team/certificate/device details are re-fetched by the sign flow via
 * `refreshAppleDeveloperContext`; here we restore the identity + tokens.
 */
export function restorePersistedAccountContexts(): Map<string, AppleDeveloperContext> {
  const map = new Map<string, AppleDeveloperContext>();
  const sessions = readSessionMap();
  for (const [key, payload] of Object.entries(sessions)) {
    const anisetteData = decodeAnisetteData(payload.anisetteData);
    if (!anisetteData) continue;
    map.set(key, {
      appleId: payload.appleId,
      session: {
        anisetteData,
        dsid: payload.dsid,
        authToken: payload.authToken,
      },
      team: { identifier: payload.teamId, name: payload.teamName },
      certificates: [],
      devices: [],
    });
  }
  return map;
}
