/**
 * USB (Lockdown) + Remote pairing records, backed by this repo's own
 * `@pairing` modules (a TypeScript port of idevice_pair / idevice).
 *
 * USB records are stored in localStorage as base64-encoded XML plists keyed
 * by device UDID. The remote pairing file (Ed25519 keys + identifier) is
 * stored under its own key.
 */
import { PairingFile, RpPairingFile } from '@pairing/pairing-file';
import {
  HOST_ID_STORAGE_KEY,
  LEGACY_PAIR_RECORD_STORAGE_KEY,
  PAIR_RECORDS_STORAGE_KEY,
  REMOTE_PAIRING_FILE_STORAGE_KEY,
  SYSTEM_BUID_STORAGE_KEY,
  loadText,
  removeText,
  saveText,
  writeJson,
} from './storage';
import { base64ToBytes, bytesToBase64 } from './ids';

export function getOrCreateHostId(): string {
  const existing = loadText(HOST_ID_STORAGE_KEY);
  if (existing && existing.trim().length > 0) return existing.trim();
  const created =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().toUpperCase()
      : `HOST-${Math.random().toString(16).slice(2).toUpperCase()}`;
  saveText(HOST_ID_STORAGE_KEY, created);
  return created;
}

export function getOrCreateSystemBuid(): string {
  const existing = loadText(SYSTEM_BUID_STORAGE_KEY);
  if (existing && existing.trim().length > 0) return existing.trim();
  const created =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().toUpperCase()
      : `BUID-${Math.random().toString(16).slice(2).toUpperCase()}`;
  saveText(SYSTEM_BUID_STORAGE_KEY, created);
  return created;
}

function readPairRecordMap(): Record<string, string> {
  const raw = loadText(PAIR_RECORDS_STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === 'string') out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

function writePairRecordMap(map: Record<string, string>): void {
  writeJson(PAIR_RECORDS_STORAGE_KEY, map);
}

/** Persist a USB pairing file (XML plist) for a device UDID. */
export function savePairRecordForUdid(udid: string, record: PairingFile): void {
  const normalized = udid.trim();
  if (normalized.length === 0) return;
  const map = readPairRecordMap();
  map[normalized] = bytesToBase64(record.serialize());
  writePairRecordMap(map);
}

/** Load the stored USB pairing file for a UDID, if any. */
export function loadPairRecordForUdid(udid: string): PairingFile | null {
  const normalized = udid.trim();
  if (normalized.length === 0) return null;
  const map = readPairRecordMap();
  const stored = map[normalized];
  if (stored) {
    try {
      return PairingFile.fromBytes(base64ToBytes(stored));
    } catch {
      return null;
    }
  }
  // Legacy single-record slot from older builds.
  const legacy = loadText(LEGACY_PAIR_RECORD_STORAGE_KEY);
  if (legacy) {
    try {
      const record = PairingFile.fromBytes(base64ToBytes(legacy));
      savePairRecordForUdid(normalized, record);
      removeText(LEGACY_PAIR_RECORD_STORAGE_KEY);
      return record;
    } catch {
      return null;
    }
  }
  return null;
}

export function deletePairRecordForUdid(udid: string): void {
  const normalized = udid.trim();
  if (normalized.length === 0) return;
  const map = readPairRecordMap();
  delete map[normalized];
  writePairRecordMap(map);
}

/** UDIDs that have a locally stored USB pairing record. */
export function listKnownDeviceUdids(fallbackUdid: string | null = null): string[] {
  const udids = Object.keys(readPairRecordMap());
  if (fallbackUdid && !udids.includes(fallbackUdid)) {
    udids.push(fallbackUdid);
  }
  return udids;
}

/** Persist the remote (Wi-Fi) pairing file. */
export function saveRemotePairingFile(record: RpPairingFile): void {
  saveText(REMOTE_PAIRING_FILE_STORAGE_KEY, bytesToBase64(record.toBytes()));
}

/** Load the stored remote pairing file, if any. */
export function loadRemotePairingFile(): RpPairingFile | null {
  const stored = loadText(REMOTE_PAIRING_FILE_STORAGE_KEY);
  if (!stored) return null;
  try {
    return RpPairingFile.fromBytes(base64ToBytes(stored));
  } catch {
    return null;
  }
}

export function deleteRemotePairingFile(): void {
  removeText(REMOTE_PAIRING_FILE_STORAGE_KEY);
}
