export const HOST_ID_STORAGE_KEY = 'webmuxd:host-id';
export const SYSTEM_BUID_STORAGE_KEY = 'webmuxd:system-buid';
export const PAIR_RECORDS_STORAGE_KEY = 'webmuxd:pair-records-by-udid';
export const LEGACY_PAIR_RECORD_STORAGE_KEY = 'webmuxd:pair-record';
export const REMOTE_PAIRING_FILE_STORAGE_KEY = 'webmuxd:remote-pairing-file';
export const APPLE_ID_STORAGE_KEY = 'webmuxd:apple-id';
export const APPLE_ACCOUNT_SUMMARY_STORAGE_KEY = 'webmuxd:apple-account-summary';
export const APPLE_ACCOUNT_LIST_STORAGE_KEY = 'webmuxd:apple-account-list';
export const APPLE_ACCOUNT_SESSION_MAP_STORAGE_KEY = 'webmuxd:apple-account-session-map';
export const APPLE_REMEMBER_SESSION_STORAGE_KEY = 'webmuxd:apple-remember-session';
export const SELECTED_DEVICE_UDID_STORAGE_KEY = 'webmuxd:selected-device-udid';

export function loadText(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function saveText(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // storage unavailable (private mode etc.) — pairing still works in-memory
  }
}

export function removeText(key: string): void {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // ignore
  }
}

export function readJson<T>(key: string, guard: (value: unknown) => value is T): T | null {
  const raw = loadText(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return guard(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function writeJson(key: string, value: unknown): void {
  saveText(key, JSON.stringify(value));
}
