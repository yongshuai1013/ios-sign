/**
 * IPA cache backed by IndexedDB.
 *
 * When the user signs an IPA through the website, we keep a copy keyed by
 * bundle ID so the Refresh page can re-sign it later without asking the user
 * to pick the file again. Metadata (bundle ID, display name, signed-at time)
 * lives in the same store.
 *
 * This is a best-effort cache: if IndexedDB is unavailable (private mode,
 * storage pressure) the sign flow still works, refresh just won't find it.
 */

export interface CachedIpaMeta {
  /** CFBundleIdentifier of the main app bundle. */
  bundleId: string;
  /** Display name from Info.plist, if known. */
  displayName?: string;
  /** Original file name the user picked. */
  fileName: string;
  /** Epoch ms when this IPA was cached (i.e. signed). */
  cachedAt: number;
  /** Byte size of the stored IPA. */
  size: number;
}

export interface CachedIpa {
  meta: CachedIpaMeta;
  data: Blob;
}

const DB_NAME = 'sideimpactor';
const DB_VERSION = 1;
const STORE_NAME = 'ipa-cache';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB unavailable'));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'meta.bundleId' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
  });
}

/** Stores (or replaces) the cached IPA for a bundle ID. Never throws. */
export async function cacheIpa(meta: CachedIpaMeta, data: Blob): Promise<void> {
  try {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put({ meta, data });
      await txDone(tx);
    } finally {
      db.close();
    }
  } catch {
    // Best effort — signing must not fail because the cache is unavailable.
  }
}

/** Returns the cached IPA for a bundle ID, or null. Never throws. */
export async function getCachedIpa(bundleId: string): Promise<CachedIpa | null> {
  try {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(bundleId);
      const result = await new Promise<unknown>((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
      });
      await txDone(tx);
      if (result !== null && typeof result === 'object') {
        const r = result as { meta?: CachedIpaMeta; data?: Blob };
        if (r.meta && r.data instanceof Blob) {
          return { meta: r.meta, data: r.data };
        }
      }
      return null;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

/** Lists metadata of all cached IPAs, newest first. Never throws. */
export async function listCachedIpas(): Promise<CachedIpaMeta[]> {
  try {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).getAll();
      const result = await new Promise<unknown>((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('IndexedDB getAll failed'));
      });
      await txDone(tx);
      const metas: CachedIpaMeta[] = [];
      if (Array.isArray(result)) {
        for (const entry of result) {
          const e = entry as { meta?: CachedIpaMeta };
          if (e.meta && typeof e.meta.bundleId === 'string') {
            metas.push(e.meta);
          }
        }
      }
      metas.sort((a, b) => b.cachedAt - a.cachedAt);
      return metas;
    } finally {
      db.close();
    }
  } catch {
    return [];
  }
}

/** Removes the cached IPA for a bundle ID. Never throws. */
export async function removeCachedIpa(bundleId: string): Promise<void> {
  try {
    const db = await openDb();
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(bundleId);
      await txDone(tx);
    } finally {
      db.close();
    }
  } catch {
    // ignore
  }
}
