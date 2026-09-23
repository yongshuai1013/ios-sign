/** Hash routing for the SPA. */

export type AppPage = 'login' | 'sign' | 'pairing' | 'direct-install' | 'refresh';

export const LOGIN_PAGE_HASH = '#/login';
export const SIGN_PAGE_HASH = '#/sign';
export const PAIRING_PAGE_HASH = '#/pairing';
export const DIRECT_INSTALL_PAGE_HASH = '#/direct-install';
export const REFRESH_PAGE_HASH = '#/refresh';

const KNOWN_HASHES = new Set([LOGIN_PAGE_HASH, SIGN_PAGE_HASH, PAIRING_PAGE_HASH, DIRECT_INSTALL_PAGE_HASH, REFRESH_PAGE_HASH]);

/** Maps a location hash to a page; unknown hashes fall back to login. */
export function resolvePageFromHash(hash: string): AppPage {
  if (hash === SIGN_PAGE_HASH) return 'sign';
  if (hash === PAIRING_PAGE_HASH) return 'pairing';
  if (hash === DIRECT_INSTALL_PAGE_HASH) return 'direct-install';
  if (hash === REFRESH_PAGE_HASH) return 'refresh';
  return 'login';
}

/** Maps a page back to its canonical hash. */
export function pageToHash(page: AppPage): string {
  if (page === 'sign') return SIGN_PAGE_HASH;
  if (page === 'pairing') return PAIRING_PAGE_HASH;
  if (page === 'direct-install') return DIRECT_INSTALL_PAGE_HASH;
  if (page === 'refresh') return REFRESH_PAGE_HASH;
  return LOGIN_PAGE_HASH;
}

/** True when the hash names a known page. */
export function isKnownPageHash(hash: string): boolean {
  return KNOWN_HASHES.has(hash);
}
