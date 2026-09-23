import { describe, expect, it } from 'vitest';
import {
  isKnownPageHash,
  pageToHash,
  resolvePageFromHash,
  LOGIN_PAGE_HASH,
  SIGN_PAGE_HASH,
  PAIRING_PAGE_HASH,
  DIRECT_INSTALL_PAGE_HASH,
  REFRESH_PAGE_HASH,
} from './router';

describe('hash routing', () => {
  it('resolves known hashes to pages', () => {
    expect(resolvePageFromHash(LOGIN_PAGE_HASH)).toBe('login');
    expect(resolvePageFromHash(SIGN_PAGE_HASH)).toBe('sign');
    expect(resolvePageFromHash(PAIRING_PAGE_HASH)).toBe('pairing');
    expect(resolvePageFromHash(DIRECT_INSTALL_PAGE_HASH)).toBe('direct-install');
    expect(resolvePageFromHash(REFRESH_PAGE_HASH)).toBe('refresh');
  });

  it('falls back to login for unknown or empty hashes', () => {
    expect(resolvePageFromHash('')).toBe('login');
    expect(resolvePageFromHash('#/nope')).toBe('login');
    expect(resolvePageFromHash('#/sign/extra')).toBe('login');
  });

  it('round-trips page -> hash -> page', () => {
    for (const page of ['login', 'sign', 'pairing', 'direct-install', 'refresh'] as const) {
      expect(resolvePageFromHash(pageToHash(page))).toBe(page);
    }
  });

  it('recognizes only the canonical hashes', () => {
    expect(isKnownPageHash(LOGIN_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(SIGN_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(PAIRING_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(DIRECT_INSTALL_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(REFRESH_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash('#/login/')).toBe(false);
    expect(isKnownPageHash('')).toBe(false);
  });
});
