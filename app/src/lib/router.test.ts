import { describe, expect, it } from 'vitest';
import {
  isKnownPageHash,
  pageToHash,
  resolvePageFromHash,
  LOGIN_PAGE_HASH,
  SIGN_PAGE_HASH,
  PAIRING_PAGE_HASH,
} from './router';

describe('hash routing', () => {
  it('resolves known hashes to pages', () => {
    expect(resolvePageFromHash(LOGIN_PAGE_HASH)).toBe('login');
    expect(resolvePageFromHash(SIGN_PAGE_HASH)).toBe('sign');
    expect(resolvePageFromHash(PAIRING_PAGE_HASH)).toBe('pairing');
  });

  it('falls back to login for unknown or empty hashes', () => {
    expect(resolvePageFromHash('')).toBe('login');
    expect(resolvePageFromHash('#/nope')).toBe('login');
    expect(resolvePageFromHash('#/sign/extra')).toBe('login');
  });

  it('round-trips page -> hash -> page', () => {
    for (const page of ['login', 'sign', 'pairing'] as const) {
      expect(resolvePageFromHash(pageToHash(page))).toBe(page);
    }
  });

  it('recognizes only the three canonical hashes', () => {
    expect(isKnownPageHash(LOGIN_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(SIGN_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash(PAIRING_PAGE_HASH)).toBe(true);
    expect(isKnownPageHash('#/login/')).toBe(false);
    expect(isKnownPageHash('')).toBe(false);
  });
});
