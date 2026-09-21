import { describe, expect, it } from 'vitest';
import { sanitizeFilename } from './filenames';

describe('sanitizeFilename', () => {
  it('keeps plain names untouched', () => {
    expect(sanitizeFilename('MyApp-signed.ipa')).toBe('MyApp-signed.ipa');
  });

  it('replaces characters illegal on Windows/macOS', () => {
    expect(sanitizeFilename('a/b\\c:d*e?f"g<h>i|j.ipa')).toBe('a_b_c_d_e_f_g_h_i_j.ipa');
  });

  it('strips control characters', () => {
    expect(sanitizeFilename('app\x00\x1f.ipa')).toBe('app.ipa');
  });

  it('falls back for empty input', () => {
    expect(sanitizeFilename('')).toBe('file');
    expect(sanitizeFilename('///')).toBe('___');
  });

  it('caps length while preserving the extension', () => {
    const long = `${'x'.repeat(200)}.ipa`;
    const out = sanitizeFilename(long);
    expect(out.length).toBeLessThanOrEqual(120);
    expect(out.endsWith('.ipa')).toBe(true);
  });

  it('handles names without extension', () => {
    const out = sanitizeFilename('x'.repeat(200));
    expect(out.length).toBe(120);
  });
});
