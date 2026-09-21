/**
 * Filename sanitization for downloaded artifacts (signed IPAs, pairing
 * files). Strips characters that are illegal on Windows/macOS and caps
 * the length so a hostile bundle name cannot escape the download name.
 */

const ILLEGAL_CHARS = /[\\/:*?"<>|]/g;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

/** Replaces illegal / control characters with `_` and caps the length. */
export function sanitizeFilename(name: string, maxLength = 120): string {
  const cleaned = name.replace(CONTROL_CHARS, '').replace(ILLEGAL_CHARS, '_').trim();
  if (!cleaned) return 'file';
  if (cleaned.length <= maxLength) return cleaned;
  const extIndex = cleaned.lastIndexOf('.');
  const ext = extIndex > 0 ? cleaned.slice(extIndex) : '';
  const stem = cleaned.slice(0, Math.max(0, maxLength - ext.length));
  return `${stem}${ext}`;
}
