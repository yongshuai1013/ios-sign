import { describe, expect, it } from 'vitest';
import { parsePlist, plistString, type PlistValue } from './plist';
import { TextEncoder } from 'node:util';

const XML_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.app</string>
  <key>CFBundleDisplayName</key>
  <string>Example &amp; Co</string>
  <key>CFBundleVersion</key>
  <string>42</string>
  <key>BuildNumber</key>
  <integer>7</integer>
  <key>MinimumOS</key>
  <real>17.2</real>
  <key>IsBeta</key>
  <true/>
  <key>IsHidden</key>
  <false/>
  <key>ReleaseDate</key>
  <date>2026-01-15T08:00:00Z</date>
  <key>IconData</key>
  <data>aGVsbG8=</data>
  <key>URLs</key>
  <array>
    <string>https://a.example</string>
    <string>https://b.example</string>
  </array>
  <key>Nested</key>
  <dict>
    <key>Deep</key>
    <string>value</string>
  </dict>
</dict>
</plist>`;

/** Hand-built `bplist00` encoding the dict {"a": "b", "n": 1}. */
const BINARY_PLIST = new Uint8Array([
  0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, // 'bplist00'
  0xd2, 0x01, 0x03, 0x02, 0x04, // obj0 @8: dict(2) keys[1,3] vals[2,4]
  0x51, 0x61, // obj1 @13: "a"
  0x51, 0x62, // obj2 @15: "b"
  0x51, 0x6e, // obj3 @17: "n"
  0x10, 0x01, // obj4 @19: int 1
  0x08, 0x0d, 0x0f, 0x11, 0x13, // offset table @21
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // trailer padding @26
  0x01, 0x01, // offsetSize=1, refSize=1
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // numObjects=5
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // topObject=0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, // offsetTableOffset=21
]);

describe('parsePlist (XML)', () => {
  it('parses a typical Info.plist', () => {
    const value = parsePlist(new TextEncoder().encode(XML_PLIST)) as {
      [key: string]: PlistValue;
    };
    expect(plistString(value, 'CFBundleIdentifier')).toBe('com.example.app');
    expect(plistString(value, 'CFBundleDisplayName')).toBe('Example & Co');
    expect(value['BuildNumber']).toBe(7);
    expect(value['MinimumOS']).toBeCloseTo(17.2);
    expect(value['IsBeta']).toBe(true);
    expect(value['IsHidden']).toBe(false);
    expect(value['ReleaseDate']).toBeInstanceOf(Date);
    expect(value['IconData']).toBeInstanceOf(Uint8Array);
    expect(Array.from(value['IconData'] as Uint8Array)).toEqual([104, 101, 108, 108, 111]);
    expect(value['URLs']).toEqual(['https://a.example', 'https://b.example']);
    expect((value['Nested'] as Record<string, unknown>)['Deep']).toBe('value');
  });

  it('rejects malformed XML', () => {
    expect(() => parsePlist(new TextEncoder().encode('<plist><dict>'))).toThrow();
  });

  it('rejects a non-plist document', () => {
    expect(() => parsePlist(new TextEncoder().encode('<html></html>'))).toThrow();
  });
});

describe('parsePlist (binary)', () => {
  it('parses a hand-built bplist00 dict', () => {
    const value = parsePlist(BINARY_PLIST) as Record<string, unknown>;
    expect(value).toEqual({ a: 'b', n: 1 });
  });

  it('rejects truncated binary plists', () => {
    expect(() => parsePlist(BINARY_PLIST.slice(0, 20))).toThrow();
  });
});

describe('plistString', () => {
  it('returns null for missing keys, non-dicts and non-strings', () => {
    expect(plistString(null, 'k')).toBeNull();
    expect(plistString(['x'], 'k')).toBeNull();
    expect(plistString({ k: 5 }, 'k')).toBeNull();
    expect(plistString({ k: 'v' }, 'missing')).toBeNull();
    expect(plistString({ k: 'v' }, 'k')).toBe('v');
  });
});
