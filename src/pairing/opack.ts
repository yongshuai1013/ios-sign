// Port of `idevice/src/remote_pairing/opack.rs` (Jackson Coxson).
//
// OPACK is Apple's compact binary plist-like encoding used by the
// remote-pairing protocol. Scalars seen while decoding are interned in a
// back-reference table so later occurrences can be sent as small pointers
// instead of being repeated.
//
// NOTE on the real tag layout (verified against the idevice source; an
// earlier guessed table with 0x00=null / 0x28=UUID / 0x10+=string etc. does
// NOT match the wire format):
//   0x01 true, 0x02 false, 0x08..=0x2F small ints (tag-8),
//   0x30 u8, 0x31 u16, 0x32 u32, 0x33 u64 (all little-endian),
//   0x35 f32 / 0x36 f64 (big-endian), 0x40..=0x60 inline string,
//   0x61/0x62/0x63/0x64 string with u8/u16/u32/u64 LE length,
//   0x70..=0x90 inline data, 0x91..=0x94 data with explicit LE length,
//   0xA0..=0xC0 / 0xC1..=0xC4 back-references,
//   0xD0..=0xDE / 0xDF arrays, 0xE0..=0xEE / 0xEF dicts (0xDF/0xEF use a
//   0x03 terminator). There is no null or UUID tag.

/** A plist-compatible value that OPACK can encode. */
export type PlistValue =
  | string
  | number
  | bigint
  | boolean
  | Uint8Array
  | PlistValue[]
  | { [key: string]: PlistValue };

const utf8Encoder = new TextEncoder();
const utf8DecoderStrict = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/** Encodes a plist value to OPACK bytes. */
export function plistToOpack(value: PlistValue): Uint8Array {
  const buf: number[] = [];
  encodeValue(value, buf);
  return Uint8Array.from(buf);
}

function encodeValue(node: PlistValue, buf: number[]): void {
  if (typeof node === 'string') {
    encodeString(node, buf);
  } else if (typeof node === 'bigint') {
    encodeBigint(node, buf);
  } else if (typeof node === 'number') {
    encodeNumber(node, buf);
  } else if (typeof node === 'boolean') {
    buf.push(node ? 0x01 : 0x02);
  } else if (node instanceof Uint8Array) {
    encodeData(node, buf);
  } else if (Array.isArray(node)) {
    encodeArray(node, buf);
  } else {
    encodeDict(node, buf);
  }
}

function encodeDict(dict: { [key: string]: PlistValue }, buf: number[]): void {
  const entries = Object.entries(dict);
  const count = entries.length;
  // (count - 32) mod 256 == 0xE0 + count for count < 15.
  buf.push(count < 15 ? (count - 32) & 0xff : 0xef);
  for (const [key, val] of entries) {
    encodeString(key, buf);
    encodeValue(val, buf);
  }
  if (count >= 15) {
    buf.push(0x03); // Terminator
  }
}

function encodeArray(array: PlistValue[], buf: number[]): void {
  const count = array.length;
  // (count - 48) mod 256 == 0xD0 + count for count < 15.
  buf.push(count < 15 ? (count - 48) & 0xff : 0xdf);
  for (const val of array) {
    encodeValue(val, buf);
  }
  if (count >= 15) {
    buf.push(0x03); // Terminator
  }
}

function encodeNumber(node: number, buf: number[]): void {
  if (Number.isInteger(node)) {
    // Mirrors Rust's `as_unsigned().unwrap_or(0)`: negatives become 0.
    encodeInteger(node < 0 ? 0 : node, buf);
  } else {
    encodeReal(node, buf);
  }
}

function encodeInteger(value: number, buf: number[]): void {
  if (value <= 0x27) {
    buf.push(0x08 + value);
  } else if (value <= 0xff) {
    buf.push(0x30, value);
  } else if (value <= 0xffffffff) {
    buf.push(0x32);
    pushU32LE(buf, value);
  } else {
    buf.push(0x33);
    pushU64LE(buf, value);
  }
}

/** Encodes a bigint as an unsigned integer on the same size ladder. */
function encodeBigint(value: bigint, buf: number[]): void {
  if (value < 0n) {
    throw new RangeError(`OPACK cannot encode negative bigint: ${value}`);
  }
  if (value <= 0x27n) {
    buf.push(0x08 + Number(value));
  } else if (value <= 0xffn) {
    buf.push(0x30, Number(value));
  } else if (value <= 0xffffffffn) {
    buf.push(0x32);
    pushU32LE(buf, Number(value));
  } else if (value <= 0xffffffffffffffffn) {
    buf.push(0x33);
    let v = value;
    for (let i = 0; i < 8; i++) {
      buf.push(Number(v & 0xffn));
      v >>= 8n;
    }
  } else {
    throw new RangeError(`bigint out of uint64 range: ${value}`);
  }
}

function encodeReal(value: number, buf: number[]): void {
  if (Math.fround(value) === value) {
    // Losslessly representable as f32: 0x35 + big-endian f32 bits.
    buf.push(0x35);
    const view = new DataView(new ArrayBuffer(4));
    view.setFloat32(0, value, false);
    for (let i = 0; i < 4; i++) {
      buf.push(view.getUint8(i));
    }
  } else {
    buf.push(0x36);
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value, false);
    for (let i = 0; i < 8; i++) {
      buf.push(view.getUint8(i));
    }
  }
}

function encodeString(s: string, buf: number[]): void {
  const bytes = utf8Encoder.encode(s);
  pushSizedTag(buf, bytes.length, 0x40, 0x61, 0x62, 0x63, 0x64);
  for (const b of bytes) {
    buf.push(b);
  }
}

function encodeData(data: Uint8Array, buf: number[]): void {
  pushSizedTag(buf, data.length, 0x70, 0x91, 0x92, 0x93, 0x94);
  for (const b of data) {
    buf.push(b);
  }
}

/** Emits the length tag for strings/data: inline tag, or u8/u16/u32/u64 tag + LE length. */
function pushSizedTag(
  buf: number[],
  len: number,
  inlineBase: number,
  u8Tag: number,
  u16Tag: number,
  u32Tag: number,
  u64Tag: number,
): void {
  if (len <= 0x20) {
    buf.push(inlineBase + len);
  } else if (len <= 0xff) {
    buf.push(u8Tag, len);
  } else if (len <= 0xffff) {
    buf.push(u16Tag);
    pushU16LE(buf, len);
  } else if (len <= 0xffffffff) {
    buf.push(u32Tag);
    pushU32LE(buf, len);
  } else {
    buf.push(u64Tag);
    pushU64LE(buf, len);
  }
}

function pushU16LE(buf: number[], value: number): void {
  buf.push(value & 0xff, (value >>> 8) & 0xff);
}

function pushU32LE(buf: number[], value: number): void {
  buf.push(
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  );
}

function pushU64LE(buf: number[], value: number): void {
  let v = BigInt(Math.floor(value));
  for (let i = 0; i < 8; i++) {
    buf.push(Number(v & 0xffn));
    v >>= 8n;
  }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/** Decodes OPACK bytes back to a plist value. Throws on malformed input. */
export function opackToPlist(bytes: Uint8Array): PlistValue {
  const reader = new OpackReader(bytes);
  const objects: PlistValue[] = [];
  const value = decodeValue(reader, objects);
  if (reader.pos !== bytes.length) {
    throw new Error(
      `unexpected trailing bytes after OPACK payload: ${bytes.length - reader.pos}`,
    );
  }
  return value;
}

class OpackReader {
  pos = 0;
  constructor(private readonly bytes: Uint8Array) {}

  peek(): number | undefined {
    return this.pos < this.bytes.length ? this.bytes[this.pos] : undefined;
  }

  u8(): number {
    const b = this.peek();
    if (b === undefined) {
      throw new Error('unexpected EOF while reading OPACK tag');
    }
    this.pos += 1;
    return b;
  }

  take(n: number): Uint8Array {
    if (this.pos + n > this.bytes.length) {
      throw new Error(`unexpected EOF while reading ${n} bytes`);
    }
    const slice = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  u16le(): number {
    const b = this.take(2);
    return b[0] | (b[1] << 8);
  }

  u32le(): number {
    const b = this.take(4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }

  u64le(): number {
    const b = this.take(8);
    let v = 0;
    for (let i = 7; i >= 0; i--) {
      v = v * 256 + b[i];
    }
    return v;
  }

  /**
   * Reads a u64 tag value, returning a `bigint` when it does not fit in a
   * JS number exactly, so `decode(encode(biguint))` round-trips.
   */
  u64Int(): number | bigint {
    const b = this.take(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) {
      v = (v << 8n) | BigInt(b[i]);
    }
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
}

/** Scalar equality used for back-reference interning (strings/numbers/data). */
function scalarEquals(a: PlistValue, b: PlistValue): boolean {
  if (typeof a !== typeof b) {
    return false;
  }
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    return (
      a instanceof Uint8Array &&
      b instanceof Uint8Array &&
      a.length === b.length &&
      a.every((v, i) => v === (b as Uint8Array)[i])
    );
  }
  return a === b;
}

/**
 * Interns `value` in the back-reference table and hands it back unchanged.
 * Only scalars are interned — collections never are — and a repeat is not
 * appended twice, otherwise every later index would be off by one.
 */
function remember(objects: PlistValue[], value: PlistValue): PlistValue {
  if (!objects.some((o) => scalarEquals(o, value))) {
    objects.push(value);
  }
  return value;
}

function lookup(objects: PlistValue[], index: number): PlistValue {
  const value = objects[index];
  if (value === undefined) {
    throw new Error(
      `OPACK back-reference ${index} out of range, only ${objects.length} objects seen`,
    );
  }
  return value;
}

interface SizedLenTags {
  inlineBase: number;
  u8Tag: number;
  u16Tag: number;
  u32Tag: number;
  u64Tag: number;
  kind: string;
}

function readSizedLen(
  reader: OpackReader,
  tag: number,
  tags: SizedLenTags,
): number {
  if (tag >= tags.inlineBase && tag < tags.u8Tag) {
    return tag - tags.inlineBase;
  }
  if (tag === tags.u8Tag) {
    return reader.u8();
  }
  if (tag === tags.u16Tag) {
    return reader.u16le();
  }
  if (tag === tags.u32Tag) {
    return reader.u32le();
  }
  if (tag === tags.u64Tag) {
    return reader.u64le();
  }
  throw new Error(
    `unsupported OPACK ${tags.kind} tag: 0x${tag.toString(16).padStart(2, '0')}`,
  );
}

function decodeStringValue(
  reader: OpackReader,
  tag: number,
): PlistValue {
  const len = readSizedLen(reader, tag, {
    inlineBase: 0x40,
    u8Tag: 0x61,
    u16Tag: 0x62,
    u32Tag: 0x63,
    u64Tag: 0x64,
    kind: 'string',
  });
  const bytes = reader.take(len);
  let s: string;
  try {
    s = utf8DecoderStrict.decode(bytes);
  } catch {
    throw new Error('invalid UTF-8 string in OPACK payload');
  }
  return s;
}

function decodeDataValue(reader: OpackReader, tag: number): Uint8Array {
  const len = readSizedLen(reader, tag, {
    inlineBase: 0x70,
    u8Tag: 0x91,
    u16Tag: 0x92,
    u32Tag: 0x93,
    u64Tag: 0x94,
    kind: 'data',
  });
  return reader.take(len);
}

function decodeArray(
  reader: OpackReader,
  objects: PlistValue[],
  count: number | undefined,
): PlistValue[] {
  const items: PlistValue[] = [];
  if (count !== undefined) {
    for (let i = 0; i < count; i++) {
      items.push(decodeValue(reader, objects));
    }
  } else {
    while (reader.peek() !== 0x03) {
      items.push(decodeValue(reader, objects));
    }
    reader.u8(); // consume terminator
  }
  return items;
}

function decodeDict(
  reader: OpackReader,
  objects: PlistValue[],
  count: number | undefined,
): { [key: string]: PlistValue } {
  const dict: { [key: string]: PlistValue } = {};
  const readPair = () => {
    const key = decodeValue(reader, objects);
    if (typeof key !== 'string') {
      throw new Error('dictionary key is not a string');
    }
    dict[key] = decodeValue(reader, objects);
  };
  if (count !== undefined) {
    for (let i = 0; i < count; i++) {
      readPair();
    }
  } else {
    while (reader.peek() !== 0x03) {
      readPair();
    }
    reader.u8(); // consume terminator
  }
  return dict;
}

function decodeValue(reader: OpackReader, objects: PlistValue[]): PlistValue {
  const tag = reader.u8();

  if (tag === 0x01) return true;
  if (tag === 0x02) return false;
  if (tag >= 0x08 && tag <= 0x2f) return tag - 8;

  if (tag === 0x30) return remember(objects, reader.u8());
  if (tag === 0x31) return remember(objects, reader.u16le());
  if (tag === 0x32) return remember(objects, reader.u32le());
  if (tag === 0x33) return remember(objects, reader.u64Int());

  if (tag === 0x35) {
    const raw = reader.take(4);
    const view = new DataView(raw.buffer, raw.byteOffset, 4);
    return remember(objects, view.getFloat32(0, false));
  }
  if (tag === 0x36) {
    const raw = reader.take(8);
    const view = new DataView(raw.buffer, raw.byteOffset, 8);
    return remember(objects, view.getFloat64(0, false));
  }

  if (tag >= 0x40 && tag <= 0x64) {
    return remember(objects, decodeStringValue(reader, tag));
  }
  if (tag >= 0x70 && tag <= 0x94) {
    return remember(objects, decodeDataValue(reader, tag));
  }

  // Back-reference to an already-seen scalar, index encoded in the tag.
  if (tag >= 0xa0 && tag <= 0xc0) {
    return lookup(objects, tag - 0xa0);
  }
  // Back-reference with an out-of-line index: 1, 2, 4 or 8 little-endian
  // bytes, same size ladder the integer tags use.
  if (tag >= 0xc1 && tag <= 0xc4) {
    let index: number;
    if (tag === 0xc1) index = reader.u8();
    else if (tag === 0xc2) index = reader.u16le();
    else if (tag === 0xc3) index = reader.u32le();
    else index = reader.u64le();
    return lookup(objects, index);
  }

  if (tag >= 0xd0 && tag <= 0xde) return decodeArray(reader, objects, tag - 0xd0);
  if (tag === 0xdf) return decodeArray(reader, objects, undefined);
  if (tag >= 0xe0 && tag <= 0xee) return decodeDict(reader, objects, tag - 0xe0);
  if (tag === 0xef) return decodeDict(reader, objects, undefined);

  if (tag === 0x03) {
    throw new Error('unexpected OPACK terminator');
  }
  throw new Error(`unsupported OPACK tag: 0x${tag.toString(16).padStart(2, '0')}`);
}


// ---------------------------------------------------------------------------
// Generic encode / decode API
// ---------------------------------------------------------------------------

/**
 * Encodes any supported value to OPACK bytes.
 *
 * Supported: `string`, `number` (integers and doubles), `bigint` (uint64),
 * `boolean`, `Uint8Array` (data), arrays, and plain-object dicts.
 *
 * Not representable (the real Apple/idevice OPACK has no such tags, so these
 * throw `TypeError` instead of silently dropping data like the Rust
 * encoder's `_ => {}` arm): `null`/`undefined` — use `false`, `0`, `""`, or
 * an empty `Uint8Array`; UUIDs — pass the 16 raw bytes as a `Uint8Array`.
 */
export function encode(value: unknown): Uint8Array {
  return plistToOpack(assertPlistValue(value));
}

/** Decodes OPACK bytes. Returns `unknown`; throws on malformed input. */
export function decode(data: Uint8Array): unknown {
  return opackToPlist(data);
}

function assertPlistValue(value: unknown): PlistValue {
  if (value === null || value === undefined) {
    throw new TypeError(
      'OPACK has no null representation (no null tag exists in the real format); ' +
        'use false, 0, "", or an empty Uint8Array instead',
    );
  }
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'bigint' ||
    typeof value === 'boolean' ||
    value instanceof Uint8Array
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(assertPlistValue);
  }
  if (typeof value === 'object') {
    const dict: { [key: string]: PlistValue } = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      dict[k] = assertPlistValue(v);
    }
    return dict;
  }
  throw new TypeError(
    `OPACK cannot encode value of type ${typeof value}`,
  );
}
