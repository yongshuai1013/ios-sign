/**
 * Minimal plist parser for the browser: XML plists via DOMParser and
 * binary (`bplist00`) plists via a hand-written reader.
 *
 * Used for `Payload/*.app/Info.plist` inside IPAs, which may be stored in
 * either format.
 */

export type PlistValue =
  | string
  | number
  | boolean
  | Uint8Array
  | Date
  | PlistValue[]
  | { [key: string]: PlistValue }
  | null;

function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ */
/* XML                                                                 */
/*                                                                     */
/* Hand-rolled parser for the tiny XML subset Apple uses in plists      */
/* (no DOMParser: keeps this module dependency-free and worker-safe).   */
/* ------------------------------------------------------------------ */

interface XmlNode {
  tag: string;
  children: XmlNode[];
  text: string;
}

function decodeEntities(s: string): string {
  return s.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (match, entity: string) => {
    switch (entity) {
      case 'amp':
        return '&';
      case 'lt':
        return '<';
      case 'gt':
        return '>';
      case 'quot':
        return '"';
      case 'apos':
        return "'";
      default:
        if (entity.startsWith('#x') || entity.startsWith('#X')) {
          return String.fromCodePoint(Number.parseInt(entity.slice(2), 16));
        }
        return String.fromCodePoint(Number.parseInt(entity.slice(1), 10));
    }
  });
}

function parseXmlDocument(text: string): XmlNode {
  const root: XmlNode = { tag: '', children: [], text: '' };
  const stack: XmlNode[] = [root];
  let i = 0;
  const len = text.length;

  const current = (): XmlNode => stack[stack.length - 1];

  while (i < len) {
    if (text[i] === '<') {
      if (text.startsWith('<!--', i)) {
        const end = text.indexOf('-->', i + 4);
        if (end === -1) throw new Error('malformed XML plist: unterminated comment');
        i = end + 3;
        continue;
      }
      if (text.startsWith('<?', i)) {
        const end = text.indexOf('?>', i + 2);
        if (end === -1) throw new Error('malformed XML plist: unterminated prolog');
        i = end + 2;
        continue;
      }
      if (text.startsWith('<!', i)) {
        // DOCTYPE / other declarations: skip to '>'
        const end = text.indexOf('>', i + 2);
        if (end === -1) throw new Error('malformed XML plist: unterminated declaration');
        i = end + 1;
        continue;
      }
      const end = text.indexOf('>', i + 1);
      if (end === -1) throw new Error('malformed XML plist: unterminated tag');
      const raw = text.slice(i + 1, end).trim();
      i = end + 1;
      if (raw.startsWith('/')) {
        const tag = raw.slice(1).trim();
        const node = stack.pop();
        if (!node || node.tag !== tag) {
          throw new Error(`malformed XML plist: mismatched </${tag}>`);
        }
        continue;
      }
      const selfClosing = raw.endsWith('/');
      const tag = (selfClosing ? raw.slice(0, -1) : raw).trim().split(/\s+/)[0];
      if (!tag) throw new Error('malformed XML plist: empty tag');
      const node: XmlNode = { tag, children: [], text: '' };
      current().children.push(node);
      if (!selfClosing) stack.push(node);
    } else {
      const next = text.indexOf('<', i);
      const chunk = next === -1 ? text.slice(i) : text.slice(i, next);
      current().text += chunk;
      i = next === -1 ? len : next;
    }
  }
  if (stack.length !== 1) throw new Error('malformed XML plist: unclosed tags');
  return root;
}

function xmlNodeToValue(node: XmlNode): PlistValue {
  switch (node.tag) {
    case 'dict': {
      const dict: { [key: string]: PlistValue } = {};
      const elements = node.children.filter((c) => c.tag !== '');
      for (let i = 0; i < elements.length; i += 2) {
        const keyEl = elements[i];
        const valEl = elements[i + 1];
        if (!keyEl || keyEl.tag !== 'key' || !valEl) {
          throw new Error('malformed plist dict');
        }
        dict[decodeEntities(keyEl.text.trim())] = xmlNodeToValue(valEl);
      }
      return dict;
    }
    case 'array':
      return node.children.filter((c) => c.tag !== '').map(xmlNodeToValue);
    case 'string':
      return decodeEntities(node.text);
    case 'integer': {
      const n = Number.parseInt(node.text.trim(), 10);
      if (!Number.isFinite(n)) throw new Error('malformed plist integer');
      return n;
    }
    case 'real': {
      const n = Number.parseFloat(node.text.trim());
      if (!Number.isFinite(n)) throw new Error('malformed plist real');
      return n;
    }
    case 'true':
      return true;
    case 'false':
      return false;
    case 'date': {
      const d = new Date(node.text.trim());
      if (Number.isNaN(d.getTime())) throw new Error('malformed plist date');
      return d;
    }
    case 'data':
      return base64ToBytes(decodeEntities(node.text));
    default:
      throw new Error(`unsupported plist tag <${node.tag}>`);
  }
}

function parseXmlPlist(data: Uint8Array): PlistValue {
  const text = new TextDecoder().decode(data);
  const doc = parseXmlDocument(text);
  const plistEl = doc.children.find((c) => c.tag === 'plist');
  if (!plistEl) throw new Error('not a plist document');
  const child = plistEl.children.find((c) => c.tag !== '');
  if (!child) throw new Error('empty plist document');
  return xmlNodeToValue(child);
}

/* ------------------------------------------------------------------ */
/* Binary (`bplist00`)                                                 */
/* ------------------------------------------------------------------ */

const APPLE_EPOCH_OFFSET = 978307200; // seconds between 1970 and 2001-01-01

class BinaryReader {
  private view: DataView;
  private offsetTable: number[] = [];
  private offsetSize = 0;
  private refSize = 0;
  private objects: PlistValue[] = [];

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  parse(): PlistValue {
    const magic = String.fromCharCode(...this.data.subarray(0, 8));
    if (magic !== 'bplist00') throw new Error('not a binary plist');
    const trailer = this.data.length - 32;
    this.offsetSize = this.data[trailer + 6];
    this.refSize = this.data[trailer + 7];
    const numObjects = Number(this.view.getBigUint64(trailer + 8));
    const topObject = Number(this.view.getBigUint64(trailer + 16));
    const offsetTableOffset = Number(this.view.getBigUint64(trailer + 24));
    for (let i = 0; i < numObjects; i++) {
      this.offsetTable.push(this.readUint(offsetTableOffset + i * this.offsetSize, this.offsetSize));
    }
    this.objects = new Array(numObjects).fill(null);
    return this.readObject(topObject);
  }

  private readUint(offset: number, size: number): number {
    let v = 0;
    for (let i = 0; i < size; i++) v = v * 256 + this.data[offset + i];
    return v;
  }

  private readObject(index: number): PlistValue {
    const cached = this.objects[index];
    if (cached !== null) return cached;
    const offset = this.offsetTable[index];
    const typeByte = this.data[offset];
    const type = typeByte >> 4;
    const info = typeByte & 0x0f;
    const value = this.readTyped(type, info, offset + 1);
    this.objects[index] = value;
    return value;
  }

  private readLength(info: number, offset: number): { length: number; next: number } {
    if (info !== 0x0f) return { length: info, next: offset };
    const typeByte = this.data[offset];
    if ((typeByte >> 4) !== 0x1) throw new Error('malformed binary plist length');
    const size = 1 << (typeByte & 0x0f);
    return { length: this.readUint(offset + 1, size), next: offset + 1 + size };
  }

  private readRef(offset: number): number {
    return this.readUint(offset, this.refSize);
  }

  private readTyped(type: number, info: number, offset: number): PlistValue {
    switch (type) {
      case 0x0:
        if (info === 0x0) return null;
        if (info === 0x8) return false;
        if (info === 0x9) return true;
        throw new Error('malformed binary plist (0x0)');
      case 0x1: {
        const size = 1 << info;
        let v = 0n;
        for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(this.data[offset + i]);
        const bits = BigInt(size * 8);
        if (v >> (bits - 1n)) v -= 1n << bits; // sign-extend
        return Number(v);
      }
      case 0x2: {
        const size = 1 << info;
        if (size === 4) return this.view.getFloat32(offset);
        if (size === 8) return this.view.getFloat64(offset);
        throw new Error('malformed binary plist real');
      }
      case 0x3: {
        const secs = this.view.getFloat64(offset);
        return new Date((secs + APPLE_EPOCH_OFFSET) * 1000);
      }
      case 0x4: {
        const { length, next } = this.readLength(info, offset);
        return this.data.slice(next, next + length);
      }
      case 0x5: {
        const { length, next } = this.readLength(info, offset);
        return String.fromCharCode(...this.data.subarray(next, next + length));
      }
      case 0x6: {
        const { length, next } = this.readLength(info, offset);
        const chars: string[] = [];
        for (let i = 0; i < length; i++) {
          chars.push(String.fromCharCode(this.view.getUint16(next + i * 2)));
        }
        return chars.join('');
      }
      case 0x8:
        return this.readUint(offset, info + 1);
      case 0xa: {
        const { length, next } = this.readLength(info, offset);
        const arr: PlistValue[] = [];
        for (let i = 0; i < length; i++) arr.push(this.readObject(this.readRef(next + i * this.refSize)));
        return arr;
      }
      case 0xc: {
        // set → represent as array (order not significant)
        const { length, next } = this.readLength(info, offset);
        const arr: PlistValue[] = [];
        for (let i = 0; i < length; i++) arr.push(this.readObject(this.readRef(next + i * this.refSize)));
        return arr;
      }
      case 0xd: {
        const { length, next } = this.readLength(info, offset);
        const dict: { [key: string]: PlistValue } = {};
        for (let i = 0; i < length; i++) {
          const key = this.readObject(this.readRef(next + i * this.refSize));
          const val = this.readObject(this.readRef(next + (length + i) * this.refSize));
          dict[String(key)] = val;
        }
        return dict;
      }
      default:
        throw new Error(`unsupported binary plist type 0x${type.toString(16)}`);
    }
  }
}

/** Parses an XML or binary plist from raw bytes. */
export function parsePlist(data: Uint8Array): PlistValue {
  if (
    data.length >= 8 &&
    data[0] === 0x62 && // 'b'
    data[1] === 0x70 && // 'p'
    data[2] === 0x6c && // 'l'
    data[3] === 0x69 && // 'i'
    data[4] === 0x73 && // 's'
    data[5] === 0x74    // 't'
  ) {
    return new BinaryReader(data).parse();
  }
  return parseXmlPlist(data);
}

/** Convenience: read a string value out of a parsed plist dict. */
export function plistString(dict: PlistValue, key: string): string | null {
  if (!dict || typeof dict !== 'object' || Array.isArray(dict)) return null;
  const v = (dict as { [k: string]: PlistValue })[key];
  return typeof v === 'string' ? v : null;
}
