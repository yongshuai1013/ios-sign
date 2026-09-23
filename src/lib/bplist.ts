/**
 * Minimal binary plist (bplist00) parser for the browser.
 * Handles the types used by installation_proxy Browse responses:
 * null, bool, int, real, date, data, ASCII string, UTF-16 string, array, dict, UID.
 */

function readUInt(buf: Uint8Array, offset: number, size: number): number {
  let val = 0;
  for (let i = 0; i < size; i++) {
    val = val * 256 + buf[offset + i]!;
  }
  return val;
}

export function parseBplist(buf: Uint8Array): unknown {
  // Verify header.
  const header = String.fromCharCode(...buf.slice(0, 8));
  if (header !== 'bplist00') {
    throw new Error(`not a bplist00 (header: ${JSON.stringify(header)})`);
  }

  // Trailer is the last 32 bytes.
  const trailer = buf.slice(buf.length - 32);
  const offsetSize = trailer[6]!;
  const refSize = trailer[7]!;
  const numObjects = readUInt(trailer, 8, 8);
  const topObject = readUInt(trailer, 16, 8);
  const offsetTableOffset = readUInt(trailer, 24, 8);

  // Read offset table.
  const offsets: number[] = [];
  for (let i = 0; i < numObjects; i++) {
    offsets.push(readUInt(buf, offsetTableOffset + i * offsetSize, offsetSize));
  }

  const getObject = (ref: number): unknown => {
    const offset = offsets[ref]!;
    const marker = buf[offset]!;
    const type = (marker & 0xf0) >> 4;
    const info = marker & 0x0f;

    const readLength = (pos: number): { length: number; next: number } => {
      if (info !== 0x0f) return { length: info, next: pos };
      // Length is in the following int.
      const lenMarker = buf[pos]!;
      const lenType = (lenMarker & 0xf0) >> 4;
      const lenInfo = lenMarker & 0x0f;
      if (lenType !== 0x1) throw new Error('bplist: length not an int');
      const lenSize = 1 << lenInfo;
      return { length: readUInt(buf, pos + 1, lenSize), next: pos + 1 + lenSize };
    };

    switch (type) {
      case 0x0: // null, bool, fill
        if (info === 0x0) return null;
        if (info === 0x8) return false;
        if (info === 0x9) return true;
        throw new Error(`bplist: unsupported simple type 0x${info.toString(16)}`);
      case 0x1: { // int
        const size = 1 << info;
        return readUInt(buf, offset + 1, size);
      }
      case 0x2: { // real
        const size = 1 << info;
        const view = new DataView(buf.buffer, buf.byteOffset + offset + 1, size);
        return size === 4 ? view.getFloat32(0, false) : view.getFloat64(0, false);
      }
      case 0x3: { // date
        const view = new DataView(buf.buffer, buf.byteOffset + offset + 1, 8);
        const appleEpoch = view.getFloat64(0, false);
        // Apple epoch is 2001-01-01; convert to Unix epoch.
        return new Date((appleEpoch + 978307200) * 1000);
      }
      case 0x4: { // data
        const { length, next } = readLength(offset + 1);
        return buf.slice(next, next + length);
      }
      case 0x5: { // ASCII string
        const { length, next } = readLength(offset + 1);
        return String.fromCharCode(...buf.slice(next, next + length));
      }
      case 0x6: { // UTF-16 string
        const { length, next } = readLength(offset + 1);
        const chars: string[] = [];
        for (let i = 0; i < length; i++) {
          const code = (buf[next + i * 2]! << 8) | buf[next + i * 2 + 1]!;
          chars.push(String.fromCharCode(code));
        }
        return chars.join('');
      }
      case 0x8: { // UID
        const size = info + 1;
        return { __uid: readUInt(buf, offset + 1, size) };
      }
      case 0xa: { // array
        const { length, next } = readLength(offset + 1);
        const arr: unknown[] = [];
        for (let i = 0; i < length; i++) {
          const ref = readUInt(buf, next + i * refSize, refSize);
          arr.push(getObject(ref));
        }
        return arr;
      }
      case 0xd: { // dict
        const { length, next } = readLength(offset + 1);
        const dict: Record<string, unknown> = {};
        for (let i = 0; i < length; i++) {
          const keyRef = readUInt(buf, next + i * refSize, refSize);
          const valRef = readUInt(buf, next + (length + i) * refSize, refSize);
          const key = getObject(keyRef);
          if (typeof key !== 'string') throw new Error('bplist: dict key not a string');
          dict[key] = getObject(valRef);
        }
        return dict;
      }
      default:
        throw new Error(`bplist: unsupported type 0x${type.toString(16)}`);
    }
  };

  return getObject(topObject);
}

/** Returns true if the buffer looks like a binary plist. */
export function isBplist(buf: Uint8Array): boolean {
  return (
    buf.length >= 8 &&
    buf[0] === 0x62 && // b
    buf[1] === 0x70 && // p
    buf[2] === 0x6c && // l
    buf[3] === 0x69 && // i
    buf[4] === 0x73 && // s
    buf[5] === 0x74 && // t
    buf[6] === 0x30 && // 0
    buf[7] === 0x30 // 0
  );
}
