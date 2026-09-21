// Port of `idevice/src/remote_pairing/tlv.rs` (Jackson Coxson).
//
// TLV8 framing for the remote-pairing protocol: a sequence of
// (1-byte type, 1-byte length, length bytes of data) entries.

/** Component types for TLV8-encoded remote pairing payloads. */
export enum PairingDataComponentType {
  Method = 0x00,
  Identifier = 0x01,
  Salt = 0x02,
  PublicKey = 0x03,
  Proof = 0x04,
  EncryptedData = 0x05,
  State = 0x06,
  ErrorResponse = 0x07,
  RetryDelay = 0x08,
  Certificate = 0x09,
  Signature = 0x0a,
  Permissions = 0x0b,
  FragmentData = 0x0c,
  FragmentLast = 0x0d,
  SessionId = 0x0e,
  Ttl = 0x0f,
  ExtraData = 0x10,
  Info = 0x11,
  Acl = 0x12,
  Flags = 0x13,
  ValidationData = 0x14,
  MfiAuthToken = 0x15,
  MfiProductType = 0x16,
  SerialNumber = 0x17,
  MfiAuthTokenUuid = 0x18,
  AppFlags = 0x19,
  OwnershipProof = 0x1a,
  SetupCodeType = 0x1b,
  ProductionData = 0x1c,
  AppInfo = 0x1d,
  Separator = 0xff,
}

/** A single TLV8 entry: a component type plus its raw payload bytes. */
export interface TLV8Entry {
  type: PairingDataComponentType;
  data: Uint8Array;
}

function typeFromByte(byte: number): PairingDataComponentType {
  // Numeric enums carry a reverse mapping, so `byte in Enum` holds exactly
  // for the declared discriminants.
  if (!(byte in PairingDataComponentType)) {
    throw new Error(
      `unknown TLV8 component type: 0x${byte.toString(16).padStart(2, '0')}`,
    );
  }
  return byte as PairingDataComponentType;
}

/** Serializes entries to TLV8 wire format. */
export function serializeTlv8(entries: TLV8Entry[]): Uint8Array {
  let total = 0;
  for (const entry of entries) {
    total += 2 + entry.data.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const entry of entries) {
    out[offset++] = entry.type;
    // Like Rust's `len as u8`, storing into a Uint8Array truncates to the low byte.
    out[offset++] = entry.data.length;
    out.set(entry.data, offset);
    offset += entry.data.length;
  }
  return out;
}

/**
 * Deserializes TLV8 wire format.
 * Throws on malformed input (a length overrunning the buffer) or on an
 * unknown component type byte. A trailing lone byte is ignored, like the
 * Rust original.
 */
export function deserializeTlv8(input: Uint8Array): TLV8Entry[] {
  const result: TLV8Entry[] = [];
  let index = 0;
  while (index + 2 <= input.length) {
    const typeByte = input[index];
    const length = input[index + 1];
    index += 2;
    if (index + length > input.length) {
      throw new Error(
        `malformed TLV8: entry claims ${length} bytes but only ${input.length - index} remain`,
      );
    }
    const data = input.slice(index, index + length);
    index += length;
    result.push({ type: typeFromByte(typeByte), data });
  }
  return result;
}

/** Concatenates the payloads of every entry with the given component type. */
export function collectComponentData(
  entries: TLV8Entry[],
  component: PairingDataComponentType,
): Uint8Array {
  let total = 0;
  for (const entry of entries) {
    if (entry.type === component) {
      total += entry.data.length;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const entry of entries) {
    if (entry.type === component) {
      out.set(entry.data, offset);
      offset += entry.data.length;
    }
  }
  return out;
}

/** Returns true if any entry has the given component type. */
export function containsComponent(
  entries: TLV8Entry[],
  component: PairingDataComponentType,
): boolean {
  return entries.some((entry) => entry.type === component);
}

// ---------------------------------------------------------------------------
// Plain numeric API (encodeTLV / decodeTLV)
// ---------------------------------------------------------------------------

/**
 * A TLV8 entry with a plain numeric type, for callers that do not want the
 * `PairingDataComponentType` enum.
 */
export interface TlvEntry {
  type: number;
  value: Uint8Array;
}

/**
 * Encodes entries to TLV8 wire format, fragmenting any value longer than 255
 * bytes into multiple consecutive same-type entries (HomeKit TLV8 semantics).
 *
 * This differs from `serializeTlv8` (a faithful port of the Rust original,
 * which truncates the length byte like `len as u8`): `encodeTLV` never
 * corrupts long values.
 */
export function encodeTLV(entries: TlvEntry[]): Uint8Array {
  let total = 0;
  for (const entry of entries) {
    if (!Number.isInteger(entry.type) || entry.type < 0 || entry.type > 0xff) {
      throw new Error(`TLV8 type must be a byte, got ${entry.type}`);
    }
    // Each fragment costs a 2-byte header.
    total += 2 * Math.max(1, Math.ceil(entry.value.length / 255)) + entry.value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const entry of entries) {
    if (entry.value.length === 0) {
      out[offset++] = entry.type;
      out[offset++] = 0;
      continue;
    }
    for (let pos = 0; pos < entry.value.length; pos += 255) {
      const chunk = entry.value.subarray(pos, pos + 255);
      out[offset++] = entry.type;
      out[offset++] = chunk.length;
      out.set(chunk, offset);
      offset += chunk.length;
    }
  }
  return out;
}

/**
 * Decodes TLV8 wire format with plain numeric types.
 *
 * Consecutive fragments with the same type are merged back into a single
 * entry, inverting `encodeTLV`'s fragmentation. Non-consecutive entries with
 * the same type are kept separate. Throws on malformed input; unlike
 * `deserializeTlv8`, unknown type bytes are preserved as-is.
 */
export function decodeTLV(data: Uint8Array): TlvEntry[] {
  const result: TlvEntry[] = [];
  let index = 0;
  while (index + 2 <= data.length) {
    const type = data[index];
    const length = data[index + 1];
    index += 2;
    if (index + length > data.length) {
      throw new Error(
        `malformed TLV8: entry claims ${length} bytes but only ${data.length - index} remain`,
      );
    }
    const value = data.slice(index, index + length);
    index += length;
    const prev = result[result.length - 1];
    if (prev !== undefined && prev.type === type) {
      // Merge with the previous fragment.
      const merged = new Uint8Array(prev.value.length + value.length);
      merged.set(prev.value, 0);
      merged.set(value, prev.value.length);
      prev.value = merged;
    } else {
      result.push({ type, value });
    }
  }
  return result;
}
