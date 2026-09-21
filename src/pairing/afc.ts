/**
 * AFC (Apple File Conduit) client — TypeScript port of the Rust `idevice`
 * crate's `services/afc` module (`opcode.rs`, `packet.rs`, `mod.rs`).
 *
 * Wire format (mirrors `AfcPacket` / `AfcPacketHeader`):
 *   header         = 5 x little-endian u64 (40 bytes):
 *                      magic, entire_len, header_payload_len, packet_num, operation
 *   header_payload = header_payload_len - 40 bytes
 *   payload        = entire_len - header_payload_len bytes
 *
 * `magic` is the u64 little-endian encoding of the ASCII string "CFA6LPAA".
 * All path strings on the wire are null-terminated UTF-8.
 *
 * The constructor takes an already-connected {@link ByteTransport} — the caller
 * is responsible for running lockdownd `StartService("com.apple.afc")` first
 * and handing over the new connection's transport.
 */

/** Byte-oriented transport, mirroring the shape defined in usbmuxd.ts. */
export interface ByteTransport {
  write(data: Uint8Array): Promise<void>;
  readExact(n: number): Promise<Uint8Array>;
  close(): void;
}

/** AFC magic: u64 LE of the ASCII string "CFA6LPAA". */
export const AFC_MAGIC = 0x4141504c36414643n;

/** Length of the AFC packet header in bytes (5 x u64). */
export const AFC_HEADER_LEN = 40;

/** Chunk size used when streaming file data with the Write opcode. */
export const AFC_WRITE_CHUNK_SIZE = 60 * 1024;

/** AFC_E_OBJECT_EXISTS — returned e.g. when creating a directory that exists. */
export const AFC_E_OBJECT_EXISTS = 16;

/** AFC opcodes (u64 on the wire; values fit in a JS number). */
export enum AfcOpcode {
  Status = 1,
  Data = 2,
  ReadDir = 3,
  ReadFile = 4,
  WriteFile = 5,
  WritePart = 6,
  Truncate = 7,
  RemovePath = 8,
  MakeDir = 9,
  GetFileInfo = 10,
  GetDevInfo = 11,
  WriteFileAtom = 12,
  FileOpen = 13,
  FileOpenRes = 14,
  Read = 15,
  Write = 16,
  FileSeek = 17,
  FileTell = 18,
  FileTellRes = 19,
  FileClose = 20,
  FileSetSize = 21,
  GetConInfo = 22,
  SetConOptions = 23,
  RenamePath = 24,
  SetFsBs = 25,
  SetSocketBs = 26,
  FileLock = 27,
  MakeLink = 28,
  GetFileHash = 29,
  SetFileTime = 30,
  RemovePathAndContents = 34,
}

/** File open modes for the FileOpen opcode. */
export enum AfcFopenMode {
  RdOnly = 1, // r   O_RDONLY
  Rw = 2, // r+  O_RDWR   | O_CREAT
  WrOnly = 3, // w   O_WRONLY | O_CREAT  | O_TRUNC
  Wr = 4, // w+  O_RDWR   | O_CREAT  | O_TRUNC
  Append = 5, // a   O_WRONLY | O_APPEND | O_CREAT
  RdAppend = 6, // a+  O_RDWR   | O_APPEND | O_CREAT
}

/** Human-readable names for AFC status codes (mirrors afc/errors.rs). */
const AFC_STATUS_NAMES: Record<number, string> = {
  0: 'Success',
  1: 'Unknown error',
  2: 'Operation header invalid',
  3: 'No resources available',
  4: 'Read error',
  5: 'Write error',
  6: 'Unknown packet type',
  7: 'Invalid argument',
  8: 'Object not found',
  9: 'Object is a directory',
  10: 'Permission denied',
  11: 'Service not connected',
  12: 'Operation timed out',
  13: 'Too much data',
  14: 'End of data',
  15: 'Operation not supported',
  16: 'Object already exists',
  17: 'Object is busy',
  18: 'No space left',
  19: 'Operation would block',
  20: 'I/O error',
  21: 'Operation interrupted',
  22: 'Operation in progress',
  23: 'Internal error',
  30: 'Multiplexer error',
  31: 'Out of memory',
  32: 'Not enough data',
  33: 'Directory not empty',
};

/** Error raised when the device reports a non-zero AFC status code. */
export class AfcError extends Error {
  /** The AFC status code reported by the device. */
  readonly status: number;

  constructor(status: number, message?: string) {
    const name = AFC_STATUS_NAMES[status] ?? 'Unknown AFC error';
    super(message ?? `AFC error ${status}: ${name}`);
    this.name = 'AfcError';
    this.status = status;
  }
}

/** A parsed AFC response packet. */
export interface AfcResponse {
  operation: number;
  headerPayload: Uint8Array;
  payload: Uint8Array;
}

function u64le(value: number | bigint): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), true);
  return buf;
}

function readU64le(data: Uint8Array, offset = 0): bigint {
  return new DataView(data.buffer, data.byteOffset + offset, 8).getBigUint64(0, true);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Encodes a path as null-terminated UTF-8, as required by the AFC wire format. */
function encodePath(path: string): Uint8Array {
  return new TextEncoder().encode(path + '\0');
}

/**
 * Client for the AFC service on iOS devices.
 *
 * Mirrors the Rust `AfcClient`: requests and responses are paired by an
 * incrementing `packet_num`, and a `Status` response carrying a non-zero code
 * becomes an {@link AfcError}.
 */
export class AfcClient {
  private packetNum = 0n;

  constructor(private readonly transport: ByteTransport) {}

  /**
   * Sends one AFC operation and returns the parsed reply.
   *
   * A `Status` reply with a non-zero code throws {@link AfcError}; a returned
   * packet always represents success.
   */
  async request(
    opcode: number,
    headerPayload: Uint8Array,
    payload: Uint8Array = new Uint8Array(0),
  ): Promise<AfcResponse> {
    const packetNum = this.packetNum;
    this.packetNum += 1n;

    const headerPayloadLen = AFC_HEADER_LEN + headerPayload.length;
    const entireLen = headerPayloadLen + payload.length;
    const packet = new Uint8Array(entireLen);
    const dv = new DataView(packet.buffer);
    dv.setBigUint64(0, AFC_MAGIC, true);
    dv.setBigUint64(8, BigInt(entireLen), true);
    dv.setBigUint64(16, BigInt(headerPayloadLen), true);
    dv.setBigUint64(24, packetNum, true);
    dv.setBigUint64(32, BigInt(opcode), true);
    packet.set(headerPayload, AFC_HEADER_LEN);
    packet.set(payload, headerPayloadLen);
    await this.transport.write(packet);

    const res = await this.readPacket();
    if (res.packetNum !== packetNum) {
      throw new Error(
        `AFC: response packet_num ${res.packetNum} does not match request ${packetNum}`,
      );
    }
    if (res.operation === AfcOpcode.Status) {
      if (res.headerPayload.length < 8) {
        throw new Error('AFC: status response too short for status code');
      }
      const status = Number(readU64le(res.headerPayload));
      if (status !== 0) {
        throw new AfcError(status);
      }
    }
    return { operation: res.operation, headerPayload: res.headerPayload, payload: res.payload };
  }

  private async readPacket(): Promise<{
    packetNum: bigint;
    operation: number;
    headerPayload: Uint8Array;
    payload: Uint8Array;
  }> {
    const headerBytes = await this.transport.readExact(AFC_HEADER_LEN);
    const dv = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);
    const magic = dv.getBigUint64(0, true);
    if (magic !== AFC_MAGIC) {
      throw new AfcError(35, 'AFC: invalid magic in response header');
    }
    const entireLen = Number(dv.getBigUint64(8, true));
    const headerPayloadLen = Number(dv.getBigUint64(16, true));
    const packetNum = dv.getBigUint64(24, true);
    const operation = Number(dv.getBigUint64(32, true));
    if (headerPayloadLen < AFC_HEADER_LEN || entireLen < headerPayloadLen) {
      throw new Error('AFC: invalid packet lengths in response header');
    }
    const headerPayload = await this.transport.readExact(headerPayloadLen - AFC_HEADER_LEN);
    const payload = await this.transport.readExact(entireLen - headerPayloadLen);
    return { packetNum, operation, headerPayload, payload };
  }

  /**
   * Creates a directory on the device.
   *
   * `AFC_E_OBJECT_EXISTS` (16) is treated as success, mirroring how callers
   * use `mkdir -p` semantics for the staging directory.
   */
  async makeDirectory(path: string): Promise<void> {
    try {
      await this.request(AfcOpcode.MakeDir, encodePath(path));
    } catch (err) {
      if (err instanceof AfcError && err.status === AFC_E_OBJECT_EXISTS) {
        return;
      }
      throw err;
    }
  }

  /** Alias of {@link makeDirectory} kept for call-site brevity. */
  async makeDir(path: string): Promise<void> {
    return this.makeDirectory(path);
  }

  /** Removes a file or empty directory at `path` (AFC `RemovePath` opcode). */
  async removePath(path: string): Promise<void> {
    await this.request(AfcOpcode.RemovePath, encodePath(path));
  }

  /** Recursively removes `path` and all its contents. */
  async removePathRecursive(path: string): Promise<void> {
    await this.request(AfcOpcode.RemovePathAndContents, encodePath(path));
  }

  /**
   * Lists the names in a directory (AFC `ReadDir` opcode).
   *
   * The device answers with a `Data` packet whose header payload holds the
   * entries as null-terminated UTF-8 strings; empty segments are dropped.
   */
  async listDirectory(path: string): Promise<string[]> {
    const res = await this.request(AfcOpcode.ReadDir, encodePath(path));
    if (res.operation !== AfcOpcode.Data) {
      throw new Error(`AFC: ReadDir did not return a Data packet (op=${res.operation})`);
    }
    const body = concat(res.headerPayload, res.payload);
    return new TextDecoder()
      .decode(body)
      .split('\0')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  /**
   * Uploads `data` to `path`, creating/truncating the file (mode `Wr`).
   *
   * Flow: FileOpen(Wr) → Write in 60KB chunks → FileClose. A non-zero status
   * at any step throws {@link AfcError}; the handle is closed before the
   * error propagates.
   */
  async uploadFile(
    remotePath: string,
    data: Uint8Array,
    onProgress?: (sent: number, total: number) => void,
  ): Promise<void> {
    const openRes = await this.request(
      AfcOpcode.FileOpen,
      concat(u64le(AfcFopenMode.Wr), encodePath(remotePath)),
    );
    if (openRes.operation !== AfcOpcode.FileOpenRes || openRes.headerPayload.length < 8) {
      throw new Error('AFC: FileOpen did not return a file handle');
    }
    const handle = openRes.headerPayload.slice(0, 8);

    try {
      const total = data.byteLength;
      let sent = 0;
      while (sent < total) {
        const chunk = data.slice(sent, Math.min(sent + AFC_WRITE_CHUNK_SIZE, total));
        await this.request(AfcOpcode.Write, handle, chunk);
        sent += chunk.length;
        onProgress?.(sent, total);
      }
    } catch (err) {
      try {
        await this.request(AfcOpcode.FileClose, handle);
      } catch {
        // Best effort: don't mask the original error.
      }
      throw err;
    }
    await this.request(AfcOpcode.FileClose, handle);
  }

  /** Alias of {@link uploadFile}. */
  async writeFile(
    path: string,
    data: Uint8Array,
    onProgress?: (sent: number, total: number) => void,
  ): Promise<void> {
    return this.uploadFile(path, data, onProgress);
  }
}
