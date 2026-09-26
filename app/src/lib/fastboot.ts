/**
 * Minimal fastboot client over WebUSB.
 *
 * Used for Motorola bootloader unlocking: the host (this page, running in
 * Chrome on an Android phone with OTG) talks to a Motorola phone that is
 * already in fastboot mode. Only the commands needed for the unlock flow
 * are implemented: `getvar`, `oem`, `reboot`.
 *
 * Protocol notes (matches the public fastboot protocol and the WebUSB
 * fastboot implementation used by e.g. the GrapheneOS web installer):
 * - fastboot USB interface: class 0xFF, subclass 0x42, protocol 0x03.
 * - Host sends the ASCII command as one bulk-OUT packet, padded to
 *   64 bytes (the spec's command packet size).
 * - Device answers with bulk-IN packets of up to 64 bytes: a 4-byte
 *   status word ("OKAY" / "FAIL" / "DATA" / "INFO") followed by payload.
 * - "INFO" packets may repeat (multi-line output); the final packet is
 *   "OKAY" or "FAIL".
 */
export class FastbootNotSupportedError extends Error {
  constructor() {
    super(
      'WebUSB is not available in this browser. ' +
        'Use a Chromium-based browser (Chrome / Edge) over HTTPS or localhost.',
    );
    this.name = 'FastbootNotSupportedError';
  }
}

export class FastbootError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FastbootError';
  }
}

const FASTBOOT_INTERFACE_CLASS = 0xff;
const FASTBOOT_INTERFACE_SUBCLASS = 0x42;
const FASTBOOT_INTERFACE_PROTOCOL = 0x03;
const FASTBOOT_PACKET_SIZE = 64;

/**
 * Minimal WebUSB surface used by this client. TypeScript's DOM lib in this
 * repo does not ship the WebUSB types, so we declare just what we need
 * (same approach as the `UsbDeviceLike` interfaces in `@pairing/webusb-mux`).
 */
interface FastbootUsbEndpointDescriptor {
  endpointNumber: number;
  direction: 'in' | 'out';
  type: 'bulk' | 'interrupt' | 'isochronous';
}

interface FastbootUsbAlternateInterface {
  interfaceClass: number;
  interfaceSubclass: number;
  interfaceProtocol: number;
  endpoints: FastbootUsbEndpointDescriptor[];
}

interface FastbootUsbInterface {
  interfaceNumber: number;
  alternates: FastbootUsbAlternateInterface[];
}

interface FastbootUsbConfiguration {
  interfaces: FastbootUsbInterface[];
}

interface FastbootUsbInTransferResult {
  data?: DataView;
  status: 'ok' | 'stall' | 'babble';
}

interface FastbootUsbOutTransferResult {
  bytesWritten?: number;
  status: 'ok' | 'stall' | 'babble';
}

interface FastbootUsbDevice {
  opened: boolean;
  configuration?: FastbootUsbConfiguration;
  open(): Promise<void>;
  close(): Promise<void>;
  selectConfiguration(configurationValue: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  transferIn(endpointNumber: number, length: number): Promise<FastbootUsbInTransferResult>;
  transferOut(endpointNumber: number, data: Uint8Array): Promise<FastbootUsbOutTransferResult>;
}

interface FastbootUsb {
  requestDevice(options: {
    filters: Array<{ classCode?: number; subclassCode?: number; protocolCode?: number }>;
  }): Promise<FastbootUsbDevice>;
}

const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
/** `oem unlock` waits for the user to confirm on the device screen. */
const UNLOCK_COMMAND_TIMEOUT_MS = 180_000;

export interface FastbootCallbacks {
  log: (message: string) => void;
}

export interface FastbootResponse {
  /** Final status word: "OKAY". Throws on "FAIL". */
  status: 'OKAY';
  /** Payload of the final OKAY packet (may be empty). */
  payload: string;
  /** Payloads of the INFO packets seen before the final status. */
  infos: string[];
}

export interface RunCommandOptions {
  timeoutMs?: number;
}

/** Parses one raw fastboot response packet. Exported for unit tests. */
export function parseFastbootPacket(data: Uint8Array): { status: string; payload: string } {
  if (data.length < 4) {
    throw new FastbootError(`fastboot: response too short (${data.length} bytes)`);
  }
  const status = String.fromCharCode(data[0], data[1], data[2], data[3]);
  // Payload is NUL-terminated / NUL-padded ASCII.
  let end = data.length;
  for (let i = 4; i < data.length; i++) {
    if (data[i] === 0) {
      end = i;
      break;
    }
  }
  const payload = new TextDecoder().decode(data.subarray(4, end));
  return { status, payload };
}

/**
 * Motorola's `oem get_unlock_data` answers with one INFO packet per line,
 * each payload looking like "(bootloader) 0A40...". Newer bootloaders
 * prepend an "Unlockdata:" label to the first line. Concatenate them into
 * the single unlock-data string the Motorola unlock site expects: pure
 * hex + "#" separators, no labels, no whitespace (per Motorola's own
 * instructions quoted on XDA).
 * Exported for unit tests.
 */
export function extractUnlockData(infos: string[]): string {
  return infos
    .map((line) => line.replace(/\(bootloader\)/gi, ''))
    .join('')
    .replace(/\s+/g, '')
    .replace(/^unlockdata:/i, '');
}

function encodeCommand(command: string): Uint8Array {
  const raw = new TextEncoder().encode(command);
  if (raw.length > FASTBOOT_PACKET_SIZE) {
    throw new FastbootError(`fastboot: command too long (${raw.length} bytes)`);
  }
  const packet = new Uint8Array(FASTBOOT_PACKET_SIZE);
  packet.set(raw);
  return packet;
}

export class FastbootClient {
  private device: FastbootUsbDevice | null = null;
  private inEndpoint = 0;
  private outEndpoint = 0;

  constructor(private readonly cb: FastbootCallbacks) {}

  get isConnected(): boolean {
    return this.device !== null && this.device.opened;
  }

  private assertWebUsb(): FastbootUsb {
    const usb = (navigator as Navigator & { usb?: FastbootUsb }).usb;
    if (typeof navigator === 'undefined' || !usb) {
      throw new FastbootNotSupportedError();
    }
    return usb;
  }

  /**
   * Shows the browser device picker filtered to fastboot interfaces, then
   * opens the device, claims the fastboot interface and resolves the bulk
   * endpoints.
   */
  async connect(): Promise<void> {
    const usb = this.assertWebUsb();
    if (this.device?.opened) return;
    this.cb.log('fastboot: waiting for device selection…');
    const device = await usb.requestDevice({
      filters: [
        {
          classCode: FASTBOOT_INTERFACE_CLASS,
          subclassCode: FASTBOOT_INTERFACE_SUBCLASS,
          protocolCode: FASTBOOT_INTERFACE_PROTOCOL,
        },
      ],
    });
    await device.open();
    if (!device.configuration) {
      await device.selectConfiguration(1);
    }
    const configuration = device.configuration;
    if (!configuration) {
      throw new FastbootError('fastboot: device has no active configuration');
    }
    let claimed = false;
    for (const iface of configuration.interfaces) {
      const alt = iface.alternates[0];
      if (
        alt &&
        alt.interfaceClass === FASTBOOT_INTERFACE_CLASS &&
        alt.interfaceSubclass === FASTBOOT_INTERFACE_SUBCLASS &&
        alt.interfaceProtocol === FASTBOOT_INTERFACE_PROTOCOL
      ) {
        await device.claimInterface(iface.interfaceNumber);
        for (const ep of alt.endpoints) {
          if (ep.type !== 'bulk') continue;
          if (ep.direction === 'in') this.inEndpoint = ep.endpointNumber;
          if (ep.direction === 'out') this.outEndpoint = ep.endpointNumber;
        }
        claimed = true;
        this.cb.log(`fastboot: claimed interface ${iface.interfaceNumber}`);
        break;
      }
    }
    if (!claimed || !this.inEndpoint || !this.outEndpoint) {
      try {
        await device.close();
      } catch {
        /* ignore */
      }
      throw new FastbootError('fastboot: no fastboot bulk endpoints found on this device');
    }
    this.device = device;
    this.cb.log('fastboot: connected');
  }

  private async transferInWithTimeout(length: number, timeoutMs: number): Promise<Uint8Array> {
    const device = this.device;
    if (!device) throw new FastbootError('fastboot: not connected');
    const endpoint = this.inEndpoint;
    const read = device.transferIn(endpoint, length).then((result) => {
      if (result.status !== 'ok' || !result.data) {
        throw new FastbootError(`fastboot: bulk-IN failed (status=${result.status})`);
      }
      return new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength);
    });
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new FastbootError(`fastboot: timed out after ${timeoutMs / 1000}s waiting for device response`)), timeoutMs);
    });
    return Promise.race([read, timeout]);
  }

  /**
   * Sends one command and reads packets until a final OKAY/FAIL arrives.
   * Throws {@link FastbootError} on FAIL, timeout, or protocol errors.
   */
  async runCommand(command: string, options: RunCommandOptions = {}): Promise<FastbootResponse> {
    const device = this.device;
    if (!device) throw new FastbootError('fastboot: not connected');
    const timeoutMs = options.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
    this.cb.log(`fastboot > ${command}`);
    const out = await device.transferOut(this.outEndpoint, encodeCommand(command));
    if (out.status !== 'ok') {
      throw new FastbootError(`fastboot: bulk-OUT failed (status=${out.status})`);
    }
    const infos: string[] = [];
    for (;;) {
      const packet = await this.transferInWithTimeout(FASTBOOT_PACKET_SIZE, timeoutMs);
      const { status, payload } = parseFastbootPacket(packet);
      if (status === 'INFO') {
        infos.push(payload);
        this.cb.log(`fastboot info: ${payload}`);
        continue;
      }
      if (status === 'OKAY') {
        this.cb.log(`fastboot < OKAY${payload ? ` ${payload}` : ''}`);
        return { status: 'OKAY', payload, infos };
      }
      if (status === 'FAIL') {
        throw new FastbootError(`fastboot: command failed: ${payload || '(no message)'}`);
      }
      if (status === 'DATA') {
        throw new FastbootError('fastboot: unexpected DATA response (not supported by this client)');
      }
      throw new FastbootError(`fastboot: unknown status word "${status}"`);
    }
  }

  /** `getvar:<name>`; returns the value from the OKAY payload. */
  async getVar(name: string, options: RunCommandOptions = {}): Promise<string> {
    const res = await this.runCommand(`getvar:${name}`, options);
    return res.payload;
  }

  /**
   * Connectivity probe: tries a few common getvar names and accepts any
   * protocol-level answer as proof the device is talking fastboot.
   * Motorola bootloaders don't implement `getvar:version` (they answer
   * INFO "version: not found" + FAIL), so a FAIL here must not kill the
   * connection — only a timeout (no answer at all) is a real failure.
   * Returns the first `name=value` that worked, or null when the device
   * answered the protocol but supports none of the probed variables.
   */
  async probeConnectivity(): Promise<{ value: string | null; answered: boolean }> {
    const names = ['version', 'product', 'version-bootloader'];
    let answered = false;
    for (const name of names) {
      try {
        const value = await this.getVar(name);
        return { value: `${name}=${value || '(empty)'}`, answered: true };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        if (/timed out/i.test(msg)) throw error;
        answered = true;
        this.cb.log(`fastboot: getvar:${name} not supported by this bootloader`);
      }
    }
    return { value: null, answered };
  }

  /**
   * `oem <args>`; returns the concatenated INFO output
   * (used for `oem get_unlock_data`), falling back to the OKAY payload
   * when the device sent no INFO packets.
   */
  async oem(args: string, options: RunCommandOptions = {}): Promise<string> {
    const res = await this.runCommand(`oem ${args}`, options);
    return res.infos.length > 0 ? res.infos.join('\n') : res.payload;
  }

  /**
   * `reboot`. The device reboots immediately, so the final OKAY may never
   * arrive — a timeout/disconnect after the command was sent is treated
   * as success.
   */
  async reboot(): Promise<void> {
    const device = this.device;
    if (!device) throw new FastbootError('fastboot: not connected');
    this.cb.log('fastboot > reboot');
    const out = await device.transferOut(this.outEndpoint, encodeCommand('reboot'));
    if (out.status !== 'ok') {
      throw new FastbootError(`fastboot: bulk-OUT failed (status=${out.status})`);
    }
    try {
      await this.transferInWithTimeout(FASTBOOT_PACKET_SIZE, 10_000);
      this.cb.log('fastboot: device acknowledged reboot');
    } catch {
      // Expected: the device is already rebooting and stops answering.
      this.cb.log('fastboot: device is rebooting (no final response, as expected)');
    }
  }

  /** Sends `oem unlock <code>` with a long timeout for on-device confirmation. */
  async oemUnlock(code: string): Promise<void> {
    await this.runCommand(`oem unlock ${code}`, { timeoutMs: UNLOCK_COMMAND_TIMEOUT_MS });
  }

  async close(): Promise<void> {
    const device = this.device;
    this.device = null;
    this.inEndpoint = 0;
    this.outEndpoint = 0;
    if (device) {
      try {
        await device.close();
      } catch {
        /* best effort */
      }
    }
  }
}
