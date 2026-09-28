export interface SignMachOOptions {
  cert?: Uint8Array | ArrayBuffer;
  pkey?: Uint8Array | ArrayBuffer;
  prov?: Uint8Array | ArrayBuffer;
  entitlements?: Uint8Array | ArrayBuffer;
  password?: string;
  adhoc?: boolean;
  sha256Only?: boolean;
  forceSign?: boolean;
}

export interface SignIpaOptions extends SignMachOOptions {
  bundleId?: string;
  bundleVersion?: string;
  displayName?: string;
  weakInject?: boolean;
  enableCache?: boolean;
  zipLevel?: number;
}

export class ZsignWasmClient {
  static create(options?: {
    moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
    moduleOptions?: Record<string, unknown>;
  }): Promise<ZsignWasmClient>;

  version(): string;
  setLogLevel(level: number): number;
  signMachO(inputMachO: Uint8Array | ArrayBuffer, options?: SignMachOOptions): Uint8Array;
}

export class ZsignWasmResigner {
  static create(options?: {
    moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
    moduleOptions?: Record<string, unknown>;
  }): Promise<ZsignWasmResigner>;

  version(): string;
  setLogLevel(level: number): number;
  signMachO(inputMachO: Uint8Array | ArrayBuffer, options?: SignMachOOptions): Uint8Array;
  signIpa(inputIpa: Uint8Array | ArrayBuffer, options?: SignIpaOptions): Promise<Uint8Array>;
}

export function createResigner(options?: {
  moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
  moduleOptions?: Record<string, unknown>;
}): Promise<ZsignWasmResigner>;

export function createZsignModule(opts?: Record<string, unknown>): Promise<unknown>;
export function createEmbeddedZsignModule(opts?: Record<string, unknown>): Promise<unknown>;
