import type { SignMachOOptions, SignIpaOptions } from '../npm/index.mjs';
export interface CreateResignerOptions {
    moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
    moduleOptions?: Record<string, unknown>;
}
export interface CreateClientOptions {
    moduleFactory?: (opts?: Record<string, unknown>) => Promise<unknown>;
    moduleOptions?: Record<string, unknown>;
}
export interface MachOSignResult {
    data: Uint8Array;
}
export interface IpaSignResult {
    data: Uint8Array;
}
export declare class ZsignClient {
    private client;
    private initialized;
    private constructor();
    static create(options?: CreateClientOptions): Promise<ZsignClient>;
    private ensureInitialized;
    version(): string;
    setLogLevel(level: number): number;
    signMachO(inputMachO: Uint8Array | ArrayBuffer | Buffer, options?: SignMachOOptions): MachOSignResult;
}
export declare class ZsignResigner {
    private resigner;
    private initialized;
    private constructor();
    static create(options?: CreateResignerOptions): Promise<ZsignResigner>;
    private ensureInitialized;
    version(): string;
    setLogLevel(level: number): number;
    signMachO(inputMachO: Uint8Array | ArrayBuffer | Buffer, options?: SignMachOOptions): MachOSignResult;
    signIpa(inputIpa: Uint8Array | ArrayBuffer | Buffer, options?: SignIpaOptions): Promise<IpaSignResult>;
}
export declare function createClient(options?: CreateClientOptions): Promise<ZsignClient>;
export declare function createResigner(options?: CreateResignerOptions): Promise<ZsignResigner>;
export type { SignMachOOptions, SignIpaOptions };
export { CertificateChainBuilder, certChainBuilder, buildCertificateChain, buildCertificateChainDER } from './certchain.js';
export type { CertificateChainOptions, P12ChainOptions } from './certchain.js';
//# sourceMappingURL=index.d.ts.map