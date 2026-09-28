import type { AnisetteHeaders, InitOptions } from "./types.js";
import type { HttpClient } from "./http.js";
import { Device } from "./device.js";
export interface AnisetteOptions {
    /** Override the HTTP client (useful for testing or custom proxy) */
    httpClient?: HttpClient;
    /** DSID to use when requesting OTP (default: -2) */
    dsid?: bigint;
    /** Options passed to WASM init */
    init?: InitOptions;
}
export declare class Anisette {
    private bridge;
    private device;
    private provisioning;
    private dsid;
    private provisioningPath;
    private libraryPath;
    private libs;
    private wasmModule;
    private identifier;
    private httpClient;
    private constructor();
    /**
     * Initialize from the two Android .so library files.
     * @param storeservicescore - bytes of libstoreservicescore.so
     * @param coreadi           - bytes of libCoreADI.so
     */
    static fromSo(storeservicescore: Uint8Array, coreadi: Uint8Array, wasmModule: any, options?: AnisetteOptions): Promise<Anisette>;
    private static _init;
    /** Whether the device is currently provisioned. */
    get isProvisioned(): boolean;
    /** Run the provisioning flow against Apple servers. */
    provision(): Promise<void>;
    /** Read adi.pb from the WASM VFS for persistence. */
    getAdiPb(): Uint8Array;
    /** Generate Anisette headers. Throws if not provisioned. */
    getData(): Promise<AnisetteHeaders>;
    /** Serialize device.json bytes for persistence. */
    getDeviceJson(): Uint8Array;
    /** Expose the device for inspection. */
    getDevice(): Device;
}
//# sourceMappingURL=anisette.d.ts.map