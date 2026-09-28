export interface StartProvisioningResult {
    cpim: Uint8Array;
    session: number;
}
export interface RequestOtpResult {
    otp: Uint8Array;
    machineId: Uint8Array;
}
export declare class WasmBridge {
    private m;
    constructor(wasmModule: any);
    private allocBytes;
    private allocCString;
    private readBytes;
    private free;
    getLastError(): string;
    private check;
    /**
     * Initialize ADI from in-memory library blobs.
     */
    initFromBlobs(storeservices: Uint8Array, coreadi: Uint8Array, libraryPath: string, provisioningPath?: string, identifier?: string): void;
    /**
     * Read a file from the WASM virtual filesystem.
     */
    readVirtualFile(filePath: string): Uint8Array;
    /**
     * Write a file into the WASM virtual filesystem.
     */
    writeVirtualFile(filePath: string, data: Uint8Array): void;
    /**
     * Returns 1 if provisioned, 0 if not, throws on error.
     */
    isMachineProvisioned(dsid: bigint): boolean;
    /**
     * Start provisioning — returns CPIM bytes and session handle.
     */
    startProvisioning(dsid: bigint, spim: Uint8Array): StartProvisioningResult;
    /**
     * Finish provisioning with PTM and TK from Apple servers.
     */
    endProvisioning(session: number, ptm: Uint8Array, tk: Uint8Array): void;
    /**
     * Request OTP — returns OTP bytes and machine ID bytes.
     */
    requestOtp(dsid: bigint): RequestOtpResult;
    /**
     * Check if IDBFS is available (browser environment only).
     */
    isIdbfsAvailable(): boolean;
    /**
     * Initialize IDBFS for browser persistence.
     * Only works in browser environments with IDBFS available.
     */
    initIdbfs(path: string): void;
    /**
     * Sync IDBFS from IndexedDB to memory (async).
     * Must be called after initIdbfs to load existing data from IndexedDB.
     * Only works in browser environments with IDBFS available.
     */
    syncIdbfsFromStorage(): Promise<void>;
    /**
     * Sync IDBFS from memory to IndexedDB (async).
     * Must be called after modifying files to persist them.
     * Only works in browser environments with IDBFS available.
     */
    syncIdbfsToStorage(): Promise<void>;
    private normalizeMountPath;
}
//# sourceMappingURL=wasm-bridge.d.ts.map