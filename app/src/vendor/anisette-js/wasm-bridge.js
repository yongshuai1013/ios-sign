// Low-level bridge to the Emscripten-generated WASM module.
// Handles all pointer/length marshalling so higher layers never touch raw memory.
export class WasmBridge {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    m;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    constructor(wasmModule) {
        this.m = wasmModule;
    }
    // ---- memory helpers ----
    allocBytes(bytes) {
        const ptr = this.m._malloc(bytes.length);
        this.m.HEAPU8.set(bytes, ptr);
        return ptr;
    }
    allocCString(value) {
        if (!value)
            return 0;
        const size = this.m.lengthBytesUTF8(value) + 1;
        const ptr = this.m._malloc(size);
        this.m.stringToUTF8(value, ptr, size);
        return ptr;
    }
    readBytes(ptr, len) {
        if (!ptr || !len)
            return new Uint8Array(0);
        return this.m.HEAPU8.slice(ptr, ptr + len);
    }
    free(ptr) {
        if (ptr)
            this.m._free(ptr);
    }
    // ---- error handling ----
    getLastError() {
        const ptr = this.m._anisette_last_error_ptr();
        const len = this.m._anisette_last_error_len();
        if (!ptr || !len)
            return "";
        const bytes = this.m.HEAPU8.subarray(ptr, ptr + len);
        return new TextDecoder("utf-8").decode(bytes);
    }
    check(result, context) {
        if (result !== 0) {
            const msg = this.getLastError();
            throw new Error(`${context}: ${msg || "unknown error"}`);
        }
    }
    // ---- public API ----
    /**
     * Initialize ADI from in-memory library blobs.
     */
    initFromBlobs(storeservices, coreadi, libraryPath, provisioningPath, identifier) {
        const ssPtr = this.allocBytes(storeservices);
        const caPtr = this.allocBytes(coreadi);
        const libPtr = this.allocCString(libraryPath);
        const provPtr = this.allocCString(provisioningPath ?? null);
        const idPtr = this.allocCString(identifier ?? null);
        try {
            const result = this.m._anisette_init_from_blobs(ssPtr, storeservices.length, caPtr, coreadi.length, libPtr, provPtr, idPtr);
            this.check(result, "anisette_init_from_blobs");
        }
        finally {
            this.free(ssPtr);
            this.free(caPtr);
            this.free(libPtr);
            this.free(provPtr);
            this.free(idPtr);
        }
    }
    /**
     * Read a file from the WASM virtual filesystem.
     */
    readVirtualFile(filePath) {
        const pathPtr = this.allocCString(filePath);
        try {
            const result = this.m._anisette_fs_read_file(pathPtr);
            this.check(result, `anisette_fs_read_file(${filePath})`);
        }
        finally {
            this.free(pathPtr);
        }
        const ptr = this.m._anisette_fs_read_ptr();
        const len = this.m._anisette_fs_read_len();
        return this.readBytes(ptr, len);
    }
    /**
     * Write a file into the WASM virtual filesystem.
     */
    writeVirtualFile(filePath, data) {
        const pathPtr = this.allocCString(filePath);
        const dataPtr = this.allocBytes(data);
        try {
            const result = this.m._anisette_fs_write_file(pathPtr, dataPtr, data.length);
            this.check(result, `anisette_fs_write_file(${filePath})`);
        }
        finally {
            this.free(pathPtr);
            this.free(dataPtr);
        }
    }
    /**
     * Returns 1 if provisioned, 0 if not, throws on error.
     */
    isMachineProvisioned(dsid) {
        const result = this.m._anisette_is_machine_provisioned(dsid);
        if (result < 0) {
            throw new Error(`anisette_is_machine_provisioned: ${this.getLastError()}`);
        }
        return result === 1;
    }
    /**
     * Start provisioning — returns CPIM bytes and session handle.
     */
    startProvisioning(dsid, spim) {
        const spimPtr = this.allocBytes(spim);
        try {
            const result = this.m._anisette_start_provisioning(dsid, spimPtr, spim.length);
            this.check(result, "anisette_start_provisioning");
        }
        finally {
            this.free(spimPtr);
        }
        const cpimPtr = this.m._anisette_get_cpim_ptr();
        const cpimLen = this.m._anisette_get_cpim_len();
        const session = this.m._anisette_get_session();
        return {
            cpim: this.readBytes(cpimPtr, cpimLen),
            session,
        };
    }
    /**
     * Finish provisioning with PTM and TK from Apple servers.
     */
    endProvisioning(session, ptm, tk) {
        const ptmPtr = this.allocBytes(ptm);
        const tkPtr = this.allocBytes(tk);
        try {
            const result = this.m._anisette_end_provisioning(session, ptmPtr, ptm.length, tkPtr, tk.length);
            this.check(result, "anisette_end_provisioning");
        }
        finally {
            this.free(ptmPtr);
            this.free(tkPtr);
        }
    }
    /**
     * Request OTP — returns OTP bytes and machine ID bytes.
     */
    requestOtp(dsid) {
        const result = this.m._anisette_request_otp(dsid);
        this.check(result, "anisette_request_otp");
        const otpPtr = this.m._anisette_get_otp_ptr();
        const otpLen = this.m._anisette_get_otp_len();
        const midPtr = this.m._anisette_get_mid_ptr();
        const midLen = this.m._anisette_get_mid_len();
        return {
            otp: this.readBytes(otpPtr, otpLen),
            machineId: this.readBytes(midPtr, midLen),
        };
    }
    /**
     * Check if IDBFS is available (browser environment only).
     */
    isIdbfsAvailable() {
        try {
            return !!(this.m.FS && this.m.FS.filesystems?.IDBFS);
        }
        catch {
            return false;
        }
    }
    /**
     * Initialize IDBFS for browser persistence.
     * Only works in browser environments with IDBFS available.
     */
    initIdbfs(path) {
        // Check if FS and IDBFS are available (browser only)
        if (!this.isIdbfsAvailable()) {
            return; // Node.js or environment without IDBFS
        }
        const normalizedPath = this.normalizeMountPath(path);
        // Create directory structure
        if (normalizedPath !== "/") {
            try {
                this.m.FS.mkdirTree(normalizedPath);
            }
            catch {
                // Directory already exists, ignore
            }
        }
        // Mount IDBFS
        try {
            this.m.FS.mount(this.m.FS.filesystems.IDBFS, {}, normalizedPath);
        }
        catch {
            // Already mounted, ignore
        }
    }
    /**
     * Sync IDBFS from IndexedDB to memory (async).
     * Must be called after initIdbfs to load existing data from IndexedDB.
     * Only works in browser environments with IDBFS available.
     */
    async syncIdbfsFromStorage() {
        if (!this.isIdbfsAvailable()) {
            return; // IDBFS not available, skip silently
        }
        return new Promise((resolve, reject) => {
            this.m.FS.syncfs(true, (err) => {
                if (err) {
                    console.error("[anisette] IDBFS sync from storage failed:", err);
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        });
    }
    /**
     * Sync IDBFS from memory to IndexedDB (async).
     * Must be called after modifying files to persist them.
     * Only works in browser environments with IDBFS available.
     */
    async syncIdbfsToStorage() {
        if (!this.isIdbfsAvailable()) {
            return; // IDBFS not available, skip silently
        }
        return new Promise((resolve, reject) => {
            this.m.FS.syncfs(false, (err) => {
                if (err) {
                    console.error("[anisette] IDBFS sync to storage failed:", err);
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        });
    }
    normalizeMountPath(path) {
        const trimmed = path.trim();
        const noSlash = trimmed.replace(/\/+$/, "");
        const noDot = noSlash.startsWith("./") ? noSlash.slice(2) : noSlash;
        if (!noDot || noDot === ".") {
            return "/";
        }
        else if (noDot.startsWith("/")) {
            return noDot;
        }
        else {
            return "/" + noDot;
        }
    }
}
//# sourceMappingURL=wasm-bridge.js.map