import { ZsignWasmResigner, ZsignWasmClient } from '../npm/browser.mjs';
export class ZsignClient {
    client = null;
    initialized = false;
    constructor() { }
    static async create(options = {}) {
        const instance = new ZsignClient();
        instance.client = await ZsignWasmClient.create(options);
        instance.initialized = true;
        return instance;
    }
    ensureInitialized() {
        if (!this.initialized || !this.client) {
            throw new Error('ZsignClient is not initialized. Call create() first.');
        }
    }
    version() {
        this.ensureInitialized();
        return this.client.version();
    }
    setLogLevel(level) {
        this.ensureInitialized();
        return this.client.setLogLevel(level);
    }
    signMachO(inputMachO, options = {}) {
        this.ensureInitialized();
        const data = this.client.signMachO(inputMachO, options);
        return { data };
    }
}
export class ZsignResigner {
    resigner = null;
    initialized = false;
    constructor() { }
    static async create(options = {}) {
        const instance = new ZsignResigner();
        instance.resigner = await ZsignWasmResigner.create(options);
        instance.initialized = true;
        return instance;
    }
    ensureInitialized() {
        if (!this.initialized || !this.resigner) {
            throw new Error('ZsignResigner is not initialized. Call create() first.');
        }
    }
    version() {
        this.ensureInitialized();
        return this.resigner.version();
    }
    setLogLevel(level) {
        this.ensureInitialized();
        return this.resigner.setLogLevel(level);
    }
    signMachO(inputMachO, options = {}) {
        this.ensureInitialized();
        const data = this.resigner.signMachO(inputMachO, options);
        return { data };
    }
    async signIpa(inputIpa, options = {}) {
        this.ensureInitialized();
        const data = await this.resigner.signIpa(inputIpa, options);
        return { data };
    }
}
export async function createClient(options) {
    return ZsignClient.create(options);
}
export async function createResigner(options) {
    return ZsignResigner.create(options);
}
// Export certificate chain utilities
export { CertificateChainBuilder, certChainBuilder, buildCertificateChain, buildCertificateChainDER } from './certchain.js';
//# sourceMappingURL=browser.js.map