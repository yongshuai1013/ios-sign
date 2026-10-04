/**
 * Certificate chain utilities for Apple code signing
 * Helps build complete certificate chains (Developer Cert + WWDR + Root CA)
 */
export interface CertificateChainOptions {
    /**
     * Developer certificate (.cer or .pem)
     */
    developerCert: Uint8Array | ArrayBuffer | Buffer;
    /**
     * WWDR certificate (optional, will download if not provided)
     */
    wwdrCert?: Uint8Array | ArrayBuffer | Buffer;
    /**
     * Apple Root CA (optional, will download if not provided)
     */
    rootCert?: Uint8Array | ArrayBuffer | Buffer;
    /**
     * Include Root CA in chain (default: false, usually not needed)
     */
    includeRootCA?: boolean;
}
export interface P12ChainOptions extends CertificateChainOptions {
    /**
     * Private key (PEM or DER format)
     */
    privateKey: Uint8Array | ArrayBuffer | Buffer;
    /**
     * Password for the output P12 (default: empty string)
     */
    password?: string;
}
export declare class CertificateChainBuilder {
    private wwdrCache;
    private rootCache;
    /**
     * Download WWDR certificate from Apple
     */
    downloadWWDR(): Promise<Uint8Array>;
    /**
     * Download Apple Root CA
     */
    downloadRootCA(): Promise<Uint8Array>;
    /**
     * Convert DER to PEM format
     */
    derToPem(der: Uint8Array, label?: string): string;
    /**
     * Build complete certificate chain in PEM format
     */
    buildCertificateChain(options: CertificateChainOptions): Promise<string>;
    /**
     * Build certificate chain and return as concatenated DER buffers
     * This is useful for passing directly to zsign
     */
    buildCertificateChainDER(options: CertificateChainOptions): Promise<Uint8Array>;
    /**
     * Utility: Convert various buffer types to Uint8Array
     */
    private toUint8Array;
    /**
     * Utility: Convert Uint8Array to Base64
     */
    private uint8ArrayToBase64;
}
export declare const certChainBuilder: CertificateChainBuilder;
export declare function buildCertificateChain(options: CertificateChainOptions): Promise<string>;
export declare function buildCertificateChainDER(options: CertificateChainOptions): Promise<Uint8Array>;
//# sourceMappingURL=certchain.d.ts.map