/** Encode string to UTF-8 bytes */
export declare function encodeUtf8(str: string): Uint8Array;
/** Decode UTF-8 bytes to string */
export declare function decodeUtf8(bytes: Uint8Array): string;
/** Encode bytes to base64 string */
export declare function toBase64(bytes: Uint8Array): string;
/** Decode base64 string to bytes */
export declare function fromBase64(b64: string): Uint8Array;
/** Format a Date as Apple client time string (ISO 8601 without milliseconds) */
export declare function toAppleClientTime(date?: Date): string;
/** Detect locale string in Apple format (e.g. "en_US") */
export declare function detectLocale(): string;
/** Generate a random hex string of the given byte length */
export declare function randomHex(byteLen: number, uppercase?: boolean): string;
/** Generate a random UUID v4 (uppercase) */
export declare function randomUUID(): string;
//# sourceMappingURL=utils.d.ts.map