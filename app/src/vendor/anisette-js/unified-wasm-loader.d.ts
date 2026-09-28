/**
 * Unified WASM loader with automatic environment detection
 * Uses import.meta.url + protocol detection to support both Node.js and Browser
 *
 * Browser (Vite/Webpack/etc):  https://... or http://... -> anisette_rs.js + .wasm
 * Node.js:                     file://...                 -> anisette_rs.node.js + .wasm
 */
export type EmscriptenModule = any;
export interface ModuleOverrides {
    [key: string]: any;
}
/**
 * Load the Emscripten WASM module with automatic environment detection.
 *
 * This function automatically:
 * - Detects Node.js vs Browser environment via import.meta.url protocol
 * - Loads the appropriate WASM build (node or web)
 * - Configures locateFile to find the .wasm binary
 * - Initializes the module with optional overrides
 *
 * @param moduleOverrides - Optional Emscripten module configuration overrides
 * @returns Initialized Emscripten module with all exports (_malloc, _free, _anisette_* etc.)
 *
 * @example
 * ```ts
 * // Browser (Vue/React/Next.js) and Node.js - same code!
 * const module = await loadWasmModule();
 *
 * // With custom overrides
 * const module = await loadWasmModule({
 *   print: (text: string) => console.log("WASM:", text),
 *   printErr: (text: string) => console.error("WASM Error:", text),
 * });
 * ```
 */
export declare function loadWasmModule(moduleOverrides?: ModuleOverrides): Promise<EmscriptenModule>;
/**
 * Convenience function to check if running in Node.js environment.
 * Uses the same protocol detection as the loader.
 */
export declare function isNodeEnvironment(): boolean;
/**
 * Get the resolved WASM binary path (useful for debugging).
 */
export declare function getWasmBinaryPath(): string;
export { loadWasmModule as loadWasm };
//# sourceMappingURL=unified-wasm-loader.d.ts.map