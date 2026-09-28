export * from './index';
export type EmscriptenModule = any;
export interface ModuleOverrides {
    [key: string]: any;
}
export declare function loadWasmModule(moduleOverrides?: ModuleOverrides): Promise<EmscriptenModule>;
export declare const loadWasm: typeof loadWasmModule;
export declare const isNodeEnvironment: () => boolean;
export declare const getWasmBinaryPath: () => string;
//# sourceMappingURL=browser.d.ts.map