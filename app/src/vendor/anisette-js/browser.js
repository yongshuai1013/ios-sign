//@ts-expect-error no types for the Emscripten module factory
import ModuleFactory from "./anisette_rs.js";
export * from './index';
const wasmUrl = new URL("./anisette_rs.wasm", import.meta.url).href;
export async function loadWasmModule(moduleOverrides = {}) {
    return ModuleFactory({
        ...moduleOverrides,
        locateFile: (filename) => {
            if (filename.endsWith(".wasm"))
                return wasmUrl;
            return filename;
        },
    });
}
export const loadWasm = loadWasmModule;
export const isNodeEnvironment = () => false;
export const getWasmBinaryPath = () => wasmUrl;
//# sourceMappingURL=browser.js.map