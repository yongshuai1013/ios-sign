import type { WasmBridge } from "./wasm-bridge.js";
import type { Device } from "./device.js";
import type { HttpClient } from "./http.js";
export declare class ProvisioningSession {
    private bridge;
    private device;
    private http;
    private urlBag;
    constructor(bridge: WasmBridge, device: Device, http?: HttpClient);
    provision(dsid: bigint): Promise<void>;
    private loadUrlBag;
    private commonHeaders;
}
//# sourceMappingURL=provisioning.d.ts.map