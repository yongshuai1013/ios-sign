import type { AnisetteDeviceConfig, DeviceJson } from "./types.js";
export declare class Device {
    readonly uniqueDeviceIdentifier: string;
    readonly serverFriendlyDescription: string;
    readonly adiIdentifier: string;
    readonly localUserUuid: string;
    private constructor();
    /** Load from a parsed device.json object, or generate defaults if null. */
    static fromJson(json: DeviceJson | null, overrides?: Partial<AnisetteDeviceConfig>): Device;
    /** Serialize back to the device.json wire format. */
    toJson(): DeviceJson;
    static generateDefaults(): AnisetteDeviceConfig;
}
//# sourceMappingURL=device.d.ts.map