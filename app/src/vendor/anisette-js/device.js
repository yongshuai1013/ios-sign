// Device identity management — loads or generates device.json
import { randomHex, randomUUID } from "./utils.js";
const DEFAULT_CLIENT_INFO = "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
export class Device {
    uniqueDeviceIdentifier;
    serverFriendlyDescription;
    adiIdentifier;
    localUserUuid;
    constructor(data) {
        this.uniqueDeviceIdentifier = data.UUID;
        this.serverFriendlyDescription = data.clientInfo;
        this.adiIdentifier = data.identifier;
        this.localUserUuid = data.localUUID;
    }
    /** Load from a parsed device.json object, or generate defaults if null. */
    static fromJson(json, overrides) {
        const defaults = Device.generateDefaults();
        const base = json ?? {
            UUID: defaults.uniqueDeviceId,
            clientInfo: defaults.serverFriendlyDescription,
            identifier: defaults.adiId,
            localUUID: defaults.localUserUuid,
        };
        if (overrides) {
            if (overrides.uniqueDeviceId)
                base.UUID = overrides.uniqueDeviceId;
            if (overrides.serverFriendlyDescription)
                base.clientInfo = overrides.serverFriendlyDescription;
            if (overrides.adiId)
                base.identifier = overrides.adiId;
            if (overrides.localUserUuid)
                base.localUUID = overrides.localUserUuid;
        }
        return new Device(base);
    }
    /** Serialize back to the device.json wire format. */
    toJson() {
        return {
            UUID: this.uniqueDeviceIdentifier,
            clientInfo: this.serverFriendlyDescription,
            identifier: this.adiIdentifier,
            localUUID: this.localUserUuid,
        };
    }
    static generateDefaults() {
        return {
            serverFriendlyDescription: DEFAULT_CLIENT_INFO,
            uniqueDeviceId: randomUUID(),
            adiId: randomHex(8, false),
            localUserUuid: randomHex(32, true),
        };
    }
}
//# sourceMappingURL=device.js.map