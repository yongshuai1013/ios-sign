// ProvisioningSession — communicates with Apple servers to provision the device
import { fromBase64, toBase64, toAppleClientTime } from "./utils.js";
import { FetchHttpClient } from "./http.js";
const LOOKUP_URL = "https://gsa.apple.com/grandslam/GsService2/lookup";
const START_PROVISIONING_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Header</key>
  <dict/>
  <key>Request</key>
  <dict/>
</dict>
</plist>`;
export class ProvisioningSession {
    bridge;
    device;
    http;
    urlBag = {};
    constructor(bridge, device, http) {
        this.bridge = bridge;
        this.device = device;
        this.http = http ?? new FetchHttpClient();
    }
    async provision(dsid) {
        if (Object.keys(this.urlBag).length === 0) {
            await this.loadUrlBag();
        }
        const startUrl = this.urlBag["midStartProvisioning"];
        const finishUrl = this.urlBag["midFinishProvisioning"];
        if (!startUrl)
            throw new Error("url bag missing midStartProvisioning");
        if (!finishUrl)
            throw new Error("url bag missing midFinishProvisioning");
        // Step 1: get SPIM from Apple
        const startBytes = await this.http.post(startUrl, START_PROVISIONING_BODY, this.commonHeaders(true));
        const startPlist = parsePlist(startBytes);
        const spimB64 = plistGetStringInResponse(startPlist, "spim");
        const spim = fromBase64(spimB64);
        // Step 2: call WASM start_provisioning
        const { cpim, session } = this.bridge.startProvisioning(dsid, spim);
        const cpimB64 = toBase64(cpim);
        // Step 3: send CPIM to Apple, get PTM + TK
        const finishBody = buildFinishBody(cpimB64);
        const finishBytes = await this.http.post(finishUrl, finishBody, this.commonHeaders(true));
        const finishPlist = parsePlist(finishBytes);
        const ptm = fromBase64(plistGetStringInResponse(finishPlist, "ptm"));
        const tk = fromBase64(plistGetStringInResponse(finishPlist, "tk"));
        // Step 4: finalize provisioning in WASM
        this.bridge.endProvisioning(session, ptm, tk);
    }
    async loadUrlBag() {
        const bytes = await this.http.get(LOOKUP_URL, this.commonHeaders(false));
        const plist = parsePlist(bytes);
        const urls = plistGetDict(plist, "urls");
        this.urlBag = {};
        for (const [k, v] of Object.entries(urls)) {
            if (typeof v === "string")
                this.urlBag[k] = v;
        }
    }
    commonHeaders(includeTime) {
        const headers = {
            "User-Agent": "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0",
            "Content-Type": "application/x-www-form-urlencoded",
            Connection: "keep-alive",
            "X-Mme-Device-Id": this.device.uniqueDeviceIdentifier,
            "X-MMe-Client-Info": this.device.serverFriendlyDescription,
            "X-Apple-I-MD-LU": this.device.localUserUuid,
            "X-Apple-Client-App-Name": "Setup",
        };
        if (includeTime) {
            headers["X-Apple-I-Client-Time"] = toAppleClientTime();
        }
        return headers;
    }
}
function parsePlist(bytes) {
    const xml = new TextDecoder("utf-8").decode(bytes);
    return parsePlistDict(xml);
}
function parsePlistDict(xml) {
    const result = {};
    // Match <key>...</key> followed by <string>...</string> or <dict>...</dict>
    const keyRe = /<key>([^<]*)<\/key>\s*(<string>([^<]*)<\/string>|<dict>([\s\S]*?)<\/dict>)/g;
    let m;
    while ((m = keyRe.exec(xml)) !== null) {
        const key = m[1];
        if (m[3] !== undefined) {
            result[key] = m[3];
        }
        else if (m[4] !== undefined) {
            result[key] = parsePlistDict(m[4]);
        }
    }
    return result;
}
function plistGetStringInResponse(plist, key) {
    const response = plist;
    const value = response[key];
    if (typeof value !== "string") {
        throw new Error(`plist Response missing string field: ${key}`);
    }
    return value;
}
function plistGetDict(plist, key) {
    const value = plist[key];
    if (!value || typeof value === "string") {
        throw new Error(`plist missing dict field: ${key}`);
    }
    return value;
}
function buildFinishBody(cpimB64) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Header</key>
  <dict/>
  <key>Request</key>
  <dict>
    <key>cpim</key>
    <string>${cpimB64}</string>
  </dict>
</dict>
</plist>`;
}
//# sourceMappingURL=provisioning.js.map