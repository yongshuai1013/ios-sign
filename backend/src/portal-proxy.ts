/**
 * Developer Portal proxy for PaxSide app.
 *
 * POST /api/portal/
 * Body: { dsid, authToken, method, path, query, bodyB64, contentType }
 * Response: { ok, status, bodyB64, contentType } | { ok: false, error }
 *
 * Fetches fresh anisette server-side (PaxSide's local anisette is broken:
 * WASM stuck, AnisetteKit crashes on A10), then makes the Developer Portal
 * API call to Apple with the session + fresh anisette.
 */

// Anisette sources to try in order (same as login-api.ts used)
const ANISETTE_SOURCES = [
  "https://ani.sidestore.io",
  "https://ani.sidestore.app",
  "https://ani.sidestore.zip",
  "https://anisette-v3-server-42tq.onrender.com/",
];

export interface PortalAnisetteData {
  machineID: string;
  oneTimePassword: string;
  localUserID: string;
  routingInfo: number;
  deviceUniqueIdentifier: string;
  deviceDescription: string;
  deviceSerialNumber: string;
  date: Date;
  locale: string;
  timeZone: string;
}

async function fetchAnisette(): Promise<PortalAnisetteData> {
  let lastError: Error | null = null;
  for (const url of ANISETTE_SOURCES) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
      if (!res.ok) {
        lastError = new Error(`HTTP ${res.status} from ${url}`);
        continue;
      }
      const json = (await res.json()) as Record<string, string>;
      const required = [
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-LU",
        "X-Mme-Device-Id",
        "X-MMe-Client-Info",
      ];
      const missing = required.filter((f) => !json[f]);
      if (missing.length > 0) {
        lastError = new Error(`Missing fields ${missing.join(",")} from ${url}`);
        continue;
      }
      return {
        machineID: json["X-Apple-I-MD-M"],
        oneTimePassword: json["X-Apple-I-MD"],
        localUserID: json["X-Apple-I-MD-LU"],
        routingInfo: parseInt(json["X-Apple-I-MD-RINFO"] || "0", 10),
        deviceUniqueIdentifier: json["X-Mme-Device-Id"],
        deviceDescription: json["X-MMe-Client-Info"],
        deviceSerialNumber: json["X-Apple-I-SRL-NO"] || "0",
        date: json["X-Apple-I-Client-Time"]
          ? new Date(json["X-Apple-I-Client-Time"])
          : new Date(),
        locale: json["X-Apple-Locale"] || "en_US",
        timeZone: json["X-Apple-I-TimeZone"] || "UTC",
      };
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
    }
  }
  throw new Error(`All anisette sources failed. Last: ${lastError?.message}`);
}

function json(status: number, data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function handlePortalProxy(request: Request): Promise<Response> {
  if (request.method !== "POST") {
    return json(405, { ok: false, error: "method not allowed" });
  }
  try {
    const req = (await request.json()) as {
      dsid: string;
      authToken: string;
      method: string;
      path: string;
      query?: string;
      bodyB64?: string;
      contentType?: string;
      anisette?: Record<string, string>;
    };
    if (!req.dsid || !req.authToken || !req.method || !req.path) {
      return json(400, { ok: false, error: "missing dsid/authToken/method/path" });
    }
    // 只允許 Developer Portal 路徑
    if (!req.path.startsWith("/services/")) {
      return json(403, { ok: false, error: "path not allowed" });
    }
    const target = new URL(
      "https://developerservices2.apple.com" + req.path + (req.query || "")
    );
    const headers = new Headers();
    headers.set("Content-Type", req.contentType || "text/x-xml-plist");
    headers.set("Accept", "text/x-xml-plist");
    headers.set("Accept-Language", "en-us");
    // 跟網站 /apple-proxy/ 的 isDevApi 一致：模仿 akd，不是 Xcode
    headers.set("X-Mme-Client-Info", "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>");
    headers.set("User-Agent", "akd/1.0 CFNetwork/808.1.4");
    headers.set("X-Xcode-Version", "27.0 (27A5218g)");
    headers.set("X-Apple-App-Info", "com.apple.gs.xcode.auth");
    headers.set("X-Apple-I-Identity-Id", req.dsid);
    headers.set("X-Apple-GS-Token", req.authToken);
    // 直接取新鮮 anisette（QR 的已過期，不用）
    const anisette = await fetchAnisette();
    headers.set("X-Apple-I-MD-M", anisette.machineID);
    headers.set("X-Apple-I-MD", anisette.oneTimePassword);
    headers.set("X-Apple-I-MD-LU", anisette.localUserID);
    headers.set("X-Apple-I-MD-RINFO", String(anisette.routingInfo));
    headers.set("X-Mme-Device-Id", anisette.deviceUniqueIdentifier);
    headers.set("X-MMe-Client-Info", anisette.deviceDescription);
    headers.set("X-Apple-I-Client-Time", anisette.date.toISOString());
    headers.set("X-Apple-Locale", anisette.locale);
    headers.set("X-Apple-I-Locale", anisette.locale);
    headers.set("X-Apple-I-TimeZone", anisette.timeZone);

    let body: BodyInit | undefined;
    if (req.bodyB64) {
      const bin = Uint8Array.from(atob(req.bodyB64), (c) => c.charCodeAt(0));
      body = bin;
    }
    const resp = await fetch(target.toString(), {
      method: req.method,
      headers,
      body,
    });
    const respBuf = new Uint8Array(await resp.arrayBuffer());
    let respB64 = "";
    const CHUNK = 8192;
    for (let i = 0; i < respBuf.length; i += CHUNK) {
      respB64 += String.fromCharCode(...respBuf.subarray(i, i + CHUNK));
    }
    respB64 = btoa(respB64);
    return json(200, {
      ok: true,
      status: resp.status,
      bodyB64: respB64,
      contentType: resp.headers.get("content-type") || "",
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return json(500, { ok: false, error: `portal proxy failed: ${msg}` });
  }
}
