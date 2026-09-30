/**
 * Login API for PaxSide app.
 * 
 * POST /api/login        { appleId, password } -> { ok, session } | { ok:false, requires2FA, token, phoneNumbers }
 * POST /api/login/verify { token, code, method } -> { ok, session } | { ok:false, error }
 * 
 * Reuses the proven altsign.js login flow (SRP + 2FA) from the web frontend.
 * Anisette is fetched from public servers (tried in order).
 */

import { AppleAuth, Fetch } from "./vendor/altsign.js";

// Anisette sources to try in order
const ANISETTE_SOURCES = [
  "https://ani.sidestore.io",
  "https://ani.sidestore.app",
  "https://ani.sidestore.zip",
  "https://anisette-v3-server-42tq.onrender.com/",
];

interface AnisetteData {
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

async function fetchAnisette(): Promise<AnisetteData> {
  let lastError: Error | null = null;
  for (const url of ANISETTE_SOURCES) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
      if (!res.ok) {
        lastError = new Error(`HTTP ${res.status} from ${url}`);
        continue;
      }
      const json = await res.json() as Record<string, string>;
      // Validate required fields
      const required = ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Mme-Device-Id", "X-MMe-Client-Info"];
      const missing = required.filter(f => !json[f]);
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
        date: json["X-Apple-I-Client-Time"] ? new Date(json["X-Apple-I-Client-Time"]) : new Date(),
        locale: json["X-Apple-Locale"] || "en_US",
        timeZone: json["X-Apple-I-TimeZone"] || "UTC",
      };
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
    }
  }
  throw new Error(`All anisette sources failed. Last: ${lastError?.message}`);
}

// Token encryption for 2FA state (AES-GCM)
async function getKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", hash, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptToken(data: object, secret: string): Promise<string> {
  const key = await getKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptToken(token: string, secret: string): Promise<any> {
  const key = await getKey(secret);
  const combined = Uint8Array.from(atob(token), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// Custom error to break out of authenticate() when 2FA is needed
class TwoFactorRequired extends Error {
  state: any;
  constructor(state: any) {
    super("2FA_REQUIRED");
    this.state = state;
  }
}

export async function handleLogin(request: Request, env: any): Promise<Response> {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }
  
  try {
    const body = await request.json() as { appleId?: string; password?: string };
    const { appleId, password } = body;
    
    if (!appleId || !password) {
      return Response.json({ ok: false, error: "Missing appleId or password" }, { headers: cors });
    }
    
    const anisetteData = await fetchAnisette();
    const auth = new AppleAuth(Fetch.default());
    
    // Custom verification handler that captures 2FA state and breaks out
    const verificationHandler = async (submitCode: any, info: any) => {
      // We can't serialize submitCode, so throw with the state needed to reconstruct
      throw new TwoFactorRequired({
        appleId,
        password,
        anisetteData: {
          ...anisetteData,
          date: anisetteData.date.toISOString(),
        },
        phoneNumbers: info.phoneNumbers || [],
      });
    };
    
    try {
      const result = await auth.authenticate(appleId, password, anisetteData, verificationHandler);
      // Success (no 2FA)
      return Response.json({
        ok: true,
        session: {
          dsid: result.session.dsid,
          authToken: result.session.authToken,
          // Don't send full anisetteData, just what's needed
        },
        account: {
          dsid: result.account?.dsid,
          // Include minimal account info
        },
      }, { headers: cors });
    } catch (e) {
      if (e instanceof TwoFactorRequired) {
        const secret = env.LOGIN_TOKEN_SECRET || "default-secret-change-me";
        const token = await encryptToken(e.state, secret);
        return Response.json({
          ok: false,
          requires2FA: true,
          token,
          phoneNumbers: e.state.phoneNumbers,
        }, { headers: cors });
      }
      throw e;
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return Response.json({ ok: false, error: msg }, { headers: cors });
  }
}

export async function handleVerify(request: Request, env: any): Promise<Response> {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }
  
  try {
    const body = await request.json() as { token?: string; code?: string; method?: string };
    const { token, code, method } = body;
    
    if (!token || !code) {
      return Response.json({ ok: false, error: "Missing token or code" }, { headers: cors });
    }
    
    const secret = env.LOGIN_TOKEN_SECRET || "default-secret-change-me";
    const state = await decryptToken(token, secret);
    
    // Reconstruct anisetteData
    const anisetteData = {
      ...state.anisetteData,
      date: new Date(state.anisetteData.date),
    };
    
    const auth = new AppleAuth(Fetch.default());
    
    // For 2FA verification, we need to use the internal methods
    // The state has appleId, password - we can retry authenticate with a handler that submits the code
    const verificationHandler = async (submitCode: (code: string) => Promise<boolean>, info: any): Promise<void> => {
      // Submit the code based on method
      // For now, use the device code flow (submitCode handles it)
      await submitCode(code);
    };
    
    const result = await auth.authenticate(state.appleId, state.password, anisetteData, verificationHandler);
    
    return Response.json({
      ok: true,
      session: {
        dsid: result.session.dsid,
        authToken: result.session.authToken,
      },
    }, { headers: cors });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return Response.json({ ok: false, error: msg }, { headers: cors });
  }
}
