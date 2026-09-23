// src/apple/srp/bigint.ts
function fromHex(s) {
  return BigInt("0x" + s.replace(/\s+/g, ""));
}
function fromBuffer(buf) {
  let hex = "";
  for (let i = 0;i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, "0");
  }
  return hex.length ? BigInt("0x" + hex) : 0n;
}
function toBuffer(n) {
  if (n === 0n)
    return new Uint8Array([0]);
  let hex = n.toString(16);
  if (hex.length % 2)
    hex = "0" + hex;
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0;i < buf.length; i++) {
    buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}
function padTo(buf, len) {
  if (buf.length > len)
    throw new Error("Negative padding");
  if (buf.length === len)
    return buf;
  const result = new Uint8Array(len);
  result.set(buf, len - buf.length);
  return result;
}
function powmod(base, exp, mod) {
  base = (base % mod + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n)
      result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

// src/apple/srp/params.ts
function hex(s) {
  return fromHex(s);
}
var params = {
  1024: {
    N_length_bits: 1024,
    N: hex("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C" + "9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4" + "8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29" + "7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A" + "FD5138FE 8376435B 9FC61D2F C0EB06E3"),
    g: 2n,
    hash: "sha1"
  },
  1536: {
    N_length_bits: 1536,
    N: hex("9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961" + "4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843" + "80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B" + "E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5" + "6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A" + "F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E" + "8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB"),
    g: 2n,
    hash: "sha1"
  },
  2048: {
    N_length_bits: 2048,
    N: hex("AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294" + "3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D" + "CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB" + "D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74" + "7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A" + "436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D" + "5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73" + "03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6" + "94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F" + "9E4AFF73"),
    g: 2n,
    hash: "sha256"
  },
  4096: {
    N_length_bits: 4096,
    N: hex("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08" + "8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B" + "302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9" + "A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6" + "49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8" + "FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" + "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C" + "180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718" + "3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D" + "04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D" + "B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226" + "1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C" + "BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC" + "E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26" + "99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB" + "04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2" + "233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127" + "D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199" + "FFFFFFFF FFFFFFFF"),
    g: 5n,
    hash: "sha256"
  }
};
var params_default = params;

// src/apple/srp/srp.ts
function hashName(hash) {
  if (hash === "sha1")
    return "SHA-1";
  if (hash === "sha256")
    return "SHA-256";
  if (hash === "sha512")
    return "SHA-512";
  throw new Error("unknown hash: " + hash);
}
async function digest(hash, ...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest(hashName(hash), buf));
}
function padToN(n, params2) {
  return padTo(toBuffer(n), params2.N_length_bits / 8);
}
function assertIsBytes(arg, name) {
  if (!(arg instanceof Uint8Array))
    throw new TypeError(name + " must be a Uint8Array");
}
function assertIsNBytes(arg, params2, name) {
  assertIsBytes(arg, name);
  const expected = params2.N_length_bits / 8;
  if (arg.length !== expected)
    throw new Error(name + " was " + arg.length + ", expected " + expected);
}
function equal(a, b) {
  if (a.length !== b.length)
    return false;
  let mismatch = 0;
  for (let i = 0;i < a.length; i++)
    mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}
async function getx(params2, salt, I, P) {
  const colon = new TextEncoder().encode(":");
  const hashIP = await digest(params2.hash, I, colon, P);
  const hashX = await digest(params2.hash, salt, hashIP);
  return fromBuffer(hashX);
}
async function getk(params2) {
  const k_buf = await digest(params2.hash, padToN(params2.N, params2), padToN(params2.g, params2));
  return fromBuffer(k_buf);
}
async function getu(params2, A, B) {
  assertIsNBytes(A, params2, "A");
  assertIsNBytes(B, params2, "B");
  return fromBuffer(await digest(params2.hash, A, B));
}
async function getK(params2, S) {
  assertIsNBytes(S, params2, "S");
  return digest(params2.hash, S);
}
async function getM1(params2, I, salt, A, B, K) {
  assertIsNBytes(A, params2, "A");
  assertIsNBytes(B, params2, "B");
  const hN = await digest(params2.hash, padToN(params2.N, params2));
  const hg = await digest(params2.hash, padToN(params2.g, params2));
  const hnxorhg = new Uint8Array(hN.length);
  for (let i = 0;i < hN.length; i++) {
    hnxorhg[i] = hN[i] ^ hg[i];
  }
  const hI = await digest(params2.hash, I);
  return digest(params2.hash, hnxorhg, hI, salt, A, B, K);
}
async function getM2(params2, A, M, K) {
  return digest(params2.hash, A, M, K);
}
class Client {
  params;
  I;
  salt;
  k;
  x;
  a;
  A_buf;
  K_buf;
  M1_buf;
  M2_buf;
  constructor(params2) {
    this.params = params2;
  }
  static async create(params2, salt, I, P, secret1, noUsernameInX = false) {
    assertIsBytes(salt, "salt");
    assertIsBytes(I, "identity");
    assertIsBytes(P, "password");
    assertIsBytes(secret1, "secret1");
    const c = new Client(params2);
    c.I = I;
    c.salt = salt;
    c.k = await getk(params2);
    if (noUsernameInX) {
      c.x = await getx(params2, salt, new Uint8Array(0), P);
    } else {
      c.x = await getx(params2, salt, I, P);
    }
    c.a = fromBuffer(secret1);
    c.A_buf = padToN(powmod(params2.g, c.a, params2.N), params2);
    return c;
  }
  computeA() {
    return this.A_buf;
  }
  async setB(B_buf) {
    assertIsNBytes(B_buf, this.params, "B");
    const B = fromBuffer(B_buf);
    if (B <= 0n || B >= this.params.N)
      throw new Error("invalid server-supplied 'B', must be 1..N-1");
    const u = await getu(this.params, this.A_buf, B_buf);
    const { g, N } = this.params;
    const base = ((B - this.k * powmod(g, this.x, N)) % N + N) % N;
    const S_buf = padToN(powmod(base, this.a + u * this.x, N), this.params);
    this.K_buf = await getK(this.params, S_buf);
    this.M1_buf = await getM1(this.params, this.I, this.salt, this.A_buf, B_buf, this.K_buf);
    this.M2_buf = await getM2(this.params, this.A_buf, this.M1_buf, this.K_buf);
  }
  computeM1() {
    if (!this.M1_buf)
      throw new Error("incomplete protocol");
    return this.M1_buf;
  }
  checkM2(serverM2) {
    if (!equal(this.M2_buf, serverM2))
      throw new Error("server is not authentic");
  }
  computeK() {
    if (!this.K_buf)
      throw new Error("incomplete protocol");
    return this.K_buf;
  }
}

// src/utils.ts
function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0;i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i]);
  }
  return btoa(s);
}
function base64ToBytes(text) {
  const clean = (text || "").trim();
  if (!clean)
    return new Uint8Array;
  const s = atob(clean);
  const out = new Uint8Array(s.length);
  for (let i = 0;i < s.length; i++) {
    out[i] = s.charCodeAt(i);
  }
  return out;
}
function parsePlist(xmlText) {
  let pos = 0;
  const src = xmlText;
  function skipWS() {
    while (pos < src.length && /\s/.test(src[pos]))
      pos++;
  }
  function skipProlog() {
    while (pos < src.length) {
      skipWS();
      if (src.startsWith("<?", pos)) {
        pos = src.indexOf("?>", pos) + 2;
      } else if (src.startsWith("<!", pos)) {
        pos = src.indexOf(">", pos) + 1;
      } else {
        break;
      }
    }
  }
  function readTag() {
    skipWS();
    if (pos >= src.length || src[pos] !== "<")
      return null;
    const closing = src[pos + 1] === "/";
    const start = closing ? pos + 2 : pos + 1;
    const end = src.indexOf(">", pos);
    if (end < 0)
      return null;
    const selfClosing = src[end - 1] === "/";
    const nameEnd = selfClosing ? end - 1 : end;
    const name = src.slice(start, nameEnd).split(/\s/)[0].trim();
    pos = end + 1;
    return { name, closing, selfClosing };
  }
  function readTextUntilClose(tag) {
    const close = `</${tag}>`;
    const idx = src.indexOf(close, pos);
    if (idx < 0)
      return "";
    const text = src.slice(pos, idx);
    pos = idx + close.length;
    return text;
  }
  function parseValue() {
    skipWS();
    const tag = readTag();
    if (!tag || tag.closing)
      return null;
    if (tag.name === "dict")
      return parseDict();
    if (tag.name === "array")
      return parseArray();
    if (tag.name === "true")
      return true;
    if (tag.name === "false")
      return false;
    if (tag.selfClosing && (tag.name === "string" || tag.name === "data"))
      return "";
    const text = readTextUntilClose(tag.name);
    if (tag.name === "string")
      return text;
    if (tag.name === "integer")
      return parseInt(text, 10);
    if (tag.name === "real")
      return parseFloat(text);
    if (tag.name === "data")
      return text.replace(/\s/g, "");
    return text;
  }
  function parseDict() {
    const result = {};
    while (pos < src.length) {
      skipWS();
      if (src.startsWith("</dict>", pos)) {
        pos += 7;
        break;
      }
      const keyTag = readTag();
      if (!keyTag || keyTag.name !== "key")
        break;
      const key = readTextUntilClose("key");
      result[key] = parseValue();
    }
    return result;
  }
  function parseArray() {
    const result = [];
    while (pos < src.length) {
      skipWS();
      if (src.startsWith("</array>", pos)) {
        pos += 8;
        break;
      }
      result.push(parseValue());
    }
    return result;
  }
  skipProlog();
  const rootPos = pos;
  const rootTag = readTag();
  if (!rootTag)
    return null;
  if (rootTag.name === "plist") {
    return parseValue();
  }
  pos = rootPos;
  return parseValue();
}

// src/apple/auth.ts
var PROTOCOL_VERSION = "QH65B2";
var CLIENT_ID = "XABBG36SBA";
function encodePlist(obj) {
  function encodeValue(v) {
    if (v === null || v === undefined)
      return "<string></string>";
    if (typeof v === "string")
      return `<string>${escapeXml(v)}</string>`;
    if (typeof v === "number")
      return `<integer>${v}</integer>`;
    if (typeof v === "boolean")
      return v ? "<true/>" : "<false/>";
    if (v instanceof Uint8Array) {
      const base64 = btoa(String.fromCharCode(...v));
      return `<data>${base64}</data>`;
    }
    if (Array.isArray(v)) {
      return `<array>${v.map(encodeValue).join("")}</array>`;
    }
    if (typeof v === "object") {
      const dict = v;
      const entries = Object.entries(dict).map(([k, val]) => `<key>${escapeXml(k)}</key>${encodeValue(val)}`).join("");
      return `<dict>${entries}</dict>`;
    }
    return "<string></string>";
  }
  function escapeXml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${encodeValue(obj)}
</plist>`;
}
async function pbkdf2(password, salt, iterations, keyLen) {
  const keyMaterial = await crypto.subtle.importKey("raw", password.buffer, { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: salt.buffer,
    iterations,
    hash: "SHA-256"
  }, keyMaterial, keyLen * 8);
  return new Uint8Array(bits);
}
async function derivePasswordKey(password, salt, iterations, isS2K) {
  const passwordData = new TextEncoder().encode(password);
  const passwordHash = await crypto.subtle.digest("SHA-256", passwordData);
  const hashBytes = new Uint8Array(passwordHash);
  let digest2;
  if (isS2K) {
    digest2 = hashBytes;
  } else {
    const hexChars = "0123456789abcdef";
    const hexBytes = new Uint8Array(hashBytes.length * 2);
    for (let i = 0;i < hashBytes.length; i++) {
      const byte = hashBytes[i];
      hexBytes[i * 2] = hexChars.charCodeAt(byte >> 4 & 15);
      hexBytes[i * 2 + 1] = hexChars.charCodeAt(byte & 15);
    }
    digest2 = hexBytes;
  }
  return pbkdf2(digest2, salt, iterations, 32);
}
async function createSessionKey(sessionKey, keyName) {
  const keyData = new TextEncoder().encode(keyName);
  const hmacKey = await crypto.subtle.importKey("raw", sessionKey.buffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", hmacKey, keyData.buffer);
  return new Uint8Array(signature);
}
function removePKCS7Padding(data) {
  if (data.length === 0)
    return data;
  const padLen = data[data.length - 1];
  if (padLen > data.length || padLen === 0 || padLen > 16)
    return data;
  for (let i = 0;i < padLen; i++) {
    if (data[data.length - 1 - i] !== padLen)
      return data;
  }
  return data.slice(0, data.length - padLen);
}
async function decryptCBC(data, key, iv) {
  const cryptoKey = await crypto.subtle.importKey("raw", key.buffer, { name: "AES-CBC" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv.slice(0, 16).buffer }, cryptoKey, data.buffer);
  return removePKCS7Padding(new Uint8Array(decrypted));
}
async function decryptGCM(data, key) {
  if (data.length < 35)
    return null;
  if (data[0] !== 88 || data[1] !== 89 || data[2] !== 90) {
    return null;
  }
  const magic = data.slice(0, 3);
  const iv = data.slice(3, 19);
  const ciphertext = data.slice(19, data.length - 16);
  const tag = data.slice(data.length - 16);
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", key.buffer, { name: "AES-GCM" }, false, ["decrypt"]);
    const combined = new Uint8Array([...ciphertext, ...tag]);
    const decrypted = await crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: iv.buffer,
      additionalData: magic.buffer,
      tagLength: 128
    }, cryptoKey, combined.buffer);
    return new Uint8Array(decrypted);
  } catch {
    return null;
  }
}
async function createAppTokensChecksum(sk, adsid, apps) {
  const hmacKey = await crypto.subtle.importKey("raw", sk.buffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const encoder = new TextEncoder;
  const parts = [encoder.encode("apptokens"), encoder.encode(adsid)];
  for (const app of apps) {
    parts.push(encoder.encode(app));
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    combined.set(p, offset);
    offset += p.length;
  }
  const checksum = await crypto.subtle.sign("HMAC", hmacKey, combined.buffer);
  return new Uint8Array(checksum);
}

class AppleAuth {
  fetch;
  baseURL;
  constructor(fetch) {
    this.fetch = fetch;
    this.baseURL = "https://developerservices2.apple.com/services/QH65B2/";
  }
  async authenticate(appleID, password, anisetteData, verificationHandler, options) {
    const refreshAnisette = options?.refreshAnisette;
    const clientDictionary = {
      bootstrap: true,
      icscrec: true,
      loc: anisetteData.locale,
      pbe: false,
      prkgen: true,
      svct: "iCloud",
      "X-Apple-I-Client-Time": this.formatDate(anisetteData.date),
      "X-Apple-Locale": anisetteData.locale,
      "X-Apple-I-TimeZone": anisetteData.timeZone,
      "X-Apple-I-MD": anisetteData.oneTimePassword,
      "X-Apple-I-MD-LU": anisetteData.localUserID,
      "X-Apple-I-MD-M": anisetteData.machineID,
      "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
      "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
      "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber
    };
    const srpParams = params_default[2048];
    const secret1 = crypto.getRandomValues(new Uint8Array(32));
    const client = await Client.create(srpParams, new Uint8Array(0), new TextEncoder().encode(appleID), new TextEncoder().encode(""), secret1, true);
    const A = client.computeA();
    const initParams = {
      A2k: A,
      ps: ["s2k", "s2k_fo"],
      cpd: clientDictionary,
      u: appleID,
      o: "init"
    };
    const initResponse = await this.sendAuthRequest(initParams, anisetteData);
    const sp = initResponse["sp"];
    const isS2K = sp === "s2k";
    const c = initResponse["c"];
    const saltBase64 = initResponse["s"];
    const iterations = initResponse["i"];
    const BBase64 = initResponse["B"];
    if (!c || !saltBase64 || !iterations || !BBase64) {
      throw new Error("Invalid server response: missing challenge parameters");
    }
    const salt = Uint8Array.from(atob(saltBase64), (c3) => c3.charCodeAt(0));
    const B = Uint8Array.from(atob(BBase64), (c3) => c3.charCodeAt(0));
    const passwordKey = await derivePasswordKey(password, salt, iterations, isS2K);
    const clientWithChallenge = await Client.create(srpParams, salt, new TextEncoder().encode(appleID), passwordKey, secret1, true);
    await clientWithChallenge.setB(B);
    const M1 = clientWithChallenge.computeM1();
    const completeParams = {
      c,
      M1,
      cpd: clientDictionary,
      u: appleID,
      o: "complete"
    };
    const completeResponse = await this.sendAuthRequest(completeParams, anisetteData);
    const M2Base64 = completeResponse["M2"];
    if (!M2Base64) {
      throw new Error("Invalid server response: missing M2");
    }
    const M2 = Uint8Array.from(atob(M2Base64), (c3) => c3.charCodeAt(0));
    clientWithChallenge.checkM2(M2);
    const sessionKey = clientWithChallenge.computeK();
    const spdBase64 = completeResponse["spd"];
    if (!spdBase64) {
      throw new Error("Invalid server response: missing spd");
    }
    const spd = Uint8Array.from(atob(spdBase64), (c3) => c3.charCodeAt(0));
    const extraDataKey = await createSessionKey(sessionKey, "extra data key:");
    const extraDataIV = await createSessionKey(sessionKey, "extra data iv:");
    const decryptedData = await decryptCBC(spd, extraDataKey, extraDataIV);
    const decryptedText = new TextDecoder().decode(decryptedData);
    const decryptedPlist = parsePlist(decryptedText);
    if (!decryptedPlist) {
      const magic = Array.from(decryptedData.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join("");
      throw new Error(`Failed to parse decrypted spd plist (magic=${magic})`);
    }
    const adsid = decryptedPlist["adsid"];
    const idmsToken = decryptedPlist["GsIdmsToken"];
    if (!adsid || !idmsToken) {
      throw new Error("Invalid server response: missing adsid or idmsToken");
    }
    const status = completeResponse["Status"];
    const authType = status?.["au"];
    // Log the auth type for debugging (helps identify non-standard 2FA flows)
    if (authType && authType !== "trustedDeviceSecondaryAuth") {
      console.log(`[altsign] 2FA required with authType: ${authType} (not trustedDeviceSecondaryAuth)`);
    }
    if (authType === "trustedDeviceSecondaryAuth" || (authType && authType.toLowerCase().includes("secondaryauth"))) {
      if (!verificationHandler) {
        throw new Error("Two-factor authentication required but no verification handler provided");
      }
      const success = await this.handleTwoFactor(adsid, idmsToken, anisetteData, verificationHandler, refreshAnisette);
      if (success) {
        return this.authenticate(appleID, password, anisetteData, verificationHandler);
      } else {
        throw new Error("Two-factor authentication failed");
      }
    }
    const skBase64 = decryptedPlist["sk"];
    const c2Base64 = decryptedPlist["c"];
    if (!skBase64 || !c2Base64) {
      throw new Error("Invalid server response: missing sk or c");
    }
    const sk = Uint8Array.from(atob(skBase64), (c3) => c3.charCodeAt(0));
    const c2 = Uint8Array.from(atob(c2Base64), (c3) => c3.charCodeAt(0));
    const authToken = await this.fetchAuthToken(adsid, idmsToken, c2, sk, clientDictionary, anisetteData);
    const session = {
      dsid: adsid,
      authToken,
      anisetteData
    };
    const account = await this.fetchAccount(session);
    return { account, session };
  }
  async handleTwoFactor(dsid, idmsToken, anisetteData, verificationHandler, refreshAnisette) {
    try {
      const identityToken = `${dsid}:${idmsToken}`;
      const encodedToken = btoa(identityToken);
      // Refresh anisette before triggering 2FA push (isideload does this;
      // OTP may be single-use or short-lived, reusing the login OTP fails).
      let freshData = anisetteData;
      if (refreshAnisette) {
        try {
          freshData = await refreshAnisette();
        } catch {
          // Fall back to original anisetteData if refresh fails
        }
      }
      const buildHeaders = (data) => ({
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        Accept: "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Apple-Identity-Token": encodedToken,
        "X-Apple-I-MD-M": data.machineID,
        "X-Apple-I-MD": data.oneTimePassword,
        "X-Apple-I-MD-LU": data.localUserID,
        "X-Apple-I-MD-RINFO": String(data.routingInfo),
        "X-Mme-Device-Id": data.deviceUniqueIdentifier,
        "X-MMe-Client-Info": data.deviceDescription,
        "X-Apple-I-Client-Time": this.formatDate(data.date),
        "X-Apple-Locale": data.locale,
        "X-Apple-I-TimeZone": data.timeZone
      });
      const headers = buildHeaders(freshData);
      // NOTE (2026-09-23): Do NOT auto-trigger the trusteddevice push here.
      // The UI now lets the user choose device vs SMS first; the push is
      // triggered on demand via triggerDevicePush() below. Auto-triggering
      // caused Apple to send both a device push AND auto-fallback SMS,
      // confusing users with two different codes.
      const triggerDevicePush = async () => {
        let pushData = freshData;
        if (refreshAnisette) {
          try {
            pushData = await refreshAnisette();
          } catch {
            // Fall back to freshData if refresh fails
          }
        }
        await this.fetch.get("https://gsa.apple.com/auth/verify/trusteddevice", buildHeaders(pushData));
      };
      // Fetch trusted phone numbers for SMS 2FA (isideload does this so the
      // UI can offer SMS as a fallback). Non-fatal if it fails.
      let phoneNumbers = [];
      try {
        phoneNumbers = await this.fetchTrustedPhoneNumbers(dsid, idmsToken, freshData);
      } catch {
        // SMS option will be hidden if we can't get the numbers
      }
      return await new Promise((resolve) => {
        const submitCode = async (code) => {
          try {
            if (!code || !code.trim()) {
              resolve(false);
              return;
            }
            // Refresh anisette again before validating (isideload does this)
            let validateData = freshData;
            if (refreshAnisette) {
              try {
                validateData = await refreshAnisette();
              } catch {
                // Fall back to freshData if refresh fails
              }
            }
            const verifyHeaders = { ...buildHeaders(validateData), "security-code": code.trim() };
            const resp = await this.fetch.get("https://gsa.apple.com/grandslam/GsService2/validate", verifyHeaders);
            const text = await resp.text();
            const plist = parsePlist(text);
            const errorCode = plist["ec"];
            resolve(errorCode === 0);
          } catch {
            resolve(false);
          }
        };
        const requestSms = async (phoneId) => {
          let smsData = freshData;
          if (refreshAnisette) {
            try {
              smsData = await refreshAnisette();
            } catch {
              // Fall back to freshData if refresh fails
            }
          }
          await this.requestSmsCode(dsid, idmsToken, smsData, phoneId);
        };
        const submitSmsCode = async (phoneId, code) => {
          let smsData = freshData;
          if (refreshAnisette) {
            try {
              smsData = await refreshAnisette();
            } catch {
              // Fall back to freshData if refresh fails
            }
          }
          const ok = await this.submitSmsCode(dsid, idmsToken, smsData, phoneId, code);
          resolve(ok);
        };
        try {
          verificationHandler(submitCode, {
            trustedPhoneNumbers: phoneNumbers,
            requestSms,
            submitSmsCode,
            triggerDevicePush,
          });
        } catch {
          resolve(false);
        }
      });
    } catch {
      return false;
    }
  }
  /**
   * SMS 2FA support (from isideload's apple_account.rs).
   * Three endpoints, all JSON (unlike the trusted-device plist flow):
   *   GET  /auth                        -> trusted phone numbers
   *   PUT  /auth/verify/phone           -> send SMS code
   *   POST /auth/verify/phone/securitycode -> submit SMS code
   * Uses the same 2FA headers as the trusted-device flow.
   */
  buildSmsHeaders(dsid, idmsToken, anisetteData) {
    const identityToken = `${dsid}:${idmsToken}`;
    const encodedToken = btoa(identityToken);
    return {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "User-Agent": "Xcode",
      "Accept-Language": "en-us",
      "X-Apple-App-Info": "com.apple.gs.xcode.auth",
      "X-Xcode-Version": "11.2 (11B41)",
      "X-Apple-Identity-Token": encodedToken,
      "X-Apple-I-MD-M": anisetteData.machineID,
      "X-Apple-I-MD": anisetteData.oneTimePassword,
      "X-Apple-I-MD-LU": anisetteData.localUserID,
      "X-Apple-I-MD-RINFO": String(anisetteData.routingInfo),
      "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
      "X-MMe-Client-Info": anisetteData.deviceDescription,
      "X-Apple-I-Client-Time": this.formatDate(anisetteData.date),
      "X-Apple-Locale": anisetteData.locale,
      "X-Apple-I-TimeZone": anisetteData.timeZone
    };
  }
  async fetchTrustedPhoneNumbers(dsid, idmsToken, anisetteData) {
    const headers = this.buildSmsHeaders(dsid, idmsToken, anisetteData);
    const resp = await this.fetch.get("https://gsa.apple.com/auth", headers);
    const text = await resp.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Failed to fetch trusted phone numbers (HTTP ${resp.status})`);
    }
    const numbers = data.trustedPhoneNumbers || [];
    return numbers.map((n) => ({
      id: n.id,
      numberWithDialCode: n.numberWithDialCode || "",
      // isideload uses lastTwoDigits; our UI shows an obfuscated number.
      obfuscatedNumber: n.lastTwoDigits ? `••••${n.lastTwoDigits}` : (n.numberWithDialCode || ""),
      pushMode: n.pushMode || ""
    }));
  }
  async requestSmsCode(dsid, idmsToken, anisetteData, phoneId) {
    const headers = this.buildSmsHeaders(dsid, idmsToken, anisetteData);
    const body = JSON.stringify({ phoneNumber: { id: phoneId }, mode: "sms" });
    const resp = await this.fetch.put("https://gsa.apple.com/auth/verify/phone", body, headers);
    // HTTP 412 means there's already an active SMS challenge; treat as success
    // and let the user enter the code they received (isideload PR #9).
    if (resp.status === 412) {
      return;
    }
    // HTTP 423/429: Apple is rate-limiting SMS sends. The user may already
    // have a valid code from a previous send, so let them enter it instead
    // of blocking on the send failure.
    if (resp.status === 423 || resp.status === 429) {
      return;
    }
    const text = await resp.text();
    if (!resp.ok) {
      let errCode;
      try {
        errCode = JSON.parse(text).errorCode;
      } catch {
        // ignore parse errors
      }
      if (errCode === -28248) {
        throw new Error("This phone number cannot receive verification codes right now. Try another method.");
      }
      if (errCode === -22979 || errCode === -22981) {
        // Rate limited; keep the selected number and let the user enter a code.
        return;
      }
      throw new Error(`Failed to send SMS (HTTP ${resp.status})`);
    }
  }
  async submitSmsCode(dsid, idmsToken, anisetteData, phoneId, code) {
    const headers = this.buildSmsHeaders(dsid, idmsToken, anisetteData);
    const body = JSON.stringify({
      securityCode: { code: code.trim() },
      phoneNumber: { id: phoneId },
      mode: "sms"
    });
    const resp = await this.fetch.post("https://gsa.apple.com/auth/verify/phone/securitycode", body, headers);
    const text = await resp.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Invalid server response (HTTP ${resp.status})`);
    }
    const errorCode = data.errorCode;
    if (errorCode === 0 || errorCode === undefined) {
      return true;
    }
    if (errorCode === -21669) {
      throw new Error("Incorrect verification code. Please try again.");
    }
    throw new Error(`SMS verification failed (error ${errorCode})`);
  }
  async fetchAuthToken(adsid, idmsToken, c, sk, clientDictionary, anisetteData) {
    const apps = ["com.apple.gs.xcode.auth"];
    const checksum = await createAppTokensChecksum(sk, adsid, apps);
    const params2 = {
      u: adsid,
      app: apps,
      c,
      t: idmsToken,
      checksum,
      cpd: clientDictionary,
      o: "apptokens"
    };
    const response = await this.sendAuthRequest(params2, anisetteData);
    const encryptedTokenBase64 = response["et"];
    const encryptedToken = Uint8Array.from(atob(encryptedTokenBase64), (c2) => c2.charCodeAt(0));
    const decryptedToken = await decryptGCM(encryptedToken, sk);
    if (!decryptedToken) {
      throw new Error("Failed to decrypt auth token");
    }
    const tokenPlistText = new TextDecoder().decode(decryptedToken);
    const tokenPlist = parsePlist(tokenPlistText);
    const tokenDict = tokenPlist["t"];
    const token = tokenDict["com.apple.gs.xcode.auth"]?.["token"];
    if (!token) {
      throw new Error("Failed to extract auth token");
    }
    return token;
  }
  async fetchAccount(session) {
    const headers = this.buildHeaders(session);
    const body = this.buildRequestBody({});
    const resp = await this.fetch.post(`${this.baseURL}viewDeveloper.action?clientId=${CLIENT_ID}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const developer = plist["developer"];
    if (!developer) {
      throw new Error("Failed to fetch account info");
    }
    return {
      identifier: developer["developerId"],
      name: developer["name"],
      email: developer["email"]
    };
  }
  async sendAuthRequest(params2, anisetteData) {
    const requestDict = {
      Header: { Version: "1.0.1" },
      Request: params2
    };
    const body = encodePlist(requestDict);
    const headers = {
      "Content-Type": "text/x-xml-plist",
      "X-MMe-Client-Info": anisetteData.deviceDescription,
      Accept: "*/*",
      "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
    };
    const resp = await this.fetch.post("https://gsa.apple.com/grandslam/GsService2", body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const response = plist["Response"];
    const status = response?.["Status"];
    if (status) {
      const errorCode = status["ec"];
      if (errorCode && errorCode !== 0) {
        const errorMsg = status["em"];
        const operation = params2["o"];
        const operationSuffix = operation ? ` during ${operation}` : "";
        throw new Error(`Authentication failed${operationSuffix}: ${errorMsg} (${errorCode})`);
      }
    }
    return response || {};
  }
  buildHeaders(session) {
    const anisette = session.anisetteData;
    return {
      "Content-Type": "text/x-xml-plist",
      "User-Agent": "Xcode",
      Accept: "text/x-xml-plist",
      "Accept-Language": "en-us",
      "X-Apple-App-Info": "com.apple.gs.xcode.auth",
      "X-Xcode-Version": "11.2 (11B41)",
      "X-Apple-I-Identity-Id": session.dsid,
      "X-Apple-GS-Token": session.authToken,
      "X-Apple-I-MD-M": anisette.machineID,
      "X-Apple-I-MD": anisette.oneTimePassword,
      "X-Apple-I-MD-LU": anisette.localUserID,
      "X-Apple-I-MD-RINFO": String(anisette.routingInfo),
      "X-Mme-Device-Id": anisette.deviceUniqueIdentifier,
      "X-MMe-Client-Info": anisette.deviceDescription,
      "X-Apple-I-Client-Time": this.formatDate(anisette.date),
      "X-Apple-Locale": anisette.locale,
      "X-Apple-I-TimeZone": anisette.timeZone
    };
  }
  buildRequestBody(additionalParams) {
    const params2 = {
      clientId: CLIENT_ID,
      protocolVersion: PROTOCOL_VERSION,
      requestId: crypto.randomUUID().toUpperCase(),
      ...additionalParams
    };
    return encodePlist(params2);
  }
  formatDate(date) {
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
  }
}

// src/fetch.ts
class Fetch {
  requestFn;
  initFn;
  initialized = false;
  constructor(initFn, requestFn) {
    this.initFn = initFn;
    this.requestFn = requestFn;
  }
  async init() {
    if (this.initialized)
      return;
    if (this.initFn)
      await this.initFn();
    this.initialized = true;
  }
  async request(method, url, headers, body) {
    if (!this.initialized)
      await this.init();
    return this.requestFn(url, { method, headers, body, redirect: "manual" });
  }
  async get(url, headers = {}) {
    return this.request("GET", url, headers);
  }
  async post(url, body, headers = {}) {
    return this.request("POST", url, headers, body);
  }
  async put(url, body, headers = {}) {
    return this.request("PUT", url, headers, body);
  }
  async delete(url, headers = {}) {
    return this.request("DELETE", url, headers);
  }
  static default() {
    return new Fetch(null, async (url, options) => {
      const resp = await globalThis.fetch(url, {
        method: options.method,
        headers: options.headers,
        body: options.body,
        redirect: options.redirect
      });
      return resp;
    });
  }
}

// src/apple/csr.ts
var DER_TAG = {
  integer: 2,
  bitString: 3,
  null: 5,
  oid: 6,
  utf8String: 12,
  printableString: 19,
  sequence: 48,
  set: 49,
  context0: 160
};
function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function encodeLength(length) {
  if (length < 128) {
    return new Uint8Array([length]);
  }
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 255);
    value >>= 8;
  }
  return new Uint8Array([128 | bytes.length, ...bytes]);
}
function encodeTLV(tag, value) {
  return concatBytes(new Uint8Array([tag]), encodeLength(value.length), value);
}
function encodeInteger(value) {
  let n = BigInt(value);
  if (n < 0n) {
    throw new Error("Negative integers are not supported");
  }
  const bytes = [];
  do {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  } while (n > 0n);
  if ((bytes[0] ?? 0) & 128) {
    bytes.unshift(0);
  }
  return encodeTLV(DER_TAG.integer, new Uint8Array(bytes));
}
function encodeOID(oid) {
  const parts = oid.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length < 2) {
    throw new Error(`Invalid OID: ${oid}`);
  }
  const output = [parts[0] * 40 + parts[1]];
  for (let i = 2;i < parts.length; i++) {
    let value = parts[i];
    const base128 = [value & 127];
    value >>= 7;
    while (value > 0) {
      base128.unshift(value & 127 | 128);
      value >>= 7;
    }
    output.push(...base128);
  }
  return encodeTLV(DER_TAG.oid, new Uint8Array(output));
}
function encodePrintableString(value) {
  return encodeTLV(DER_TAG.printableString, new TextEncoder().encode(value));
}
function encodeUTF8String(value) {
  return encodeTLV(DER_TAG.utf8String, new TextEncoder().encode(value));
}
function encodeSequence(...values) {
  return encodeTLV(DER_TAG.sequence, concatBytes(...values));
}
function encodeSet(...values) {
  return encodeTLV(DER_TAG.set, concatBytes(...values));
}
function encodeNull() {
  return encodeTLV(DER_TAG.null, new Uint8Array(0));
}
function encodeBitString(value) {
  return encodeTLV(DER_TAG.bitString, concatBytes(new Uint8Array([0]), value));
}
function encodeRDN(attributeOID, value, useUTF8 = false) {
  const encodedValue = useUTF8 ? encodeUTF8String(value) : encodePrintableString(value);
  return encodeSet(encodeSequence(encodeOID(attributeOID), encodedValue));
}
function toPEM(der, label) {
  const base64 = btoa(String.fromCharCode(...der));
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----
${lines.join(`
`)}
-----END ${label}-----
`;
}
async function generateCSR(publicKey, privateKey, commonName = "AltSign") {
  const subjectPublicKeyInfo = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  const subject = encodeSequence(encodeRDN("2.5.4.6", "US"), encodeRDN("2.5.4.8", "CA"), encodeRDN("2.5.4.7", "Los Angeles"), encodeRDN("2.5.4.10", "AltSign"), encodeRDN("2.5.4.3", commonName, true));
  const certificationRequestInfo = encodeSequence(encodeInteger(0), subject, subjectPublicKeyInfo, encodeTLV(DER_TAG.context0, new Uint8Array(0)));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, privateKey, certificationRequestInfo));
  const signatureAlgorithm = encodeSequence(encodeOID("1.2.840.113549.1.1.5"), encodeNull());
  const certificationRequest = encodeSequence(certificationRequestInfo, signatureAlgorithm, encodeBitString(signature));
  return new TextEncoder().encode(toPEM(certificationRequest, "CERTIFICATE REQUEST"));
}

// src/apple/api.ts
var PROTOCOL_VERSION2 = "QH65B2";
var CLIENT_ID2 = "XABBG36SBA";
function encodePlist2(obj) {
  function encodeValue(v) {
    if (v === null || v === undefined)
      return "<string></string>";
    if (typeof v === "string")
      return `<string>${escapeXml(v)}</string>`;
    if (typeof v === "number")
      return `<integer>${v}</integer>`;
    if (typeof v === "boolean")
      return v ? "<true/>" : "<false/>";
    if (v instanceof Uint8Array) {
      const base64 = btoa(String.fromCharCode(...v));
      return `<data>${base64}</data>`;
    }
    if (Array.isArray(v)) {
      return `<array>${v.map(encodeValue).join("")}</array>`;
    }
    if (typeof v === "object") {
      const dict = v;
      const entries = Object.entries(dict).map(([k, val]) => `<key>${escapeXml(k)}</key>${encodeValue(val)}`).join("");
      return `<dict>${entries}</dict>`;
    }
    return "<string></string>";
  }
  function escapeXml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${encodeValue(obj)}
</plist>`;
}

class AppleAPI {
  fetch;
  auth;
  baseURL;
  servicesBaseURL;
  constructor(fetch) {
    this.fetch = fetch ?? Fetch.default();
    this.auth = new AppleAuth(this.fetch);
    this.baseURL = `https://developerservices2.apple.com/services/${PROTOCOL_VERSION2}/`;
    this.servicesBaseURL = "https://developerservices2.apple.com/services/v1/";
  }
  async authenticate(appleID, password, anisetteData, verificationHandler, options) {
    return this.auth.authenticate(appleID, password, anisetteData, verificationHandler, options);
  }
  async fetchTeams(session) {
    const headers = this.buildHeaders(session);
    const body = this.buildRequestBody({});
    const resp = await this.fetch.post(`${this.baseURL}listTeams.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const resultCode = plist["resultCode"];
    if (resultCode !== undefined && resultCode !== 0) {
      const errorStr = plist["userString"] ?? plist["resultString"];
      throw new Error(`Failed to fetch teams: ${errorStr} (${resultCode})`);
    }
    const teamsArray = plist["teams"];
    if (!teamsArray || teamsArray.length === 0) {
      // Free Apple ID without a developer team: use dsid as personal team ID
      // (like AltStore/SideStore do for personal accounts).
      return [{
        identifier: session.dsid,
        name: "Personal Team",
        type: "Free",
        account: {
          identifier: session.dsid,
          name: "",
          email: ""
        }
      }];
    }
    return teamsArray.map((teamDict) => this.parseTeam(teamDict, session));
  }
  async fetchTeam(session) {
    const teams = await this.fetchTeams(session);
    const preferredTeam = teams.find((team) => team.type === "Individual") ?? teams.find((team) => team.type === "Free") ?? teams[0];
    if (!preferredTeam) {
      throw new Error("No team found for this account");
    }
    return preferredTeam;
  }
  async fetchDevices(session, team) {
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({}, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/listDevices.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const devicesArray = plist["devices"];
    if (!devicesArray) {
      return [];
    }
    return devicesArray.map((deviceDict) => this.parseDevice(deviceDict));
  }
  async registerDevice(session, team, name, identifier) {
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({
      deviceNumber: identifier,
      name
    }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/addDevice.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const deviceDict = plist["device"];
    if (!deviceDict) {
      // Device may already be registered; treat "already exists" as success.
      const validation = plist["validationMessages"];
      const userString = plist["userString"] ?? plist["resultString"] ?? "";
      const alreadyExists = (Array.isArray(validation) && validation.some((m) => String(m).includes("already exists")))
        || String(userString).includes("already exists");
      if (alreadyExists) {
        return { identifier: "", name, udid: identifier, status: "Enabled" };
      }
      throw new Error("Failed to register device");
    }
    return this.parseDevice(deviceDict);
  }
  async fetchCertificates(session, team) {
    // Use legacy plist API like isideload (listAllDevelopmentCerts.action)
    // instead of v1/certificates JSON API which needs different auth.
    const headers = this.buildHeaders(session);
    const body = this.buildRequestBody({ teamId: team.identifier }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/listAllDevelopmentCerts.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const resultCode = plist["resultCode"];
    if (resultCode !== undefined && resultCode !== 0) {
      const errorStr = plist["userString"] ?? plist["resultString"];
      throw new Error(`Failed to fetch certificates: ${errorStr} (${resultCode})`);
    }
    const certsArray = plist["certificates"];
    if (!certsArray) {
      return [];
    }
    return certsArray.map((certDict) => this.parseLegacyCertificate(certDict));
  }
  parseLegacyCertificate(dict) {
    return {
      identifier: dict["certId"] ?? dict["certificateId"],
      name: dict["name"],
      machineName: dict["machineName"],
      machineId: dict["machineId"],
      serialNumber: dict["serialNumber"],
      publicKey: dict["certContent"] ? Uint8Array.from(atob(dict["certContent"]), (c) => c.charCodeAt(0)) : new Uint8Array(),
      expirationDate: dict["expirationDate"],
    };
  }
  async addCertificate(session, team, machineName) {
    const keyPair = await crypto.subtle.generateKey({
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1"
    }, true, ["sign", "verify"]);
    const csrData = await generateCSR(keyPair.publicKey, keyPair.privateKey, "AltSign");
    const encodedCSR = new TextDecoder().decode(csrData);
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({
      csrContent: encodedCSR,
      machineId: crypto.randomUUID(),
      machineName
    }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/submitDevelopmentCSR.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const certDict = plist["certRequest"];
    if (!certDict) {
      const errorStr = plist["userString"] ?? plist["resultString"];
      const resultCode = plist["resultCode"];
      throw new Error(`Failed to add certificate: ${errorStr} (${resultCode})`);
    }
    const privateKeyData = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKey = new Uint8Array(privateKeyData);
    const certificates = await this.fetchCertificates(session, team);
    const newCertificate = certificates.find((c) => c.machineName === machineName);
    if (!newCertificate) {
      throw new Error("Failed to find newly created certificate");
    }
    newCertificate.privateKey = privateKey;
    return { certificate: newCertificate, privateKey };
  }
  async revokeCertificate(session, team, certificate) {
    // Use legacy plist API like isideload (revokeDevelopmentCert.action)
    // instead of v1/certificates JSON API which needs DELETE method.
    const headers = this.buildHeaders(session);
    const serialNumber = certificate.serialNumber;
    const body = this.buildRequestBody({ teamId: team.identifier, serialNumber }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/revokeDevelopmentCert.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const resultCode = plist["resultCode"];
    if (resultCode !== undefined && resultCode !== 0) {
      const errorStr = plist["userString"] ?? plist["resultString"];
      throw new Error(`Failed to revoke certificate: ${errorStr} (${resultCode})`);
    }
    return true;
  }
  async fetchAppIDs(session, team) {
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({}, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/listAppIds.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const appIdsArray = plist["appIds"];
    if (!appIdsArray) {
      return [];
    }
    return appIdsArray.map((appIdDict) => this.parseAppID(appIdDict));
  }
  async addAppID(session, team, name, bundleIdentifier) {
    const sanitizedName = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-zA-Z0-9\s]/g, "");
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({
      identifier: bundleIdentifier,
      name: sanitizedName
    }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/addAppId.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const appIdDict = plist["appId"];
    if (!appIdDict) {
      throw new Error("Failed to add App ID");
    }
    return this.parseAppID(appIdDict);
  }
  async fetchAppGroups(session, team) {
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({}, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/listApplicationGroups.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const groupsArray = plist["applicationGroupList"];
    if (!groupsArray) {
      return [];
    }
    return groupsArray.map((groupDict) => this.parseAppGroup(groupDict));
  }
  async fetchProvisioningProfile(session, team, appID) {
    const headers = this.buildHeaders(session, team);
    const body = this.buildRequestBody({
      appIdId: appID.identifier
    }, team);
    const resp = await this.fetch.post(`${this.baseURL}ios/downloadTeamProvisioningProfile.action?clientId=${CLIENT_ID2}`, body, headers);
    const text = await resp.text();
    const plist = parsePlist(text);
    const profileDict = plist["provisioningProfile"];
    if (!profileDict) {
      throw new Error("Failed to fetch provisioning profile");
    }
    return this.parseProvisioningProfile(profileDict);
  }
  buildHeaders(session, team) {
    const anisette = session.anisetteData;
    const headers = {
      "Content-Type": "text/x-xml-plist",
      "User-Agent": "Xcode",
      Accept: "text/x-xml-plist",
      "Accept-Language": "en-us",
      "X-Apple-App-Info": "com.apple.gs.xcode.auth",
      "X-Xcode-Version": "11.2 (11B41)",
      "X-Apple-I-Identity-Id": session.dsid,
      "X-Apple-GS-Token": session.authToken,
      "X-Apple-I-MD-M": anisette.machineID,
      "X-Apple-I-MD": anisette.oneTimePassword,
      "X-Apple-I-MD-LU": anisette.localUserID,
      "X-Apple-I-MD-RINFO": String(anisette.routingInfo),
      "X-Mme-Device-Id": anisette.deviceUniqueIdentifier,
      "X-MMe-Client-Info": anisette.deviceDescription,
      "X-Apple-I-Client-Time": this.formatDate(anisette.date),
      "X-Apple-Locale": anisette.locale,
      "X-Apple-I-Locale": anisette.locale,
      "X-Apple-I-TimeZone": anisette.timeZone
    };
    return headers;
  }
  buildServicesHeaders(session, httpMethodOverride) {
    const anisette = session.anisetteData;
    return {
      "Content-Type": "application/vnd.api+json",
      "User-Agent": "Xcode",
      Accept: "application/vnd.api+json",
      "Accept-Language": "en-us",
      "X-Apple-App-Info": "com.apple.gs.xcode.auth",
      "X-Xcode-Version": "11.2 (11B41)",
      "X-HTTP-Method-Override": httpMethodOverride,
      "X-Apple-I-Identity-Id": session.dsid,
      "X-Apple-GS-Token": session.authToken,
      "X-Apple-I-MD-M": anisette.machineID,
      "X-Apple-I-MD": anisette.oneTimePassword,
      "X-Apple-I-MD-LU": anisette.localUserID,
      "X-Apple-I-MD-RINFO": String(anisette.routingInfo),
      "X-Mme-Device-Id": anisette.deviceUniqueIdentifier,
      "X-MMe-Client-Info": anisette.deviceDescription,
      "X-Apple-I-Client-Time": this.formatDate(anisette.date),
      "X-Apple-Locale": anisette.locale,
      "X-Apple-I-TimeZone": anisette.timeZone
    };
  }
  async sendServicesRequest(method, requestURL, session, team, additionalParameters = {}) {
    const params2 = new URLSearchParams;
    params2.set("teamId", team.identifier);
    for (const [key, value] of Object.entries(additionalParameters)) {
      params2.set(key, value);
    }
    const body = JSON.stringify({ urlEncodedQueryParams: params2.toString() });
    const headers = this.buildServicesHeaders(session, method);
    const resp = await this.fetch.post(requestURL, body, headers);
    const text = await resp.text();
    if (!text.trim()) {
      return {};
    }
    const json = JSON.parse(text);
    if (!json || typeof json !== "object") {
      throw new Error("Invalid services response");
    }
    return json;
  }
  buildRequestBody(additionalParams, team) {
    const params2 = {
      clientId: CLIENT_ID2,
      protocolVersion: PROTOCOL_VERSION2,
      requestId: crypto.randomUUID().toUpperCase(),
      ...additionalParams
    };
    if (team) {
      params2["teamId"] = team.identifier;
    }
    return encodePlist2(params2);
  }
  parseTeam(dict, session) {
    const typeStr = String(dict["type"] ?? "");
    const normalizedType = typeStr.toLowerCase();
    let teamType;
    switch (normalizedType) {
      case "individual":
      case "ind":
        teamType = "Individual";
        {
          const memberships = dict["memberships"];
          if (Array.isArray(memberships) && memberships.length === 1) {
            const membership = memberships[0];
            const membershipName = String(membership["name"] ?? "").toLowerCase();
            if (membershipName.includes("free")) {
              teamType = "Free";
            }
          }
        }
        break;
      case "company/organization":
      case "organization":
      case "company_or_organization":
        teamType = "Organization";
        break;
      default:
        teamType = "Free";
    }
    return {
      identifier: dict["teamId"],
      name: dict["name"],
      type: teamType,
      account: {
        identifier: session.dsid,
        name: "",
        email: ""
      }
    };
  }
  parseDevice(dict) {
    const statusStr = dict["status"];
    const deviceStatus = statusStr === "c" ? "Enabled" : "Disabled";
    return {
      identifier: dict["deviceId"],
      name: dict["name"],
      model: dict["deviceClass"],
      status: deviceStatus,
      udid: dict["deviceNumber"],
    };
  }
  parseCertificate(dict) {
    const attrs = dict["attributes"];
    const certId = dict["id"] ?? dict["certificateId"] ?? dict["serialNumber"] ?? attrs?.["serialNumber"];
    const certData = dict["certContent"] ?? dict["certificate"] ?? attrs?.["certificateContent"];
    let publicKey = new Uint8Array;
    if (certData) {
      publicKey = Uint8Array.from(atob(certData), (c) => c.charCodeAt(0));
    }
    return {
      identifier: certId,
      machineName: dict["machineName"] ?? attrs?.["machineName"] ?? attrs?.["name"],
      publicKey
    };
  }
  parseAppID(dict) {
    const featuresDict = dict["features"];
    const enabledFeatures = dict["enabledFeatures"];
    const features = {};
    if (enabledFeatures) {
      for (const feature of enabledFeatures) {
        features[feature] = true;
      }
    }
    if (featuresDict) {
      Object.assign(features, featuresDict);
    }
    return {
      identifier: dict["appIdId"],
      name: dict["name"],
      bundleIdentifier: dict["identifier"],
      features
    };
  }
  parseAppGroup(dict) {
    return {
      identifier: dict["applicationGroup"],
      name: dict["name"],
      groupIdentifier: dict["identifier"]
    };
  }
  parseProvisioningProfile(dict) {
    const profileData = dict["encodedProfile"];
    const expiresStr = dict["dateExpire"] ?? dict["expirationDate"];
    return {
      identifier: dict["provisioningProfileId"],
      name: dict["name"],
      data: profileData ? Uint8Array.from(atob(profileData), (c) => c.charCodeAt(0)) : new Uint8Array,
      expires: expiresStr ? new Date(expiresStr) : new Date
    };
  }
  formatDate(date) {
    return date.toISOString().replace(/\.\d{3}Z$/, "Z");
  }
}
// src/sign.ts
import { createResigner } from "@lbr77/zsign-wasm-resigner-wrapper";
function toUint8Array(data) {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}
async function resolveInputData(options) {
  const { data, path, readFile, name } = options;
  if (data) {
    return toUint8Array(data);
  }
  if (!path) {
    throw new Error(`${name} data is required. Provide ${name}Data or ${name}Path.`);
  }
  if (!readFile) {
    throw new Error(`${name}Path was provided but readFile callback is missing.`);
  }
  return toUint8Array(await readFile(path));
}
async function writeOutputIfNeeded(options) {
  const { outputPath, writeFile, data } = options;
  if (!outputPath) {
    return;
  }
  if (!writeFile) {
    throw new Error("outputPath was provided but writeFile callback is missing.");
  }
  await writeFile(outputPath, data);
  return outputPath;
}
async function signIPA(options) {
  const {
    ipaData,
    ipaPath,
    outputPath,
    readFile,
    writeFile,
    certificate,
    privateKey,
    password,
    provisioningProfile,
    bundleID,
    displayName,
    bundleVersion,
    entitlements: entitlementsInput,
    entitlementsPath,
    adhoc = false,
    forceSign = true
  } = options;
  const resigner = await createResigner();
  const inputIpa = await resolveInputData({
    data: ipaData,
    path: ipaPath,
    readFile,
    name: "ipa"
  });
  let entitlements;
  if (entitlementsInput || entitlementsPath) {
    entitlements = await resolveInputData({
      data: entitlementsInput,
      path: entitlementsPath,
      readFile,
      name: "entitlements"
    });
  }
  const signedIPA = await resigner.signIpa(inputIpa, {
    cert: toUint8Array(certificate),
    pkey: toUint8Array(privateKey),
    prov: toUint8Array(provisioningProfile),
    password,
    bundleId: bundleID,
    displayName,
    bundleVersion,
    entitlements,
    adhoc,
    forceSign
  });
  const finalOutputPath = await writeOutputIfNeeded({
    outputPath,
    writeFile,
    data: signedIPA.data
  });
  return {
    outputPath: finalOutputPath,
    bundleID,
    size: signedIPA.data.length,
    data: signedIPA.data
  };
}
async function signMachO(options) {
  const {
    inputData,
    inputPath,
    outputPath,
    readFile,
    writeFile,
    certificate,
    privateKey,
    provisioningProfile,
    password,
    entitlements,
    adhoc = false,
    forceSign = true
  } = options;
  const resigner = await createResigner();
  const machoData = await resolveInputData({
    data: inputData,
    path: inputPath,
    readFile,
    name: "input"
  });
  const signedData = resigner.signMachO(machoData, {
    cert: certificate ? toUint8Array(certificate) : undefined,
    pkey: privateKey ? toUint8Array(privateKey) : undefined,
    prov: provisioningProfile ? toUint8Array(provisioningProfile) : undefined,
    password,
    entitlements: entitlements ? toUint8Array(entitlements) : undefined,
    adhoc,
    forceSign
  });
  const finalOutputPath = await writeOutputIfNeeded({
    outputPath,
    writeFile,
    data: signedData.data
  });
  return {
    outputPath: finalOutputPath,
    size: signedData.data.length,
    data: signedData.data
  };
}
export {
  signMachO,
  signIPA,
  parsePlist,
  bytesToBase64,
  base64ToBytes,
  Fetch,
  AppleAuth,
  AppleAPI
};
